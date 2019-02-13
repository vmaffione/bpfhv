/*
 *    Linux driver for the eBPF paravirtual device.
 *    2018 Vincenzo Maffione <v.maffione@gmail.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/filter.h>	/* struct bpf_prog */
#include <linux/bpf.h>		/* struct bpf_prog_aux */
#include <linux/netdevice.h>
#include <linux/random.h>	/* get_random_bytes() */
#include <linux/pci.h>
#include <linux/virtio_net.h>	/* struct virtio_net_hdr */

#include "bpfhv.h"

#define USE_NAPI

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV|NETIF_MSG_PROBE|NETIF_MSG_LINK)
static int debug = -1; /* use DEFAULT_MSG_ENABLE by default */
module_param(debug, int, /* perm = allow override on modprobe */0);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

struct bpfhv_rxq;
struct bpfhv_txq;

struct bpfhv_info {
	/* PCI information. */
	struct pci_dev			*pdev;
	struct device			*dev;	/* cache &pdev->dev */
	int				bars;
	u8* __iomem			regaddr;
	u8* __iomem			dbmmio_addr;
	u8* __iomem			progmmio_addr;

	struct net_device		*netdev;

	/* Transmit and receive programs (publish, completion and reclaim). */
	struct bpf_prog			*progs[BPFHV_PROG_MAX];

	/* Transmit and receive queues. */
	struct bpfhv_rxq		*rxqs;
	struct bpfhv_txq		*txqs;
	size_t				num_rx_queues;
	size_t				num_tx_queues;
	size_t				rx_ctx_size;
	size_t				tx_ctx_size;

	/* Maximum number of bufs available for receive operation. */
	size_t				rx_bufs;

	/* Maximum number of bufs available for transmission. */
	size_t				tx_bufs;

	/* Is LRO enabled? */
	bool				lro;

	/* Variable needed to use netif logging macros (netif_info,
	 * netif_err, etc.). */
	int				msg_enable;

	/* Name of the program upgrade interrupt. */
	char				upgrade_irq_name[64];

	struct work_struct		upgrade_work;

	/* True if we failed to upgrade the program from the hypervisor.
	 * This situation renders the device unusable. */
	bool				broken;
};

struct bpfhv_rxq {
	struct bpfhv_info		*bi;

	/* Context for the receive programs. */
	struct bpfhv_rx_context		*ctx;
	dma_addr_t			ctx_dma;
	/* Number of bufs currently available for the guest to publish
	 * more receive buffers. */
	size_t				rx_free_bufs;

	/* Structure for packet buffer allocation. */
	struct page_frag		alloc_frag;

	/* Address of the doorbell to be used for guest-->hv notifications
	 * on this queue. */
	u32* __iomem			doorbell;

	struct napi_struct		napi;

	char irq_name[64];

};

/* Padding to be reserved at the beginning of the linear part of the skb. */
#define BPFHV_RX_PAD	(NET_IP_ALIGN + NET_SKB_PAD)
/* Maximum receive packet size without LRO. */
#define BPFHV_RX_PKT_SZ	(ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
/* Bytes to allocate from the frag allocator in order to build a complete
 * skb (including data and shared info). */
#define BPFHV_RX_SKB_TRUESIZE	(SKB_DATA_ALIGN(BPFHV_RX_PAD + BPFHV_RX_PKT_SZ) \
			+ SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

struct bpfhv_txq {
	struct bpfhv_info		*bi;

	/* Context for the transmit programs. */
	struct bpfhv_tx_context		*ctx;
	dma_addr_t			ctx_dma;
	/* Number of bufs currently available for the guest to transmit
	 * more packets. */
	size_t				tx_free_bufs;

	/* Address of the doorbell to be used for guest-->hv notifications
	 * on this queue. */
	u32* __iomem			doorbell;

	unsigned int			idx;

	struct napi_struct		napi;

	char irq_name[64];
};

static int		bpfhv_probe(struct pci_dev *pdev,
					const struct pci_device_id *id);
static void		bpfhv_remove(struct pci_dev *pdev);
static void		bpfhv_shutdown(struct pci_dev *pdev);
static int		bpfhv_irqs_setup(struct bpfhv_info *bi);
static void		bpfhv_irqs_teardown(struct bpfhv_info *bi);
static irqreturn_t	bpfhv_upgrade_intr(int irq, void *data);
static void		bpfhv_upgrade(struct work_struct *w);
static irqreturn_t	bpfhv_rx_intr(int irq, void *data);
static irqreturn_t	bpfhv_tx_intr(int irq, void *data);
static int		bpfhv_programs_setup(struct bpfhv_info *bi);
static int		bpfhv_helper_calls_fixup(struct bpfhv_info *bi,
						struct bpf_insn *insns,
						size_t insns_count);
static struct bpf_prog	*bpfhv_prog_alloc(struct bpfhv_info *bi,
					const char *progname,
					struct bpf_insn *insns,
					size_t insn_count);
static int		bpfhv_programs_teardown(struct bpfhv_info *bi);

static int		bpfhv_open(struct net_device *netdev);
static int		bpfhv_resources_alloc(struct bpfhv_info *bi);
static int		bpfhv_close(struct net_device *netdev);
static void		bpfhv_resources_dealloc(struct bpfhv_info *bi);
static netdev_tx_t	bpfhv_start_xmit(struct sk_buff *skb,
					struct net_device *netdev);
static int		bpfhv_tx_poll(struct napi_struct *napi, int budget);
static int		bpfhv_tx_clean(struct bpfhv_txq *txq, bool in_napi);
static void		bpfhv_tx_ctx_clean(struct bpfhv_txq *txq, bool in_napi);
static int		bpfhv_rx_refill(struct bpfhv_rxq *rxq, gfp_t gfp);
static int		bpfhv_rx_poll(struct napi_struct *napi, int budget);
static struct net_device_stats *bpfhv_get_stats(struct net_device *netdev);
static int		bpfhv_change_mtu(struct net_device *netdev, int new_mtu);

static const struct net_device_ops bpfhv_netdev_ops = {
	.ndo_open			= bpfhv_open,
	.ndo_stop			= bpfhv_close,
	.ndo_start_xmit			= bpfhv_start_xmit,
	.ndo_get_stats			= bpfhv_get_stats,
	.ndo_change_mtu			= bpfhv_change_mtu,
};

static int
bpfhv_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	unsigned int num_rx_queues, num_tx_queues, queue_pairs;
	struct net_device *netdev;
	u8* __iomem progmmio_addr;
	u8* __iomem dbmmio_addr;
	struct bpfhv_info *bi;
	size_t doorbell_size;
	u8* __iomem regaddr;
	uint32_t features;
	int bars;
	int ret;
	int i;

	/* PCI initialization. */
	bars = pci_select_bars(pdev, IORESOURCE_MEM);
	ret = pci_enable_device(pdev);
	if (ret) {
		return ret;
	}

	ret = pci_request_selected_regions(pdev, bars, "bpfhv");
	if (ret) {
		goto err_pci_req_reg;
	}

	pci_set_master(pdev);
	ret = pci_save_state(pdev);
	if (ret) {
		goto err_iomap;
	}

	pr_info("REGS BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_REG_PCI_BAR),
		pci_resource_len(pdev, BPFHV_REG_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_REG_PCI_BAR));
	pr_info("DOORBELL MMIO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_DOORBELL_PCI_BAR),
		pci_resource_len(pdev, BPFHV_DOORBELL_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_DOORBELL_PCI_BAR));
	pr_info("PROG MMIO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_PROG_PCI_BAR),
		pci_resource_len(pdev, BPFHV_PROG_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_PROG_PCI_BAR));

	regaddr = pci_iomap(pdev, BPFHV_REG_PCI_BAR, 0);
	if (!regaddr) {
		ret = -EIO;
		goto err_iomap;
	}

	{
		uint32_t hwversion = readl(regaddr + BPFHV_REG_VERSION);

		if (hwversion != BPFHV_VERSION) {
			pr_err("fatal: bpfhv version mismatch: expected %u,"
				" got %u\n", BPFHV_VERSION, hwversion);
			goto err_dbmmio_map;
		}
	}

	dbmmio_addr = pci_iomap(pdev, BPFHV_DOORBELL_PCI_BAR, 0);
	if (!dbmmio_addr) {
		ret = -EIO;
		goto err_dbmmio_map;
	}

	progmmio_addr = pci_iomap(pdev, BPFHV_PROG_PCI_BAR, 0);
	if (!progmmio_addr) {
		ret = -EIO;
		goto err_progmmio_map;
	}

	/* Inform the hypervisor about the doorbell base GVA. */
	writel(((uint64_t)dbmmio_addr) & 0xffffffff,
			regaddr + BPFHV_REG_DOORBELL_GVA_LO);
	writel((((uint64_t)dbmmio_addr) >> 32ULL) & 0xffffffff,
			regaddr + BPFHV_REG_DOORBELL_GVA_HI);
	doorbell_size = readl(regaddr + BPFHV_REG_DOORBELL_SIZE);

	num_rx_queues = readl(regaddr + BPFHV_REG_NUM_RX_QUEUES);
	num_tx_queues = readl(regaddr + BPFHV_REG_NUM_TX_QUEUES);
	queue_pairs = min(num_tx_queues, num_rx_queues);
	netdev = alloc_etherdev_mq(sizeof(*bi) +
				num_rx_queues * sizeof(bi->rxqs[0]) +
				num_tx_queues * sizeof(bi->txqs[0]), queue_pairs);
	if (!netdev) {
		printk("Failed to allocate net device\n");
		ret = -ENOMEM;
		goto err_alloc_eth;
	}

	/* Cross-link data structures. */
	SET_NETDEV_DEV(netdev, &pdev->dev);
	pci_set_drvdata(pdev, netdev);
	bi = netdev_priv(netdev);
	bi->netdev = netdev;
	bi->pdev = pdev;
	bi->dev = &pdev->dev;
	bi->bars = bars;
	bi->regaddr = regaddr;
	bi->dbmmio_addr = dbmmio_addr;
	bi->progmmio_addr = progmmio_addr;
	bi->num_rx_queues = num_rx_queues;
	bi->num_tx_queues = num_tx_queues;
	bi->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
	INIT_WORK(&bi->upgrade_work, bpfhv_upgrade);
	bi->broken = false;

	bi->rxqs = (struct bpfhv_rxq *)(bi + 1);
	bi->txqs = (struct bpfhv_txq *)(bi->rxqs + num_rx_queues);

	/* Read MAC address from device registers and put it into the
	 * netdev struct. */
	{
		uint8_t macaddr[6];
		uint32_t macreg;

		macreg = readl(regaddr + BPFHV_REG_MAC_HI);
		macaddr[0] = (macreg >> 8) & 0xff;
		macaddr[1] = macreg & 0xff;
		macreg = readl(regaddr + BPFHV_REG_MAC_LO);
		macaddr[2] = (macreg >> 24) & 0xff;
		macaddr[3] = (macreg >> 16) & 0xff;
		macaddr[4] = (macreg >> 8) & 0xff;
		macaddr[5] = macreg & 0xff;
		memcpy(netdev->dev_addr, macaddr, netdev->addr_len);
	}

	netdev->netdev_ops = &bpfhv_netdev_ops;
	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	/* Negotiate features with the hypervisor, and report them to
	 * the kernel. */
	features = readl(regaddr + BPFHV_REG_FEATURES);
	features &= (BPFHV_F_SG | BPFHV_F_TX_CSUM | BPFHV_F_RX_CSUM |
		BPFHV_F_TSOv4 | BPFHV_F_TCPv4_LRO | BPFHV_F_TSOv6 |
		BPFHV_F_TCPv6_LRO);
	writel(features, regaddr + BPFHV_REG_FEATURES);
	netdev->needed_headroom = 0;
	bi->lro = false;
	netdev->features = NETIF_F_HIGHDMA;
	netdev->hw_features = 0;
	if (features & BPFHV_F_SG) {
		netdev->features |= NETIF_F_SG;
		netdev->hw_features |= NETIF_F_SG;
	}
	if (features & BPFHV_F_TX_CSUM) {
		netdev->hw_features |= NETIF_F_HW_CSUM;
		netdev->features |= NETIF_F_HW_CSUM;
		if (features & BPFHV_F_TSOv4) {
			netdev->hw_features |= NETIF_F_TSO;
		}
		if (features & BPFHV_F_TSOv6) {
			netdev->hw_features |= NETIF_F_TSO6;
		}
		netdev->features |= NETIF_F_GSO_ROBUST;
		netdev->features |= netdev->hw_features & NETIF_F_ALL_TSO;
	}
	if (features & BPFHV_F_RX_CSUM) {
		netdev->features |= NETIF_F_RXCSUM;
	}
	if (features & (BPFHV_F_TCPv4_LRO | BPFHV_F_TCPv6_LRO)) {
		netdev->hw_features |= NETIF_F_LRO;
		netdev->features |= NETIF_F_LRO;
		bi->lro = true;
	}
	netdev->vlan_features = netdev->features;
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ETH_DATA_LEN;

	/* Prepare transmit/receive eBPF programs and the associated
	 * contexts. */
	ret = bpfhv_programs_setup(bi);
	if (ret) {
		goto err_prog;
	}

	for (i = 0; i < num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		rxq->bi = bi;
		netif_napi_add(netdev, &rxq->napi, bpfhv_rx_poll,
				NAPI_POLL_WEIGHT);
		rxq->doorbell = (u32* __iomem)(dbmmio_addr +
						doorbell_size * i);
	}

	for (i = 0; i < num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		txq->bi = bi;
		txq->idx = i;
		netif_napi_add(netdev, &txq->napi, bpfhv_tx_poll,
				NAPI_POLL_WEIGHT);
		txq->doorbell = (u32* __iomem)(dbmmio_addr +
					doorbell_size * (num_rx_queues + i));
	}

	/* Register the network interface within the network stack. */
	ret = register_netdev(netdev);
	if (ret) {
		goto err_reg;
	}

	ret = bpfhv_irqs_setup(bi);
	if (ret) {
		goto err_irqs;
	}

	netif_carrier_on(netdev);

	return 0;

err_irqs:
	unregister_netdev(netdev);
err_reg:
	bpfhv_programs_teardown(bi);
err_prog:
	free_netdev(netdev);
err_alloc_eth:
	iounmap(progmmio_addr);
err_progmmio_map:
	iounmap(dbmmio_addr);
err_dbmmio_map:
	iounmap(regaddr);
err_iomap:
	pci_release_selected_regions(pdev, bars);
err_pci_req_reg:
	pci_disable_device(pdev);

	return ret;
}

/* Called when the device is being detached from this driver (e.g. when
 * this kernel module is going to be removed. */
static void
bpfhv_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct bpfhv_info *bi = netdev_priv(netdev);
	int i;

	netif_carrier_off(netdev);
	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		netif_napi_del(&rxq->napi);
	}
	cancel_work_sync(&bi->upgrade_work);
	bpfhv_irqs_teardown(bi);
	unregister_netdev(netdev);
	bpfhv_programs_teardown(bi);
	iounmap(bi->progmmio_addr);
	iounmap(bi->dbmmio_addr);
	iounmap(bi->regaddr);
	pci_release_selected_regions(pdev, bi->bars);
	free_netdev(netdev);
	pci_disable_device(pdev);
}

/* Called when the system is going to power off or reboot. */
static void
bpfhv_shutdown(struct pci_dev *pdev)
{
	pci_disable_device(pdev);
}

static int bpfhv_irqs_setup(struct bpfhv_info *bi)
{
	const size_t num_queues = bi->num_rx_queues + bi->num_tx_queues;
	int num_intrs = num_queues + 1;
	int ret = 0;
	int i;

	/* Allocate the MSI-X interrupt vectors we need. */
	ret = pci_alloc_irq_vectors(bi->pdev, num_intrs, num_intrs,
				    PCI_IRQ_MSIX);
	if (ret != num_intrs) {
		netif_err(bi, probe, bi->netdev,
			"Failed to enable msix vectors (%d)\n", ret);
		return ret;
	}

	/* Setup transmit and receive per-queue interrupts. */
	for (i = 0; i < num_queues; i++) {
		unsigned int vector = pci_irq_vector(bi->pdev, i);
		irq_handler_t handler = NULL;
		char *irq_name = NULL;
		void *q = NULL;

		if (i < bi->num_rx_queues) {
			irq_name = bi->rxqs[i].irq_name;
			q = bi->rxqs + i;
			handler = bpfhv_rx_intr;
		} else {
			i -= bi->num_rx_queues;
			irq_name = bi->txqs[i].irq_name;
			q = bi->txqs + i;
			handler = bpfhv_tx_intr;
			i += bi->num_rx_queues;
		}

		snprintf(irq_name, sizeof(bi->rxqs[0].irq_name),
				"%s-%d", bi->netdev->name, i);
		ret = request_irq(vector, handler, 0, irq_name, q);
		if (ret) {
			netif_err(bi, probe, bi->netdev,
				"Unable to allocate queue interrupt (%d)\n",
				ret);
			goto err_irqs;
		}
		netif_info(bi, intr, bi->netdev,
			"IRQ %u for queue #%d\n", vector, i);
	}

	/* Setup program upgrade interrupt. */
	{
		unsigned int vector = pci_irq_vector(bi->pdev, num_intrs - 1);

		snprintf(bi->upgrade_irq_name, sizeof(bi->upgrade_irq_name),
				"%s-u", bi->netdev->name);
		ret = request_irq(vector, bpfhv_upgrade_intr, 0,
					bi->upgrade_irq_name, bi);
		if (ret) {
			netif_err(bi, probe, bi->netdev,
				"Unable to allocate upgrade interrupt (%d)\n",
				ret);
			goto err_irqs;
		}
		netif_info(bi, intr, bi->netdev, "IRQ %u for upgrade\n",
				vector);
	}

	return 0;

err_irqs:
	for (i--; i>=0; i--) {
		void *q = NULL;

		if (i < bi->num_rx_queues) {
			q = bi->rxqs + i;
		} else {
			q = bi->txqs + i - bi->num_rx_queues;
		}
		free_irq(pci_irq_vector(bi->pdev, i), q);
	}
	pci_free_irq_vectors(bi->pdev);

	return ret;
}

static void bpfhv_irqs_teardown(struct bpfhv_info *bi)
{
	const size_t num_queues = bi->num_rx_queues + bi->num_tx_queues;
	int i;

	free_irq(pci_irq_vector(bi->pdev, num_queues), bi);
	for (i = 0; i < num_queues; i++) {
		void *q = NULL;

		if (i < bi->num_rx_queues) {
			q = bi->rxqs + i;
		} else {
			q = bi->txqs + i - bi->num_rx_queues;
		}
		free_irq(pci_irq_vector(bi->pdev, i), q);
	}

	pci_free_irq_vectors(bi->pdev);
}

static irqreturn_t
bpfhv_upgrade_intr(int irq, void *data)
{
	struct bpfhv_info *bi = data;

	schedule_work(&bi->upgrade_work);

	return IRQ_HANDLED;
}

static void
bpfhv_upgrade(struct work_struct *w)
{
	struct bpfhv_info *bi = container_of(w, struct bpfhv_info,
						upgrade_work);
	uint32_t status = readl(bi->regaddr + BPFHV_REG_STATUS);
	uint32_t ctrl;
	int ret;

	if (!(status & BPFHV_STATUS_UPGRADE)) {
		return; /* nothing to do */
	}
	netif_info(bi, drv, bi->netdev, "Program upgrade\n");

	/* Stop all transmit queues (locked version of
	 * netif_tx_stop_all_queues()). */
	netif_tx_disable(bi->netdev);

	rtnl_lock();

	/* Disable transmit and receive in the hardware, disable
	 * NAPI and release the allocated resources. */
	if (netif_running(bi->netdev)) {
		bpfhv_close(bi->netdev);
	}

	/* Tell the hypervisor that we are ready to proceed with
	 * the upgrade. */
	ctrl = readl(bi->regaddr + BPFHV_REG_CTRL);
	writel(ctrl | BPFHV_CTRL_UPGRADE_READY,
			bi->regaddr + BPFHV_REG_CTRL);

	/* Do the upgrade. */
	ret = bpfhv_programs_setup(bi);
	if (ret) {
		netif_err(bi, drv, bi->netdev,
			"Program upgrade failed: %d\n", ret);
		bi->broken = true;
		rtnl_unlock();
		return;
	}

	bi->broken = false;

	if (netif_running(bi->netdev)) {
		bpfhv_open(bi->netdev);
	}
	rtnl_unlock();
}

static irqreturn_t
bpfhv_rx_intr(int irq, void *data)
{
	struct bpfhv_rxq *rxq = data;

	napi_schedule(&rxq->napi);

	return IRQ_HANDLED;
}

static irqreturn_t
bpfhv_tx_intr(int irq, void *data)
{
	struct bpfhv_txq *txq = data;

#ifdef USE_NAPI
	napi_schedule(&txq->napi);
#else  /* !USE_NAPI */
	netif_wake_subqueue(txq->bi->netdev, txq - txq->bi->txqs);
#endif /* !USE_NAPI */

	return IRQ_HANDLED;
}

#define RXQ_FROM_CTX(_ctx)\
	((struct bpfhv_rxq *)((uintptr_t)((_ctx)->guest_priv)))

#define TXQ_FROM_CTX(_ctx)\
	((struct bpfhv_txq *)((uintptr_t)((_ctx)->guest_priv)))

BPF_CALL_1(bpf_hv_rx_pkt_alloc, struct bpfhv_rx_context *, ctx)
{
	struct bpfhv_rxq *rxq = RXQ_FROM_CTX(ctx);
	struct sk_buff *skb = NULL;
	bool lro = rxq->bi->lro;
	int i;

	if (unlikely(ctx->num_bufs == 0)) {
		return -EINVAL;
	}

	for (i = 0; i < ctx->num_bufs; i++) {
		struct bpfhv_rx_buf *rxb = ctx->bufs + i;
		void *kbuf = (void *)rxb->cookie;

		dma_unmap_single(rxq->bi->dev, (dma_addr_t)rxb->paddr,
				rxb->len, DMA_FROM_DEVICE);
		if (i == 0) {
			if (lro) {
				/* TODO */
			} else {
				skb = build_skb(kbuf, BPFHV_RX_SKB_TRUESIZE);
				if (unlikely(!skb)) {
					put_page(virt_to_head_page(kbuf));
				} else {
					skb_reserve(skb, BPFHV_RX_PAD);
					skb_put(skb, rxb->len);
					ctx->packet = (uintptr_t)skb;
				}
			}
		} else {
			/* TODO handle all the fragments (lro == true). */
		}
	}

	return skb ? 0 : -ENOMEM;
}

BPF_CALL_3(bpf_hv_pkt_l4_csum_md_get, struct bpfhv_tx_context *, ctx,
	   uint16_t *, csum_start, uint16_t *, csum_offset)
{
	struct sk_buff *skb = (struct sk_buff *)(uintptr_t)ctx->packet;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		*csum_start = skb_checksum_start_offset(skb);
		*csum_offset = skb->csum_offset;
		return 1; /* Checksum needed. */
	}

	return 0; /* Checksum already done or not needed. */
}

BPF_CALL_3(bpf_hv_pkt_l4_csum_md_set, struct bpfhv_rx_context *, ctx,
	   uint16_t, csum_start, uint16_t, csum_offset)
{
	struct sk_buff *skb = (struct sk_buff *)(uintptr_t)ctx->packet;

	skb_partial_csum_set(skb, csum_start, csum_offset);

	return 0;
}

BPF_CALL_2(bpf_hv_pkt_virtio_net_md_get, struct bpfhv_tx_context *, ctx,
	   struct virtio_net_hdr *, hdr)
{
	struct sk_buff *skb = (struct sk_buff *)(uintptr_t)ctx->packet;

	virtio_net_hdr_from_skb(skb, hdr, /*little_endian=*/true,
				/*has_data_valid=*/false, /*vlan_hlen=*/0);

	return skb->ip_summed == CHECKSUM_PARTIAL; /* checksum needed ? */
}

BPF_CALL_2(bpf_hv_pkt_virtio_net_md_set, struct bpfhv_rx_context *, ctx,
	   const struct virtio_net_hdr *, hdr)
{
	struct sk_buff *skb = (struct sk_buff *)(uintptr_t)ctx->packet;

	virtio_net_hdr_to_skb(skb, hdr, /*little_endian=*/true);

	return 0;
}

#undef PROGDUMP
#ifdef PROGDUMP
static void
bpfhv_prog_dump(const char *progname, struct bpf_insn *insns,
		size_t insns_count)
{
	size_t dumpsz = strlen(progname) + (2+16+1) * insns_count + 30;
	char *dump = kmalloc(dumpsz, GFP_KERNEL);
	size_t ofs = 0;
	uint64_t *ip;
	int i = 0;

	if (!dump) {
		return;
	}

	ofs += snprintf(dump + ofs, dumpsz - ofs, "%s: {", progname);
	for (i = 0; i < insns_count; i++) {
		if (i > 0) {
			ofs += snprintf(dump + ofs, dumpsz - ofs, ",");
		}
		ip = (uint64_t *)(insns + i);
		ofs += snprintf(dump + ofs, dumpsz - ofs, "0x%llx", *ip);
	}
	ofs += snprintf(dump + ofs, dumpsz - ofs, "}\n");
	printk("%s\n", dump);
	kfree(dump);
}
#endif /* PROGDUMP */

static const char *
progname_from_idx(unsigned int prog_idx)
{
	switch (prog_idx) {
	case BPFHV_PROG_RX_PUBLISH:
		return "rxp";
	case BPFHV_PROG_RX_COMPLETE:
		return "rxc";
	case BPFHV_PROG_RX_INTRS:
		return "rxi";
	case BPFHV_PROG_RX_RECLAIM:
		return "rxr";
	case BPFHV_PROG_TX_PUBLISH:
		return "txp";
	case BPFHV_PROG_TX_COMPLETE:
		return "txc";
	case BPFHV_PROG_TX_INTRS:
		return "txi";
	case BPFHV_PROG_TX_RECLAIM:
		return "txr";
	default:
		break;
	}

	return NULL;
}

static void
ctx_paddr_write(struct bpfhv_info *bi, unsigned int qidx, phys_addr_t paddr)
{
	writel(qidx, bi->regaddr + BPFHV_REG_QUEUE_SELECT);
	writel(paddr & 0xffffffff,
			bi->regaddr + BPFHV_REG_CTX_PADDR_LO);
	writel((paddr >> 32) & 0xffffffff,
			bi->regaddr + BPFHV_REG_CTX_PADDR_HI);
}

static int
bpfhv_programs_setup(struct bpfhv_info *bi)
{
#if 0
	struct bpf_insn txp_insns[] = {
		/* R2 = *(u64 *)(R1 + sizeof(ctx)) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1,
				sizeof(struct bpfhv_tx_context)),
		/* R2 += 1 */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
		/* *(u64 *)(R1 + sizeof(ctx)) = R2 */
		BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2,
				sizeof(struct bpfhv_tx_context)),
		/* R0 = R2 */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
		BPF_EXIT_INSN(),
	};
	struct bpf_insn txc_insns[] = {
		/* R0 = *(u64 *)(R1 + sizeof(ctx)) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1,
				sizeof(struct bpfhv_tx_context)),
		/* R2 = *(u64 *)(R1 + sizeof(ctx) + 8) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1,
				sizeof(struct bpfhv_tx_context) + 8),
		/* if R0 == R2 */
		BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_2, 2),
		/*     R0 = 0 */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/*     return R0 */
		BPF_EXIT_INSN(),
		/* R2 += 1 */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
		/* *(u64 *)(R1 + sizeof(ctx) + 8) = R2 */
		BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2,
				sizeof(struct bpfhv_tx_context) + 8),
		/* R0 = 1 */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		/* return R0 */
		BPF_EXIT_INSN(),
	};
	struct bpf_insn rxp_insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_insn rxc_insns[] = {
		/* R6 = R1 */
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		/* R2 = *(u64 *)(R6 + sizeof(ctx)) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
				sizeof(struct bpfhv_rx_context)),
		/* if R2 > 0 goto PC + 2 */
		BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 0, 2),
		/* R0 = 0 */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* return R0 */
		BPF_EXIT_INSN(),
		/* R2 -= 1 */
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, 1),
		/* *(u64 *)(R6 + sizeof(ctx)) = R2 */
		BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_2,
				sizeof(struct bpfhv_rx_context)),
		/* call bpf_hv_rx_pkt_alloc(R1 = ctx) --> R0 */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPFHV_FUNC_rx_pkt_alloc),
		/* if R0 < 0 goto PC + 1 */
		BPF_JMP_IMM(BPF_JSLT, BPF_REG_0, 0, 1),
		/* R0 = 1 */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		/* return R0 */
		BPF_EXIT_INSN(),
	};
#endif
	struct bpf_insn *insns;
	int ret = -EIO;
	int i;

	insns = kmalloc(BPFHV_PROG_SIZE_MAX * sizeof(struct bpf_insn),
			GFP_KERNEL);
	if (!insns) {
		netif_err(bi, drv, bi->netdev,
			"Failed to allocate memory for instructions\n");
		return -ENOMEM;
	}

	/* Deallocate previous eBPF programs and the associated contexts. */
	bpfhv_programs_teardown(bi);

	/* Update context size and max number of buffers. */
	bi->rx_bufs = readl(bi->regaddr + BPFHV_REG_NUM_RX_BUFS);
	bi->tx_bufs = readl(bi->regaddr + BPFHV_REG_NUM_TX_BUFS);
	bi->rx_ctx_size = readl(bi->regaddr + BPFHV_REG_RX_CTX_SIZE);
	bi->tx_ctx_size = readl(bi->regaddr + BPFHV_REG_TX_CTX_SIZE);

	/* Read the eBPF programs from the hypervisor. */
	for (i = BPFHV_PROG_NONE + 1; i < BPFHV_PROG_MAX; i++) {
		uint32_t *progp;
		size_t prog_len;
		size_t j, jmax;

		writel(i, bi->regaddr + BPFHV_REG_PROG_SELECT);
		prog_len = readl(bi->regaddr + BPFHV_REG_PROG_SIZE);
		if (prog_len == 0 || prog_len > BPFHV_PROG_SIZE_MAX) {
			netif_err(bi, drv, bi->netdev,
				"Invalid program length %u\n",
				(unsigned int)prog_len);
			goto out;
		}

		jmax = (prog_len * sizeof(struct bpf_insn)) / sizeof(*progp);
		progp = (uint32_t *)insns;
		for (j = 0; j < jmax; j++, progp++) {
			*progp = readl(bi->progmmio_addr +
					j * sizeof(*progp));
		}

#ifdef PROGDUMP
		bpfhv_prog_dump(progname_from_idx(i), insns, prog_len);
#endif

		/* Fix the immediate field of call instructions to helper
		 * functions, replacing the abstract identifiers with actual
		 * offsets. */
		ret = bpfhv_helper_calls_fixup(bi, insns, prog_len);
		if (ret) {
			goto out;
		}

		/* Allocate an eBPF program for 'insns'. */
		bi->progs[i] = bpfhv_prog_alloc(bi, progname_from_idx(i),
						insns, prog_len);
		if (bi->progs[i] == NULL) {
			goto out;
		}
	}


	/* Allocate the program contexts for transmit and receive operation. */
	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		rxq->ctx = dma_alloc_coherent(bi->dev, bi->rx_ctx_size,
						&rxq->ctx_dma, GFP_KERNEL);
		if (rxq->ctx == NULL) {
			goto out;
		}
		memset(rxq->ctx, 0, bi->rx_ctx_size);
		rxq->rx_free_bufs = bi->rx_bufs;
		rxq->ctx->guest_priv = (uintptr_t)rxq;
		rxq->ctx->min_completed_bufs = 1;
		ctx_paddr_write(bi, i, rxq->ctx_dma);
	}

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		txq->ctx = dma_alloc_coherent(bi->dev, bi->tx_ctx_size,
						&txq->ctx_dma, GFP_KERNEL);
		if (txq->ctx == NULL) {
			goto out;
		}
		memset(txq->ctx, 0, bi->tx_ctx_size);
		txq->tx_free_bufs = bi->tx_bufs;
		txq->ctx->guest_priv = (uintptr_t)txq;
		txq->ctx->min_completed_bufs = 1;
		ctx_paddr_write(bi, bi->num_rx_queues + i, txq->ctx_dma);
	}

	ret = 0;
out:
	kfree(insns);
	if (ret) {
		bpfhv_programs_teardown(bi);
	}

	return ret;
}

static int
bpfhv_helper_calls_fixup(struct bpfhv_info *bi, struct bpf_insn *insns,
			size_t insns_count)
{
	size_t i;

	for (i = 0; i < insns_count; i++, insns++) {
		u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

		if (!(insns->code == (BPF_JMP | BPF_CALL) &&
			insns->dst_reg == 0 && insns->src_reg == 0 &&
				insns->off == 0)) {
			/* This is not an instruction that calls to
			 * an helper function. */
			continue;
		}

		switch (insns->imm) {
		case BPFHV_FUNC_rx_pkt_alloc:
			func = bpf_hv_rx_pkt_alloc;
			break;
		case BPFHV_FUNC_pkt_l4_csum_md_get:
			func = bpf_hv_pkt_l4_csum_md_get;
			break;
		case BPFHV_FUNC_pkt_l4_csum_md_set:
			func = bpf_hv_pkt_l4_csum_md_set;
			break;
		case BPFHV_FUNC_pkt_virtio_net_md_get:
			func = bpf_hv_pkt_virtio_net_md_get;
			break;
		case BPFHV_FUNC_pkt_virtio_net_md_set:
			func = bpf_hv_pkt_virtio_net_md_set;
			break;
		default:
			netif_err(bi, drv, bi->netdev,
				"Uknown helper function id %08x\n", insns->imm);
			return -EINVAL;
			break;
		}

		insns->imm = func - __bpf_call_base;
	}

	return 0;
}

/* Taken from kernel/bpf/syscall.c:bpf_prog_load(). */
static struct bpf_prog *
bpfhv_prog_alloc(struct bpfhv_info *bi, const char *progname,
		struct bpf_insn *insns, size_t insn_count)
{
	struct bpf_prog *prog;
	int ret;

	prog = bpf_prog_alloc(bpf_prog_size(insn_count), GFP_USER);
	if (!prog) {
		return NULL;
	}
	prog->len = insn_count;
	memcpy(prog->insnsi, insns, bpf_prog_insn_size(prog));
	atomic_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = 1;
	prog->type = BPF_PROG_TYPE_UNSPEC;
	prog->aux->load_time = ktime_get_boot_ns();
	strlcpy(prog->aux->name, "hv-", sizeof(prog->aux->name));
	strlcat(prog->aux->name, progname, sizeof(prog->aux->name));

	/* Replacement for bpf_check(). */
	prog->aux->stack_depth = MAX_BPF_STACK;

	prog = bpf_prog_select_runtime(prog, &ret);
	if (ret < 0) {
		netif_err(bi, drv, bi->netdev,
			"bpf_prog_select_runtime() failed: %d\n", ret);
		bpf_prog_free(prog);
		return NULL;
	}

	return prog;
}

static int
bpfhv_programs_teardown(struct bpfhv_info *bi)
{
	size_t i;

	for (i = BPFHV_PROG_NONE + 1; i < BPFHV_PROG_MAX; i++) {
		if (bi->progs[i]) {
			bpf_prog_free(bi->progs[i]);
			bi->progs[i] = NULL;
		}
	}

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		if (rxq->ctx) {
			dma_free_coherent(bi->dev, bi->rx_ctx_size,
					rxq->ctx, rxq->ctx_dma);
			rxq->ctx = NULL;
		}
		ctx_paddr_write(bi, i, 0);
	}

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		if (txq->ctx) {
			dma_free_coherent(bi->dev, bi->tx_ctx_size,
					txq->ctx, txq->ctx_dma);
			txq->ctx = NULL;
		}
		ctx_paddr_write(bi, bi->num_rx_queues + i, 0);
	}

	return 0;
}

static int
bpfhv_open(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	uint32_t status;
	int ret;
	int i;

	if (bi->broken) {
		return -EIO;
	}

	ret = bpfhv_resources_alloc(bi);
	if (ret) {
		bpfhv_resources_dealloc(bi);
		return ret;
	}

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		napi_enable(&rxq->napi);
	}

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		napi_enable(&txq->napi);
	}

	/* Enable transmit and receive in the hardware, and
	 * check that the operation was successful. */
	writel(BPFHV_CTRL_RX_ENABLE | BPFHV_CTRL_TX_ENABLE,
			bi->regaddr + BPFHV_REG_CTRL);
	status = readl(bi->regaddr + BPFHV_REG_STATUS);
	if ((status & (BPFHV_STATUS_RX_ENABLED | BPFHV_STATUS_TX_ENABLED))
		!= (BPFHV_STATUS_RX_ENABLED | BPFHV_STATUS_TX_ENABLED)) {
		if (!(status & BPFHV_STATUS_RX_ENABLED)) {
			netif_err(bi, drv, netdev,
				"Failed to enable receive operation\n");
		}
		if (!(status & BPFHV_STATUS_TX_ENABLED)) {
			netif_err(bi, drv, netdev,
				"Failed to enable transmit operation\n");
		}
		bpfhv_close(netdev);
		return -EIO;
	}

	netif_tx_start_all_queues(netdev);

	return 0;
}

static int
bpfhv_resources_alloc(struct bpfhv_info *bi)
{
	int ret;
	int i;

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		ret = bpfhv_rx_refill(rxq, GFP_KERNEL);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

static int
bpfhv_close(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	int i;

	if (bi->broken) {
		return 0;
	}

	/* Disable transmit and receive in the hardware. */
	writel(0, bi->regaddr + BPFHV_REG_CTRL);

	/* Disable NAPI. */
	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		napi_disable(&rxq->napi);

	}

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		napi_disable(&txq->napi);
	}

	bpfhv_resources_dealloc(bi);

	return 0;
}

static void
bpfhv_resources_dealloc(struct bpfhv_info *bi)
{
	int i;

	/* Drain the unused buffers in the transmit queues. Transmit
	 * operation must be disabled in the device at this point. */
	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;
		unsigned int count = 0;

		for (;;) {
			int ret;

			ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_RECLAIM],
						/*ctx=*/txq->ctx);
			if (ret == 0) {
				/* No more completed transmissions. */
				break;
			}
			if (unlikely(ret < 0)) {
				netif_err(bi, tx_err, bi->netdev,
					"txr() failed --> %d\n", ret);
				break;
			}

			bpfhv_tx_ctx_clean(txq, /*in_napi=*/false);
			count += txq->ctx->num_bufs;
		}

		if (count) {
			netif_info(bi, drv, bi->netdev,
				"txr() --> %u packets\n", count);
		}
		if (txq->tx_free_bufs != bi->tx_bufs) {
			netif_err(bi, drv, bi->netdev,
				"%d transmit buffers not reclaimed\n",
				(int)bi->tx_bufs - (int)txq->tx_free_bufs);
		}
	}

	/* Drain the unused buffers in the receive queues. Receive operation
	 * must be disabled in the device at this point. */
	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;
		struct bpfhv_rx_context *ctx = rxq->ctx;
		unsigned int count = 0;

		for (;;) {
			int ret;
			int j;

			ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_RECLAIM],
					/*ctx=*/ctx);
			if (ret == 0) {
				/* No more buffers to reclaim. */
				break;
			}

			if (ret < 0) {
				netif_err(bi, rx_err, bi->netdev,
					"rxr() failed --> %d\n", ret);
				break;
			}

			for (j = 0; j < ctx->num_bufs; j++) {
				struct bpfhv_rx_buf *rxb = ctx->bufs + j;
				void *kbuf = (void *)rxb->cookie;

				BUG_ON(kbuf == NULL);
				dma_unmap_single(bi->dev,
						(dma_addr_t)rxb->paddr,
						rxb->len, DMA_FROM_DEVICE);
				put_page(virt_to_head_page(kbuf));
			}

			rxq->rx_free_bufs += ctx->num_bufs;
			count += ctx->num_bufs;
		}

		if (count) {
			netif_info(bi, drv, bi->netdev,
				"rxr() --> %u packets\n", count);
		}
		if (rxq->rx_free_bufs != bi->rx_bufs) {
			netif_err(bi, drv, bi->netdev,
				"%d receive buffers not reclaimed\n",
				(int)bi->rx_bufs - (int)rxq->rx_free_bufs);
		}

		if (rxq->alloc_frag.page) {
			put_page(rxq->alloc_frag.page);
			rxq->alloc_frag.page = NULL;
		}
	}
}

#define F_MAPPED_AS_PAGE	(0x1)

static netdev_tx_t
bpfhv_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	struct bpfhv_txq *txq = bi->txqs + 0;
	struct bpfhv_tx_context *ctx = txq->ctx;
	unsigned int len = skb_headlen(skb);
	struct device *dev = bi->dev;
	unsigned int nr_frags;
	unsigned int i;
	unsigned int f;
	dma_addr_t dma;
	int ret;

	/* Opportunistically free completed packets before queueing a new
	 * one. */
	bpfhv_tx_clean(txq, /*in_napi=*/false);

	nr_frags = skb_shinfo(skb)->nr_frags;
	if (unlikely(nr_frags + 1 > BPFHV_MAX_TX_BUFS)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(txq->tx_free_bufs < nr_frags + 1)) {
		return NETDEV_TX_BUSY;
	}

	skb_tx_timestamp(skb);

	/* Prepare the input arguments for the txp program. */
	ctx->packet = (uintptr_t)skb;

	/* Linear part. */
	dma = dma_map_single(dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, dma))) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	ctx->bufs[0].paddr = dma;
	ctx->bufs[0].len = len;
	ctx->bufs[0].cookie = ((uintptr_t)skb) | /* not mapped as a page */0;
	i = 1;

	for (f = 0; f < nr_frags; f++, i++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;

		dma = dma_map_page(dev, skb_frag_page(frag),
				frag->page_offset, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, dma))) {
			for (i--; i >= 0; i--) {
				struct bpfhv_tx_buf *txb = ctx->bufs + i;

				if (txb->cookie & F_MAPPED_AS_PAGE) {
					dma_unmap_page(dev, txb->paddr,
							txb->len, DMA_TO_DEVICE);
				} else {
					dma_unmap_single(dev, txb->paddr,
							txb->len, DMA_TO_DEVICE);
				}
			}
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		ctx->bufs[i].paddr = dma;
		ctx->bufs[i].len = len;
		ctx->bufs[i].cookie = F_MAPPED_AS_PAGE;
	}
	ctx->num_bufs = i;
	txq->tx_free_bufs -= i;

	ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_PUBLISH], /*ctx=*/ctx);
	netif_info(bi, tx_queued, bi->netdev,
		"txp(%u bytes) --> %d\n", skb->len, ret);

#ifdef USE_NAPI
	/* Enable the interrupts to clean this published buffer once
	 * transmitted. */
	ctx->min_completed_bufs = i;
	BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_INTRS], ctx);
#else  /* !USE_NAPI */
	skb_orphan(skb);
	nf_reset(skb);
#endif /* !USE_NAPI */

	if (txq->tx_free_bufs < 2 + MAX_SKB_FRAGS) {
#ifdef USE_NAPI
		netif_stop_subqueue(netdev, txq->idx);
#else  /* !USE_NAPI */
		bool have_enough_bufs;

		/* Enable interrupts if we are out of buffers. */
		ctx->min_completed_bufs = 2 + MAX_SKB_FRAGS - txq->tx_free_bufs;
		have_enough_bufs = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_INTRS], ctx);
		if (!have_enough_bufs) {
			netif_stop_subqueue(netdev, txq->idx);
		}
#endif /* !USE_NAPI */
	}

	if (!skb->xmit_more && (ctx->oflags & BPFHV_OFLAGS_NOTIF_NEEDED)) {
		writel(0, txq->doorbell);
	}

	return NETDEV_TX_OK;
}

static int
bpfhv_tx_poll(struct napi_struct *napi, int budget)
{
	struct bpfhv_txq *txq = container_of(napi, struct bpfhv_txq, napi);
	struct bpfhv_tx_context *ctx = txq->ctx;
	struct bpfhv_info *bi = txq->bi;
	struct netdev_queue *q =
		netdev_get_tx_queue(bi->netdev, txq - bi->txqs);
	bool wakeup, more;

	__netif_tx_lock(q, raw_smp_processor_id());

	/* Disable interrupts while we are calling bpfhv_tx_clean(). */
	ctx->min_completed_bufs = 0;
	BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_INTRS], ctx);

	bpfhv_tx_clean(txq, /*in_napi=*/true);
	wakeup = (txq->tx_free_bufs >= 2 + MAX_SKB_FRAGS);

	/* Enable interrupts and complete NAPI. */
	ctx->min_completed_bufs = 1;
	more = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_INTRS], ctx);

	__netif_tx_unlock(q);

	napi_complete(napi);

	if (unlikely(more)) {
		/* Reschedule, as more work came in the meanwhile. */
		napi_schedule(napi);
	}

	if (wakeup) {
		netif_tx_wake_queue(q);
	}

	return 0;
}

static int
bpfhv_tx_clean(struct bpfhv_txq *txq, bool in_napi)
{
	struct bpfhv_info *bi = txq->bi;
	int count;

	for (count = 0;; count++) {
		int ret;

		ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_COMPLETE],
					/*ctx=*/txq->ctx);
		if (ret == 0) {
			/* No more completed transmissions. */
			break;
		}
		if (unlikely(ret < 0)) {
			netif_err(bi, tx_err, bi->netdev,
				"txc() failed --> %d\n", ret);
			break;
		}

		bpfhv_tx_ctx_clean(txq, in_napi);
	}

	if (count) {
		netif_info(bi, tx_done, bi->netdev,
			"txc() --> %d packets\n", count);
	}

	return count;
}

/* This function must be called only on successful return of "txc" or "txr". */
static void
bpfhv_tx_ctx_clean(struct bpfhv_txq *txq, bool in_napi)
{
	struct bpfhv_tx_context *ctx = txq->ctx;
	struct bpfhv_info *bi = txq->bi;
	struct device *dev = bi->dev;
	struct sk_buff *skb = NULL;
	int i;

	for (i = 0; i < ctx->num_bufs; i++) {
		struct bpfhv_tx_buf *txb = ctx->bufs + i;

		if (i == 0) {
			skb = (struct sk_buff *)
				(txb->cookie & (~F_MAPPED_AS_PAGE));
		}
		if (txb->cookie & F_MAPPED_AS_PAGE) {
			dma_unmap_page(dev, txb->paddr,
					txb->len, DMA_TO_DEVICE);
		} else {
			dma_unmap_single(dev, txb->paddr,
					txb->len, DMA_TO_DEVICE);
		}
	}
	txq->tx_free_bufs += ctx->num_bufs;

	BUG_ON(!skb);
	napi_consume_skb(skb, in_napi);
}

static int
bpfhv_rx_refill(struct bpfhv_rxq *rxq, gfp_t gfp)
{
	struct page_frag *alloc_frag = &rxq->alloc_frag;
	struct bpfhv_rx_context *ctx = rxq->ctx;
	struct bpfhv_info *bi = rxq->bi;
	struct device *dev = bi->dev;
	bool oom = false;
	unsigned int i;
	int ret;

	while (rxq->rx_free_bufs > 0 && !oom) {
		size_t n = rxq->rx_free_bufs;

		if (n > BPFHV_MAX_RX_BUFS) {
			n = BPFHV_MAX_RX_BUFS;
		}

		/* Prepare the context for publishing receive buffers. */
		for (i = 0; i < n; i++) {
			struct bpfhv_rx_buf *rxb = ctx->bufs + i;
			size_t truesize, bufsize, pad;
			dma_addr_t dma;
			void *kbuf;

			if (bi->lro) {
				truesize = bufsize = PAGE_SIZE;
				pad = 0;
			} else {
				truesize = BPFHV_RX_SKB_TRUESIZE;
				bufsize = BPFHV_RX_PKT_SZ;
				pad = BPFHV_RX_PAD;
			}

			/* We need to reserve space for shared info, and
			 * make sure the sizes are properly aligned. */
			if (unlikely(!skb_page_frag_refill(truesize,
						alloc_frag, gfp))) {
				oom = true;
				break;
			}

			kbuf = (char *)page_address(alloc_frag->page) +
				alloc_frag->offset;
			get_page(alloc_frag->page);
			alloc_frag->offset += truesize;

			dma = dma_map_single(dev, kbuf + pad,
					     bufsize, DMA_FROM_DEVICE);
			if (unlikely(dma_mapping_error(dev, dma))) {
				put_page(virt_to_head_page(kbuf));
				break;
			}
			rxb->cookie = (uintptr_t)kbuf;
			rxb->paddr = (uintptr_t)dma;
			rxb->len = bufsize;
		}
		ctx->num_bufs = i;
		rxq->rx_free_bufs -= i;

		ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_PUBLISH],
					/*ctx=*/ctx);
		netif_info(bi, rx_status, bi->netdev,
			"rxp(%u bufs) --> %d\n", i, ret);

		if (ctx->oflags & BPFHV_OFLAGS_NOTIF_NEEDED) {
			writel(0, rxq->doorbell);
		}
	}

	return 0;
}

static int
bpfhv_rx_poll(struct napi_struct *napi, int budget)
{
	struct bpfhv_rxq *rxq = container_of(napi, struct bpfhv_rxq, napi);
	struct bpfhv_rx_context *ctx = rxq->ctx;
	struct bpfhv_info *bi = rxq->bi;
	bool more = true;
	int count;

	/* Disable interrupts. */
	ctx->min_completed_bufs = 0;
	BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_INTRS], ctx);

	for (count = 0; count < budget; count++) {
		struct sk_buff *skb;
		int ret;

		ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_COMPLETE],
					/*ctx=*/ctx);
		if (ret == 0) {
			/* No more received packets. */
			break;
		}
		if (unlikely(ret < 0)) {
			netif_err(bi, rx_err, bi->netdev,
				"rxc() failed --> %d\n", ret);
			break;
		}
		rxq->rx_free_bufs++;

		skb = (struct sk_buff *)ctx->packet;
		if (unlikely(!skb)) {
			netif_err(bi, rx_err, bi->netdev,
				"rxc() hv bug: skb not allocated\n");
			break;
		}

		skb->protocol = eth_type_trans(skb, bi->netdev);
		netif_receive_skb(skb);
		if (rxq->rx_free_bufs >= 16) {
			bpfhv_rx_refill(rxq, GFP_ATOMIC);
		}
	}

	if (count < budget) {
		/* No more received packets. Complete NAPI, enable interrupts
		 * and reschedule if necesssary. */
		napi_complete_done(napi, count);
		ctx->min_completed_bufs = 1;
		more = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_INTRS], ctx);
		if (unlikely(more)) {
			napi_schedule(napi);
		}
	}

	if (count > 0) {
		netif_info(bi, rx_status, bi->netdev,
			"rxc() --> %d packets\n", count);
	}

	return count;
}

static struct net_device_stats *
bpfhv_get_stats(struct net_device *netdev)
{
	return &netdev->stats;
}

static int
bpfhv_change_mtu(struct net_device *netdev, int new_mtu)
{
	pr_info("%s: %s changing MTU from %d to %d\n",
		__func__, netdev->name, netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	return 0;
}

/* List of (VendorID, DeviceID) pairs supported by this driver. */
static struct pci_device_id bpfhv_device_table[] = {
	{ PCI_DEVICE(BPFHV_PCI_VENDOR_ID, BPFHV_PCI_DEVICE_ID), },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, bpfhv_device_table);

/* PCI driver information. */
static struct pci_driver bpfhv_driver = {
	.name       = "bpfhv",
	.id_table   = bpfhv_device_table,
	.probe      = bpfhv_probe,
	.remove     = bpfhv_remove,
	.shutdown   = bpfhv_shutdown,
};

static int __init
bpfhv_init(void)
{
	return pci_register_driver(&bpfhv_driver);
}

static void __exit
bpfhv_fini(void)
{
	pci_unregister_driver(&bpfhv_driver);
}

module_init(bpfhv_init);
module_exit(bpfhv_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
