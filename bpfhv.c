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

#include "bpfhv.h"

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
	u8* __iomem			ioaddr;
	u8* __iomem			dbmmio_addr;
	u8* __iomem			progmmio_addr;

	struct net_device		*netdev;

	/* Transmit and receive programs (publish and completion). */
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

	/* Variable needed to use netif logging macros (netif_info,
	 * netif_err, etc.). */
	int				msg_enable;
};

struct bpfhv_rxq {
	struct bpfhv_info		*bi;

	/* Context for the receive programs. */
	struct bpfhv_rx_context		*ctx;
	dma_addr_t			ctx_dma;
	/* Number of bufs currently available for the guest to publish
	 * more receive buffers. */
	size_t				rx_free_bufs;

	/* Address of the doorbell to be used for guest-->hv notifications
	 * on this queue. */
	u32* __iomem			doorbell;

	struct napi_struct		napi;

	char irq_name[64];

};

/* Information associated to a pending transmit buffer. */
struct bpfhv_tx_info {
	struct sk_buff	*skb;
	dma_addr_t	dma;
	uint32_t	len;
	int16_t		eop;
	int16_t		mapped_page;
};

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

	/* Array to associate data to each published (but incomplete)
	 * buffer. The 'info_ntu' field (next to use) is an index in
	 * the array that points to the next slot to be used. This
	 * works assuming that the hypervisor does not process packets
	 * out of order. In the future we need to support out of order
	 * by implementing a free-list within the array. */
	struct bpfhv_tx_info		*info;
	unsigned int			info_ntu;

	char irq_name[64];
};

static int		bpfhv_probe(struct pci_dev *pdev,
					const struct pci_device_id *id);
static void		bpfhv_remove(struct pci_dev *pdev);
static void		bpfhv_shutdown(struct pci_dev *pdev);
static int		bpfhv_irqs_setup(struct bpfhv_info *bi);
static void		bpfhv_irqs_teardown(struct bpfhv_info *bi);
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
static void		bpfhv_tx_clean(struct bpfhv_txq *txq);
static int		bpfhv_rx_refill(struct bpfhv_rxq *rxq);
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
	u8* __iomem ioaddr;
	int bars;
	int ret;
	int i;

	/* PCI initialization. */
	bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
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

	printk("IO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_IO_PCI_BAR),
		pci_resource_len(pdev, BPFHV_IO_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_IO_PCI_BAR));
	printk("DOORBELL MMIO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_DOORBELL_PCI_BAR),
		pci_resource_len(pdev, BPFHV_DOORBELL_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_DOORBELL_PCI_BAR));
	printk("PROG MMIO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, BPFHV_PROG_PCI_BAR),
		pci_resource_len(pdev, BPFHV_PROG_PCI_BAR),
		pci_resource_flags(pdev, BPFHV_PROG_PCI_BAR));

	ioaddr = pci_iomap(pdev, BPFHV_IO_PCI_BAR, 0);
	if (!ioaddr) {
		ret = -EIO;
		goto err_iomap;
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
	iowrite32(((uint64_t)dbmmio_addr) & 0xffffffff,
			ioaddr + BPFHV_IO_DOORBELL_GVA_LO);
	iowrite32((((uint64_t)dbmmio_addr) >> 32ULL) & 0xffffffff,
			ioaddr + BPFHV_IO_DOORBELL_GVA_HI);
	doorbell_size = ioread32(ioaddr + BPFHV_IO_DOORBELL_SIZE);

	num_rx_queues = ioread32(ioaddr + BPFHV_IO_NUM_RX_QUEUES);
	num_tx_queues = ioread32(ioaddr + BPFHV_IO_NUM_TX_QUEUES);
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
	bi->ioaddr = ioaddr;
	bi->dbmmio_addr = dbmmio_addr;
	bi->progmmio_addr = progmmio_addr;
	bi->num_rx_queues = num_rx_queues;
	bi->num_tx_queues = num_tx_queues;
	bi->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);

	bi->rxqs = (struct bpfhv_rxq *)(bi + 1);
	bi->txqs = (struct bpfhv_txq *)(bi->rxqs + num_rx_queues);

	/* Read MAC address from device registers and put it into the
	 * netdev struct. */
	{
		uint8_t macaddr[6];
		uint32_t macreg;

		macreg = ioread32(ioaddr + BPFHV_IO_MAC_HI);
		macaddr[0] = (macreg >> 8) & 0xff;
		macaddr[1] = macreg & 0xff;
		macreg = ioread32(ioaddr + BPFHV_IO_MAC_LO);
		macaddr[2] = (macreg >> 24) & 0xff;
		macaddr[3] = (macreg >> 16) & 0xff;
		macaddr[4] = (macreg >> 8) & 0xff;
		macaddr[5] = macreg & 0xff;
		memcpy(netdev->dev_addr, macaddr, netdev->addr_len);
	}

	netdev->netdev_ops = &bpfhv_netdev_ops;

	netdev->features = NETIF_F_HIGHDMA;
	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	/* Prepare transmit/receive eBPF programs and the associated
	 * contexts. */
	ret = bpfhv_programs_setup(bi);
	if (ret) {
		goto err_prog;
	}

	for (i = 0; i < num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		netif_napi_add(netdev, &rxq->napi, bpfhv_rx_poll,
				NAPI_POLL_WEIGHT);
		rxq->bi = bi;
		rxq->doorbell = (u32* __iomem)(dbmmio_addr +
						doorbell_size * i);
	}

	for (i = 0; i < num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		txq->bi = bi;
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
	iounmap(ioaddr);
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
	bpfhv_irqs_teardown(bi);
	unregister_netdev(netdev);
	bpfhv_programs_teardown(bi);
	iounmap(bi->progmmio_addr);
	iounmap(bi->dbmmio_addr);
	iounmap(bi->ioaddr);
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
	int ret = 0;
	int i;

	/* Allocate the MSI-X interrupt vectors we need. */
	ret = pci_alloc_irq_vectors(bi->pdev, num_queues, num_queues,
				    PCI_IRQ_MSIX);
	if (ret != num_queues) {
		netif_err(bi, probe, bi->netdev,
			"Failed to enable msix vectors (%d)\n", ret);
		return ret;
	}

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
				"Unable to allocate interrupt (%d)\n", ret);
			goto err_irqs;
		}
		netif_info(bi, intr, bi->netdev,
			"bpfhv: IRQ for queue #%d --> %u\n", i, vector);
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

	/* TODO protect txq from concurrent access */
	bpfhv_tx_clean(txq);

	return IRQ_HANDLED;
}

#define RXQ_FROM_CTX(_ctx)\
	((struct bpfhv_rxq *)((uintptr_t)((_ctx)->guest_priv)))

BPF_CALL_1(bpf_hv_rx_pkt_alloc, struct bpfhv_rx_context *, ctx)
{
	struct bpfhv_rxq *rxq = RXQ_FROM_CTX(ctx);
	struct sk_buff *skb = NULL;
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
			skb = napi_alloc_skb(&rxq->napi, rxb->len);
			if (skb) {
				/* TODO remove the data copy */
				skb_put_data(skb, kbuf, rxb->len);
				ctx->packet = (uintptr_t)skb;
			}
		} else {
			/* TODO handle all the fragments. */
		}
		kfree(kbuf);
	}

	return skb ? 0 : -ENOMEM;
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
	case BPFHV_PROG_TX_PUBLISH:
		return "txp";
	case BPFHV_PROG_TX_COMPLETE:
		return "txc";
	case BPFHV_PROG_RX_PUBLISH:
		return "rxp";
	case BPFHV_PROG_RX_COMPLETE:
		return "rxc";
	default:
		break;
	}

	return NULL;
}

static void
ctx_paddr_write(struct bpfhv_info *bi, unsigned int qidx, phys_addr_t paddr)
{
	iowrite32(qidx, bi->ioaddr + BPFHV_IO_QUEUE_SELECT);
	iowrite32(paddr & 0xffffffff,
			bi->ioaddr + BPFHV_IO_CTX_PADDR_LO);
	iowrite32((paddr >> 32) & 0xffffffff,
			bi->ioaddr + BPFHV_IO_CTX_PADDR_HI);
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
	bi->rx_bufs = ioread32(bi->ioaddr + BPFHV_IO_NUM_RX_BUFS);
	bi->tx_bufs = ioread32(bi->ioaddr + BPFHV_IO_NUM_TX_BUFS);
	bi->rx_ctx_size = ioread32(bi->ioaddr + BPFHV_IO_RX_CTX_SIZE);
	bi->tx_ctx_size = ioread32(bi->ioaddr + BPFHV_IO_TX_CTX_SIZE);

	/* Read the eBPF programs from the hypervisor. */
	for (i = BPFHV_PROG_NONE + 1; i < BPFHV_PROG_MAX; i++) {
		uint32_t *progp;
		size_t prog_len;
		size_t j, jmax;

		iowrite32(i, bi->ioaddr + BPFHV_IO_PROG_SELECT);
		prog_len = ioread32(bi->ioaddr + BPFHV_IO_PROG_SIZE);
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
	int ret;
	int i;

	ret = bpfhv_resources_alloc(bi);
	if (ret) {
		bpfhv_resources_dealloc(bi);
		return ret;
	}

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		napi_enable(&rxq->napi);
	}

	/* Enable transmit and receive in the hardware. */
	iowrite32(BPFHV_CTRL_RX_ENABLE | BPFHV_CTRL_TX_ENABLE,
			bi->ioaddr + BPFHV_IO_CTRL);

	return 0;
}

static int
bpfhv_resources_alloc(struct bpfhv_info *bi)
{
	int ret;
	int i;

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		ret = bpfhv_rx_refill(rxq);
		if (ret) {
			return ret;
		}
	}

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		txq->info = kzalloc(sizeof(txq->info[0]) * bi->tx_bufs,
					GFP_KERNEL);
		if (txq->info == NULL) {
			return -ENOMEM;
		}
		txq->info_ntu = 0;
	}

	return 0;
}

static int
bpfhv_close(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	int i;

	/* Disable transmit and receive in the hardware. */
	iowrite32(0, bi->ioaddr + BPFHV_IO_CTRL);

	for (i = 0; i < bi->num_rx_queues; i++) {
		struct bpfhv_rxq *rxq = bi->rxqs + i;

		napi_disable(&rxq->napi);
	}

	bpfhv_resources_dealloc(bi);

	return 0;
}

static void
bpfhv_resources_dealloc(struct bpfhv_info *bi)
{
	int i;

	for (i = 0; i < bi->num_tx_queues; i++) {
		struct bpfhv_txq *txq = bi->txqs + i;

		if (txq->info) {
			kfree(txq->info);
			txq->info = NULL;
		}
	}
}

#define TX_INFO_IDX_INC(_bi, _idx) \
	do {\
		if (unlikely(++(_idx) == (_bi)->tx_bufs)) {\
			(_idx) = 0;\
		}\
	} while (0)

static netdev_tx_t
bpfhv_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	struct bpfhv_txq *txq = bi->txqs + 0;
	struct bpfhv_tx_context *ctx = txq->ctx;
	unsigned int len = skb_headlen(skb);
	unsigned int ntu = txq->info_ntu;
	struct device *dev = bi->dev;
	struct bpfhv_tx_info *info;
	unsigned int nr_frags;
	unsigned int i;
	unsigned int f;
	dma_addr_t dma;
	int ret;

	nr_frags = skb_shinfo(skb)->nr_frags;
	if (unlikely(nr_frags + 1 > BPFHV_MAX_TX_BUFS)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(txq->tx_free_bufs < nr_frags + 1)) {
		return NETDEV_TX_BUSY;
	}

	/* Prepare the input arguments for the txp program. */
	ctx->cookie = ntu;

	/* Linear part. */
	dma = dma_map_single(dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, dma))) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	ctx->bufs[0].paddr = dma;
	ctx->bufs[0].len = len;
	i = 1;
	info = txq->info + ntu;
	info->dma = dma;
	info->len = len;
	info->skb = skb;
	info->eop = (nr_frags == 0);
	info->mapped_page = 0;
	TX_INFO_IDX_INC(bi, ntu);

	for (f = 0; f < nr_frags; f++, i++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;

		dma = dma_map_page(dev, skb_frag_page(frag),
				frag->page_offset, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, dma))) {
			for (i--; i >= 0; i--) {
				if (ntu == 0) {
					ntu = bi->tx_bufs;
				}
				ntu--;
				info = txq->info + ntu;
				if (info->mapped_page) {
					dma_unmap_page(dev, info->dma,
							info->len, DMA_TO_DEVICE);
				} else {
					dma_unmap_single(dev, info->dma,
							info->len, DMA_TO_DEVICE);
				}
			}
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		ctx->bufs[i].paddr = dma;
		ctx->bufs[i].len = len;
		info = txq->info + ntu;
		info->dma = dma;
		info->len = len;
		info->skb = NULL;
		info->eop = (f == nr_frags - 1);
		info->mapped_page = 1;
		TX_INFO_IDX_INC(bi, ntu);
	}
	ctx->num_bufs = i;
	txq->tx_free_bufs -= i;
	txq->info_ntu = ntu;

	ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_PUBLISH], /*ctx=*/ctx);
	netif_info(bi, tx_queued, bi->netdev,
		"txp(%u bytes) --> %d\n", skb->len, ret);

	if (!skb->xmit_more && (ctx->oflags & BPFHV_OFLAGS_NOTIF_NEEDED)) {
		writel(0, txq->doorbell);
	}

	return NETDEV_TX_OK;
}

static void
bpfhv_tx_clean(struct bpfhv_txq *txq)
{
	struct bpfhv_tx_context *ctx = txq->ctx;
	struct bpfhv_info *bi = txq->bi;
	struct device *dev = bi->dev;
	unsigned int count;

	for (count = 0;; count++) {
		struct bpfhv_tx_info *info;
		unsigned int ntc;
		struct sk_buff *skb;
		int ret;

		ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_COMPLETE],
					/*ctx=*/ctx);
		if (ret == 0) {
			/* No more completed transmissions. */
			break;
		}
		if (unlikely(ret < 0)) {
			netif_err(bi, tx_err, bi->netdev,
				"tcx() failed --> %d\n", ret);
			break;
		}

		ntc = (unsigned int)ctx->cookie;
		info = txq->info + ntc;
		skb = info->skb;
		for (;;) {
			if (info->mapped_page) {
				dma_unmap_page(dev, info->dma,
						info->len, DMA_TO_DEVICE);
			} else {
				dma_unmap_single(dev, info->dma,
						info->len, DMA_TO_DEVICE);
			}
			if (info->eop) {
				break;
			}
			TX_INFO_IDX_INC(bi, ntc);
			info = txq->info + ntc;
		}
		dev_kfree_skb_any(skb);
	}

	if (count) {
		netif_info(bi, tx_done, bi->netdev,
			"txc() --> %d packets\n", count);
		txq->tx_free_bufs += count;
	}
}

static int
bpfhv_rx_refill(struct bpfhv_rxq *rxq)
{
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
			/* TODO allocate buffers using get_page or
			 * skb_frag_alloc. */
			const size_t bufsize = 2048;
			void *kbuf = kmalloc(bufsize, GFP_KERNEL);
			struct bpfhv_rx_buf *rxb = ctx->bufs + i;
			dma_addr_t dma;

			if (kbuf == NULL) {
				oom = true;
				break;
			}

			dma = dma_map_single(dev, kbuf, bufsize,
						DMA_FROM_DEVICE);
			if (unlikely(dma_mapping_error(dev, dma))) {
				kfree(kbuf);
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
	int count;

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
			bpfhv_rx_refill(rxq);
		}
	}

	napi_complete(napi);

	if (count > 0) {
		netif_info(bi, rx_status, bi->netdev,
			"rxc() --> %d packets\n", count);
	}

	return 0;
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
