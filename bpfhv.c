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

#include "bpfhv_context.h"

struct bpfhv_info {
	struct net_device		*netdev;
	struct napi_struct		napi;

	/* Transmit programs: publish and completion. */
	struct bpf_prog			*tx_publish_prog;
	struct bpf_prog			*tx_complete_prog;
	/* Context for the transmit programs. */
	struct bpfhv_tx_context		*tx_ctx;
	size_t				tx_ctx_size;
	/* Maximum number of slots available for transmission. */
	size_t				tx_slots;
	/* Number of slots currently available for the guest to transmit
	 * more packets. */
	size_t				tx_free_slots;

	/* Receive programs: publish and completion. */
	struct bpf_prog			*rx_publish_prog;
	struct bpf_prog			*rx_complete_prog;
	/* Context for the receive programs. */
	struct bpfhv_rx_context		*rx_ctx;
	size_t				rx_ctx_size;
	/* Maximum number of slots available for receive operation. */
	size_t				rx_slots;
	/* Number of slots currently available for the guest to publish
	 * more buffers. */
	size_t				rx_free_slots;

	/* Temporary timer for interrupt emulation. */
	struct timer_list		intr_tmr;
};

static int		bpfhv_netdev_setup(struct bpfhv_info **bip);
static void		bpfhv_netdev_teardown(struct bpfhv_info *bi);
static int		bpfhv_programs_setup(struct bpfhv_info *bi);
static struct bpf_prog	*bpfhv_prog_alloc(const char *progname,
					struct bpf_insn *insns,
					size_t insn_count);
static int		bpfhv_programs_teardown(struct bpfhv_info *bi);

static int		bpfhv_open(struct net_device *netdev);
static int		bpfhv_close(struct net_device *netdev);
static netdev_tx_t	bpfhv_start_xmit(struct sk_buff *skb,
					struct net_device *netdev);
static void		bpfhv_tx_clean(struct bpfhv_info *bi);
static void		bpfhv_intr_tmr(struct timer_list *tmr);
static int		bpfhv_rx_refill(struct bpfhv_info *bi);
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
bpfhv_netdev_setup(struct bpfhv_info **bip)
{
	const unsigned int queue_pairs = 1;
	struct net_device *netdev;
	struct bpfhv_info *bi;
	int ret;

	netdev = alloc_etherdev_mq(sizeof(*bi), queue_pairs);
	if (!netdev) {
		printk("Failed to allocate net device\n");
		return -ENOMEM;
	}

	/* Cross-link data structures. */
	SET_NETDEV_DEV(netdev, NULL);
	bi = netdev_priv(netdev);
	bi->netdev = netdev;

	netdev->netdev_ops = &bpfhv_netdev_ops;

	{
		uint8_t macaddr[6] = {
			0x00, 0x0a, 0x0b, 0x0c, 0x01, 0x02
		};
		memcpy(netdev->dev_addr, macaddr, netdev->addr_len);
	}

	netdev->features = NETIF_F_HIGHDMA;
	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	/* Prepare transmit/receive eBPF programs and the associated
	 * contexts. */
	ret = bpfhv_programs_setup(bi);
	if (ret) {
		goto err_prog;
	}

	/* Register the network interface within the network stack. */
	netif_napi_add(netdev, &bi->napi, bpfhv_rx_poll, NAPI_POLL_WEIGHT);

	ret = register_netdev(netdev);
	if (ret) {
		goto err_reg;
	}

	timer_setup(&bi->intr_tmr, bpfhv_intr_tmr, 0);

	netif_carrier_on(netdev);

	*bip = bi;

	return 0;
err_reg:
	bpfhv_programs_teardown(bi);
err_prog:
	free_netdev(netdev);

	return ret;
}

static void
bpfhv_netdev_teardown(struct bpfhv_info *bi)
{
	struct net_device *netdev = bi->netdev;

	netif_carrier_off(netdev);
	netif_napi_del(&bi->napi);
	unregister_netdev(netdev);
	bpfhv_programs_teardown(bi);
	free_netdev(netdev);
}

static const uint8_t udp_pkt[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x10,
	0x00, 0x2e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x26, 0xad, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x01,
	0x00, 0x01, 0x04, 0xd2, 0x04, 0xd2, 0x00, 0x1a, 0x15, 0x80, 0x6e, 0x65, 0x74, 0x6d, 0x61, 0x70,
	0x20, 0x70, 0x6b, 0x74, 0x2d, 0x67, 0x65, 0x6e, 0x20, 0x44, 0x49, 0x52,
};

#define BI_FROM_CTX(_ctx)\
	((struct bpfhv_info *)((uintptr_t)((_ctx)->guest_priv)))

BPF_CALL_1(bpf_hv_pkt_alloc, struct bpfhv_rx_context *, ctx)
{
	struct bpfhv_info *bi = BI_FROM_CTX(ctx);
	struct sk_buff *skb = napi_alloc_skb(&bi->napi, sizeof(udp_pkt));

	ctx->packet = (uintptr_t)skb;
	if (unlikely(!skb)) {
		return -ENOMEM;
	}

	skb_put_data(skb, udp_pkt, sizeof(udp_pkt));

	return 0;
}

static int
bpfhv_programs_setup(struct bpfhv_info *bi)
{
	const size_t ctx_size = sizeof(struct bpfhv_tx_context) + 1024;
	const size_t num_slots = 256;
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
		/* call bpf_hv_pkt_alloc(R1 = ctx) --> R0 */
		BPF_EMIT_CALL(bpf_hv_pkt_alloc),
		/* if R0 < 0 goto PC + 1 */
		BPF_JMP_IMM(BPF_JSLT, BPF_REG_0, 0, 1),
		/* R0 = 1 */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		/* return R0 */
		BPF_EXIT_INSN(),
	};

	bpfhv_programs_teardown(bi);

	bi->tx_ctx_size = ctx_size;
	bi->tx_ctx = kzalloc(bi->tx_ctx_size, GFP_KERNEL);
	if (bi->tx_ctx == NULL) {
		goto err;
	}
	bi->tx_slots = bi->tx_free_slots = num_slots;

	bi->tx_publish_prog = bpfhv_prog_alloc("txp", txp_insns,
						ARRAY_SIZE(txp_insns));
	if (bi->tx_publish_prog == NULL) {
		goto err;
	}

	bi->tx_complete_prog = bpfhv_prog_alloc("txc", txc_insns,
						ARRAY_SIZE(txc_insns));
	if (bi->tx_complete_prog == NULL) {
		goto err;
	}

	bi->rx_ctx_size = ctx_size;
	bi->rx_ctx = kzalloc(bi->rx_ctx_size, GFP_KERNEL);
	if (bi->rx_ctx == NULL) {
		goto err;
	}
	bi->rx_slots = bi->rx_free_slots = num_slots;

	bi->rx_publish_prog = bpfhv_prog_alloc("rxp", rxp_insns,
						ARRAY_SIZE(rxp_insns));
	if (bi->rx_publish_prog == NULL) {
		goto err;
	}

	bi->rx_complete_prog = bpfhv_prog_alloc("rxc", rxc_insns,
						ARRAY_SIZE(rxc_insns));
	if (bi->rx_complete_prog == NULL) {
		goto err;
	}

	bi->tx_ctx->guest_priv = (uintptr_t)bi;
	bi->rx_ctx->guest_priv = (uintptr_t)bi;

	return 0;
err:
	bpfhv_programs_teardown(bi);
	return -1;
}

/* Taken from kernel/bpf/syscall.c:bpf_prog_load(). */
static struct bpf_prog *
bpfhv_prog_alloc(const char *progname, struct bpf_insn *insns,
		size_t insn_count)
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
		printk("bpf_prog_select_runtime() failed: %d\n", ret);
		bpf_prog_free(prog);
		return NULL;
	}

	return prog;
}

static int
bpfhv_programs_teardown(struct bpfhv_info *bi)
{
	if (bi->tx_publish_prog) {
		bpf_prog_free(bi->tx_publish_prog);
		bi->tx_publish_prog = NULL;
	}

	if (bi->tx_complete_prog) {
		bpf_prog_free(bi->tx_complete_prog);
		bi->tx_complete_prog = NULL;
	}

	if (bi->tx_ctx) {
		kfree(bi->tx_ctx);
		bi->tx_ctx = NULL;
	}

	if (bi->rx_publish_prog) {
		bpf_prog_free(bi->rx_publish_prog);
		bi->rx_publish_prog = NULL;
	}

	if (bi->rx_complete_prog) {
		bpf_prog_free(bi->rx_complete_prog);
		bi->rx_complete_prog = NULL;
	}

	if (bi->rx_ctx) {
		kfree(bi->rx_ctx);
		bi->rx_ctx = NULL;
	}

	return 0;
}

static int
bpfhv_open(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);

	bpfhv_rx_refill(bi);
	napi_enable(&bi->napi);
	mod_timer(&bi->intr_tmr, jiffies + msecs_to_jiffies(300));

	return 0;
}

static int
bpfhv_close(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);

	del_timer_sync(&bi->intr_tmr);
	napi_disable(&bi->napi);

	return 0;
}

static netdev_tx_t
bpfhv_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);
	struct bpfhv_tx_context *tx_ctx = bi->tx_ctx;
	unsigned int len = skb_headlen(skb);
	unsigned int nr_frags;
	unsigned int i;
	unsigned int f;
	int ret;

	nr_frags = skb_shinfo(skb)->nr_frags;
	if (unlikely(nr_frags + 1 > BPFHV_MAX_TX_SLOTS)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (bi->tx_free_slots < nr_frags + 1) {
		return NETDEV_TX_BUSY;
	}

	/* Prepare the input arguments for the txp program. */
	tx_ctx->cookie = (uintptr_t)skb;
	if (unlikely(len == 0)) {
		i = 0;
	} else {
		/* TODO dma_map_single(dev, skb->data, len, DMA_TO_DEVICE); */
		tx_ctx->phys[0] = (uintptr_t)NULL;
		tx_ctx->len[0] = len;
		i = 1;
	}

	for (f = 0; f < nr_frags; f++, i++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;

		if (unlikely(len == 0)) {
			continue;
		}

		/* TODO dma_map_page(dev, frag->page, frag->page_offset,
					len, DMA_TO_DEVICE); */
		tx_ctx->phys[i] = (uintptr_t)NULL;
		tx_ctx->len[i] = len;
	}
	tx_ctx->num_slots = i;
	bi->tx_free_slots -= i;

	/* Of course we should not free the skb, but for now we know that
	 * the txp program is a stub. */
	ret = BPF_PROG_RUN(bi->tx_publish_prog, /*ctx=*/tx_ctx);
	printk("txp(%u bytes) --> %d\n", skb->len, ret);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static void
bpfhv_intr_tmr(struct timer_list *tmr)
{
	struct bpfhv_info *bi = from_timer(bi, tmr, intr_tmr);

	{
		/* Trigger "reception" of a packet (see rxc_insns[]). */
		uint8_t rand;
		uint64_t *rxcntp = (uint64_t *)(&bi->rx_ctx[1]);

		get_random_bytes((void *)&rand, sizeof(rand));
		if (rand < 30) {
			(*rxcntp)++;
		}
	}

	napi_schedule(&bi->napi);
	bpfhv_tx_clean(bi);
	mod_timer(&bi->intr_tmr, jiffies + msecs_to_jiffies(300));
}

static void
bpfhv_tx_clean(struct bpfhv_info *bi)
{
	unsigned int count;

	for (count = 0;; count++) {
		int ret;

		ret = BPF_PROG_RUN(bi->tx_complete_prog, /*ctx=*/bi->tx_ctx);
		if (ret == 0) {
			/* No more completed transmissions. */
			break;
		}
		if (unlikely(ret < 0)) {
			printk("tcx() failed --> %d\n", ret);
			break;
		}
	}

	if (count) {
		printk("txc() --> %d packets\n", count);
		bi->tx_free_slots += count;
	}
}

static int
bpfhv_rx_refill(struct bpfhv_info *bi)
{
	struct bpfhv_rx_context *rx_ctx = bi->rx_ctx;
	unsigned int i;
	int ret;

	while (bi->rx_free_slots > 0) {
		size_t n = bi->rx_free_slots;

		if (n > BPFHV_MAX_RX_SLOTS) {
			n = BPFHV_MAX_RX_SLOTS;
		}

		/* Prepare the context for publishing receive buffers. */
		for (i = 0; i < n; i++) {
			rx_ctx->buf_cookie[i] = (uintptr_t)NULL;
			rx_ctx->phys[i] = (uintptr_t)NULL;
			rx_ctx->len[i] = 70;
		}
		rx_ctx->num_slots = i;
		bi->rx_free_slots -= i;

		ret = BPF_PROG_RUN(bi->rx_publish_prog, /*ctx=*/bi->rx_ctx);
		printk("rxp(%u bufs) --> %d\n", i, ret);
	}

	return 0;
}

static int
bpfhv_rx_poll(struct napi_struct *napi, int budget)
{
	struct bpfhv_info *bi = container_of(napi, struct bpfhv_info, napi);
	struct bpfhv_rx_context *rx_ctx = bi->rx_ctx;
	int count;

	for (count = 0; count < budget; count++) {
		struct sk_buff *skb;
		int ret;

		ret = BPF_PROG_RUN(bi->rx_complete_prog, /*ctx=*/rx_ctx);
		if (ret == 0) {
			/* No more completed transmissions. */
			break;
		}
		if (unlikely(ret < 0)) {
			printk("rxc() failed --> %d\n", ret);
			break;
		}

		skb = (struct sk_buff *)rx_ctx->packet;
		if (unlikely(!skb)) {
			printk("rxc() bug: skb not allocated\n");
			break;
		}

		skb->protocol = eth_type_trans(skb, bi->netdev);
		netif_receive_skb(skb);
	}

	napi_complete(napi);

	if (count > 0) {
		printk("rxc() --> %d packets\n", count);
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

#define TEST
#ifdef TEST
static int
test_bpf_program(const char *progname, struct bpf_insn *insns,
		size_t insn_count)
{
	struct bpf_prog *prog;
	int ret;

	prog = bpfhv_prog_alloc(progname, insns, insn_count);
	if (!prog) {
		return -EPERM;
	}

	ret = BPF_PROG_RUN(prog, /*ctx=*/NULL);
	printk("BPF_PROG_RUN(%s) returns %d\n", prog->aux->name, ret);

	bpf_prog_free(prog);

	return 0;
}

static void
test_bpf_programs(void)
{
	struct bpf_insn insns1[] = {
		BPF_MOV64_IMM(BPF_REG_2, 20),		/* R2 = 20 */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 10),	/* R2 += 10 */
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_2),	/* R3 = R2 */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_3),	/* R0 = R3 */
		BPF_EXIT_INSN(),
	};

	struct bpf_insn insns2[] = {
		BPF_MOV64_IMM(BPF_REG_8, 0),			/* R8 = 0 */
		BPF_MOV64_IMM(BPF_REG_7, 0),			/* R7 = 0 */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 3),		/* l: R7 += 3 */
		BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_8),	/* R7 -= R8 */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1),		/* R8 += 1 */
		BPF_JMP_IMM(BPF_JLT, BPF_REG_8, 10, -4),	/* if R8 < 10 goto l */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_7),		/* R0 = R7 */
		BPF_EXIT_INSN(),
	};
	test_bpf_program("simple", insns1, sizeof(insns1) / sizeof(insns1[0]));
	test_bpf_program("fixed-loop", insns2, sizeof(insns2) / sizeof(insns2[0]));
}
#endif  /* TEST */

static struct bpfhv_info *__bip = NULL;

static int __init
bpfhv_init(void)
{
#ifdef TEST
	test_bpf_programs();
#endif  /* TEST */

	return bpfhv_netdev_setup(&__bip);
}

static void __exit
bpfhv_fini(void)
{
	if (__bip) {
		bpfhv_netdev_teardown(__bip);
	}
}

module_init(bpfhv_init);
module_exit(bpfhv_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
