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

#include "bpfhv_context.h"

struct bpfhv_info {
	struct net_device *netdev;
	struct napi_struct napi;

	struct bpf_prog *tx_publish_prog;
	struct bpf_prog *tx_complete_prog;
	struct bpf_prog *rx_publish_prog;
	struct bpf_prog *rx_complete_prog;
};

static int		bpfhv_netdev_setup(struct bpfhv_info **bip);
static void		bpfhv_netdev_teardown(struct bpfhv_info *bi);
static int		bpfhv_programs_setup(struct bpfhv_info *bi);
static struct bpf_prog	*bpfhv_prog_alloc(const char *progname,
						struct bpf_insn *insns,
						unsigned int insn_count);
static int		bpfhv_programs_teardown(struct bpfhv_info *bi);

static int		bpfhv_open(struct net_device *netdev);
static int		bpfhv_close(struct net_device *netdev);
static netdev_tx_t	bpfhv_start_xmit(struct sk_buff *skb,
					struct net_device *netdev);
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
	netdev->features = NETIF_F_HIGHDMA;
	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	netif_napi_add(netdev, &bi->napi, bpfhv_rx_poll, NAPI_POLL_WEIGHT);

	ret = bpfhv_programs_setup(bi);
	if (ret) {
		goto err_prog;
	}

	ret = register_netdev(netdev);
	if (ret) {
		goto err_reg;
	}

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

static int
bpfhv_programs_setup(struct bpfhv_info *bi)
{
	struct bpf_insn stub[] = {
		BPF_MOV64_IMM(BPF_REG_0, 42),
	};
	const unsigned int insn_count = sizeof(stub)/sizeof(stub[0]);

	bpfhv_programs_teardown(bi);

	bi->tx_publish_prog = bpfhv_prog_alloc("txp", stub, insn_count);
	if (bi->tx_publish_prog == NULL) {
		goto err;
	}

	bi->tx_complete_prog = bpfhv_prog_alloc("txc", stub, insn_count);
	if (bi->tx_complete_prog == NULL) {
		goto err;
	}

	bi->rx_publish_prog = bpfhv_prog_alloc("rxp", stub, insn_count);
	if (bi->rx_publish_prog == NULL) {
		goto err;
	}

	bi->rx_complete_prog = bpfhv_prog_alloc("rxc", stub, insn_count);
	if (bi->rx_complete_prog == NULL) {
		goto err;
	}

	return 0;
err:
	bpfhv_programs_teardown(bi);
	return -1;
}

/* Taken from kernel/bpf/syscall.c:bpf_prog_load(). */
static struct bpf_prog *
bpfhv_prog_alloc(const char *progname, struct bpf_insn *insns,
		unsigned int insn_count)
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

	if (bi->rx_publish_prog) {
		bpf_prog_free(bi->rx_publish_prog);
		bi->rx_publish_prog = NULL;
	}

	if (bi->rx_complete_prog) {
		bpf_prog_free(bi->rx_complete_prog);
		bi->rx_complete_prog = NULL;
	}

	return 0;
}

static int
bpfhv_open(struct net_device *netdev)
{
	struct bpfhv_info *bi = netdev_priv(netdev);

	(void)bi;

	return 0;
}

static int
bpfhv_close(struct net_device *netdev)
{
	return 0;
}

static netdev_tx_t
bpfhv_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int
bpfhv_rx_poll(struct napi_struct *napi, int budget)
{
	struct bpfhv_info *bi = container_of(napi, struct bpfhv_info, napi);
	(void)bi;

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
		unsigned int insn_count)
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
