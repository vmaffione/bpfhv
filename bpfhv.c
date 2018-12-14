/*
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

static int
test_bpf_program(struct bpf_insn *insns, unsigned int insn_count)
{
	struct bpf_prog *prog;
	int ret;

	prog = bpf_prog_alloc(bpf_prog_size(insn_count), GFP_USER);
	if (!prog) {
		return -ENOMEM;
	}
	prog->len = insn_count;
	memcpy(prog->insnsi, insns, bpf_prog_insn_size(prog));
	atomic_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = 1;
	prog->type = BPF_PROG_TYPE_UNSPEC;
	prog->aux->load_time = ktime_get_boot_ns();
	strlcpy(prog->aux->name, "bpfhv", sizeof(prog->aux->name));

	/* Replacement for bpf_check(). */
	prog->aux->stack_depth = MAX_BPF_STACK;

	prog = bpf_prog_select_runtime(prog, &ret);
	if (ret < 0) {
		printk("bpf_prog_select_runtime() failed: %d\n", ret);
	}

	ret = BPF_PROG_RUN(prog, /*ctx=*/NULL);
	printk("BPF_PROG_RUN returns %d\n", ret);

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

	test_bpf_program(insns1, sizeof(insns1) / sizeof(insns1[0]));
}

static int __init
bpfhv_init(void)
{
	test_bpf_programs();
	return 0;
}

static void __exit
bpfhv_fini(void)
{
}

module_init(bpfhv_init);
module_exit(bpfhv_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
