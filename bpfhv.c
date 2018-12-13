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

static int
test_bpf_program(void)
{
	struct bpf_prog *prog;
	unsigned int insn_count;
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_2, 20),
		BPF_MOV64_IMM(BPF_REG_3, 30),
	};

	insn_count = sizeof(insns) / sizeof(insns[0]);

	prog = bpf_prog_alloc(bpf_prog_size(insn_count), GFP_USER);
	if (!prog) {
		return -ENOMEM;
	}

	bpf_prog_free(prog);

	return 0;
}

static int __init
bpfhv_init(void)
{
	return test_bpf_program();
}

static void __exit
bpfhv_fini(void)
{
}

module_init(bpfhv_init);
module_exit(bpfhv_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
