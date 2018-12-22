/*
 *    Shared definitions for the eBPF paravirtual device.
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

/*
 * When compiling from userspace include <stdint.h>,
 * when compiling from kernelspace include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else  /* !__KERNEL__ */
#include <stdint.h>
#endif /* !__KERNEL__ */

/* Context for the transmit-side eBPF programs. */
struct bpfhv_tx_context {
	/* Reference to guest OS data structures, filled by the guest.
	 * This field can be used by the helper functions. */
	uint64_t	guest_priv;
	/*
	 * Array of physical addresses and lengths, representing a
	 * scatter-gather buffer. The number of valid slots is stored
	 * in 'num_slots'. Guest OS packet reference (e.g., pointer to sk_buff
	 * or mbuf) can be stored in 'cookie'.
	 *
	 * On publication, 'phys', 'len', 'cookie' and 'num_slots'
	 * are input argument for the eBPF program.
	 * On completion, 'cookie' is an output argument, while
	 * all the other fields are invalid.
	 */
	uint64_t	cookie;
#define BPFHV_MAX_TX_SLOTS		64
	uint64_t	phys[BPFHV_MAX_TX_SLOTS];
	uint32_t	len[BPFHV_MAX_TX_SLOTS];
	uint32_t	num_slots;
	uint32_t	pad[15];

	/* Private hv-side context follows here. */
	char		opaque[0];
};

/* Context for the receive-side eBPF programs. */
struct bpfhv_rx_context {
	/* Reference to guest OS data structures, filled by the guest.
	 * This field can be used by the helper functions. */
	uint64_t	guest_priv;
	/*
	 * Array of physical addresses and lengths, representing a set of
	 * buffers. The number of valid slots is stored in 'num_slots'.
	 * The buffer cookies can be used by the guest OS to identify the
	 * buffers when building the OS packet (e.g. sk_buff or mbuf).
	 * A reference to the OS packet can be stored in 'packet'.
	 *
	 * On publication, 'phys', 'len', 'buf_cookie' and 'num_slots'
	 * are input arguments for the eBPF program, and the 'packet'
	 * field is invalid.
	 * On receiving, 'packet' is an output argument, and it contains
	 * a pointer to a guest OS packet. The OS packet allocated by the
	 * receive eBPF program by means of a helper call.
	 * All the other fields are invalid.
	 */
	uint64_t	packet;
#define BPFHV_MAX_RX_SLOTS		64
	uint64_t	buf_cookie[BPFHV_MAX_RX_SLOTS];
	uint64_t	phys[BPFHV_MAX_RX_SLOTS];
	uint32_t	len[BPFHV_MAX_RX_SLOTS];
	uint32_t	num_slots;
	uint32_t	pad[15];

	/* Private hv-side context follows here. */
	char		opaque[0];
};

/* Numbers for the helper calls used by bpfhv programs. */
#define BPFHV_HELPER_MAGIC	0x4b8f0000
enum bpfhv_helper_id {
	BPFHV_pkt_alloc = BPFHV_HELPER_MAGIC,
};

/* PCI device definitions, including PCI identifiers,
 * BAR numbers, and device registers. */
#define BPFHV_IO_PCI_BAR		0
#define BPFHV_MSIX_PCI_BAR		1

#define BPFHV_IO_MAC_LO			0
#define BPFHV_IO_MAC_HI			4
#define BPFHV_IO_NUM_RX_QUEUES		8
#define BPFHV_IO_NUM_TX_QUEUES		12
#define BPFHV_IO_NUM_RX_SLOTS		16
#define BPFHV_IO_NUM_TX_SLOTS		20
#define BPFHV_IO_END			24
#define BPFHV_IO_MASK			0xff

