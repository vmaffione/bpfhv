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
	/*
	 * Array of physical addresses and lengths, representing a
	 * scatter-gather buffer. The number of valid slots is stored
	 * in 'num_slots'. OS packet reference (e.g., pointer to sk_buff
	 * or mbuf) is stored in 'packet_cookie'.
	 *
	 * On publication, 'phys', 'len', 'packet_cookie' and 'num_slots'
	 * are input argument for the eBPF program.
	 * On completion, 'packet_cookie' is an output argument, while
	 * all the other fields are invalid.
	 */
	uint64_t	packet_cookie;
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
	/*
	 * Array of physical addresses and lengths, representing a
	 * scatter-gather buffer. The number of valid slots is stored
	 * in 'num_slots'. OS packet reference (e.g., pointer to sk_buff
	 * or mbuf) is stored in 'packet_cookie'.
	 *
	 * On publication, 'phys', 'len', 'buf_cookies' and 'num_slots'
	 * are input arguments for the eBPF program.
	 * The 'packet_cookie' field is invalid.
	 * On receiving, 'packet_cookie' is an output argument, and it contains
	 * a pointer to an OS packet. The OS packet allocated by the receive
	 * eBPF program through a helper call.
	 * All the other fields are invalid.
	 */
	uint64_t	packet_cookie;
#define BPFHV_MAX_RX_SLOTS		64
	uint64_t	buf_cookies[BPFHV_MAX_RX_SLOTS];
	uint64_t	phys[BPFHV_MAX_RX_SLOTS];
	uint32_t	len[BPFHV_MAX_RX_SLOTS];
	uint32_t	num_slots;
	uint32_t	pad[15];

	/* Private hv-side context follows here. */
	char		opaque[0];
};

