#ifndef __BPFHV_H__
#define __BPFHV_H__
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
	 * scatter-gather buffer. The number of valid bufs is stored
	 * in 'num_bufs'. Guest OS packet reference (e.g., pointer to sk_buff
	 * or mbuf) can be stored in 'cookie'.
	 *
	 * On publication, 'phys', 'len', 'cookie' and 'num_bufs'
	 * are input argument for the eBPF program, and 'oflags' is
	 * an output argument.
	 * On completion, 'cookie' and 'oflags' are output arguments, while
	 * all the other fields are invalid.
	 */
	uint64_t	cookie;
#define BPFHV_MAX_TX_BUFS		64
	uint64_t	phys[BPFHV_MAX_TX_BUFS];
	uint32_t	len[BPFHV_MAX_TX_BUFS];
	uint32_t	num_bufs;
	uint32_t	oflags;
#define BPFHV_OFLAGS_NOTIF_NEEDED	(1 << 0)
#define BPFHV_OFLAGS_RESCHED_NEEDED	(1 << 1)
	uint32_t	pad[14];

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
	 * buffers. The number of valid bufs is stored in 'num_bufs'.
	 * The buffer cookies can be used by the guest OS to identify the
	 * buffers when building the OS packet (e.g. sk_buff or mbuf).
	 * A reference to the OS packet can be stored in 'packet'.
	 *
	 * On publication, 'phys', 'len', 'buf_cookie' and 'num_bufs'
	 * are input arguments for the eBPF program, the 'packet'
	 * field is invalid, and 'oflags' is an output argument.
	 * On receiving, 'packet' and 'oflags' are output arguments, with
	 * 'packet' containing a pointer to a guest OS packet.
	 * The OS packet allocated by the receive eBPF program by means of
	 * a helper call.
	 * All the other fields are invalid.
	 */
	uint64_t	packet;
#define BPFHV_MAX_RX_BUFS		64
	uint64_t	buf_cookie[BPFHV_MAX_RX_BUFS];
	uint64_t	phys[BPFHV_MAX_RX_BUFS];
	uint32_t	len[BPFHV_MAX_RX_BUFS];
	uint32_t	num_bufs;
	uint32_t	oflags;
	uint32_t	pad[14];

	/* Private hv-side context follows here. */
	char		opaque[0];
};

/* Numbers for the helper calls used by bpfhv programs. */
#define BPFHV_HELPER_MAGIC	0x4b8f0000
enum bpfhv_helper_id {
	BPFHV_FUNC_pkt_alloc = BPFHV_HELPER_MAGIC,
};

#ifndef BPFHV_FUNC
#define BPFHV_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPFHV_FUNC_##NAME
#endif

/* Example of helper call definition, to be used in the C code to be compiled
 * into eBPF. */
#if 0
static void *BPFHV_FUNC(pkt_alloc, struct bpfhv_rx_context *ctx);
#endif

/*
 * PCI device definitions, including PCI identifiers,
 * BAR numbers, and device registers.
 */
#define BPFHV_PCI_VENDOR_ID		0x1b36 /* qemu virtual devices */
#define BPFHV_PCI_DEVICE_ID		0x000e
#define BPFHV_IO_PCI_BAR		0
#define BPFHV_DOORBELL_PCI_BAR		1
#define BPFHV_MSIX_PCI_BAR		2
#define BPFHV_PROG_PCI_BAR		3

/*
 * Device status register:
 *   - bit 0: link status: value is 0 if link is down, 1 if link is up
 */
#define BPFHV_IO_STATUS			0
#define		BPFHV_STATUS_LINK	(1 << 0)

/* Device MAC address: the least significant 32 bits of the address are taken
 * from MAC_LO, while the most significant 16 bits are taken from the least
 * significant 16 bits of MAC_HI. */
#define BPFHV_IO_MAC_LO			4
#define BPFHV_IO_MAC_HI			8

/* Number of receive and transmit queues implemented by the device. */
#define BPFHV_IO_NUM_RX_QUEUES		12
#define BPFHV_IO_NUM_TX_QUEUES		16

/* The maximum number of pending buffers for receive and transmit queues. */
#define BPFHV_IO_NUM_RX_BUFS		20
#define BPFHV_IO_NUM_TX_BUFS		24

/* Size of per-queue context for receive and transmit queues. The context
 * size includes the size of struct bpfhv_rx_context (or struct
 * bpfhv_tx_context) plus the size of hypervisor-specific data structures. */
#define BPFHV_IO_RX_CTX_SIZE            28
#define BPFHV_IO_TX_CTX_SIZE            32

/* A guest can notify a queue by writing (any value) to a per-queue doorbell
 * register. Doorbell registers are exposed through a separate memory-mapped
 * I/O region, and laid out as an array. The BPFHV_IO_DOORBELL_SIZE reports
 * the size of each slot in the array. Writing to any address within the i-th
 * slot will ring the i-th doorbell. Indices in [0, NUM_RX_QUEUES-1] reference
 * receive queues, while transmit queues correspond to indices in
 * [NUM_RX_QUEUES, NUM_RX_QUEUES + NUM_TX_QUEUES - 1].
 */
#define BPFHV_IO_DOORBELL_SIZE		36

/* A register where the guest can write the index of a receive or transmit
 * queue, and subsequently perform an operation on that queue. Indices in
 * [0, NUM_RX_QUEUES-1] reference receive queues, while transmit queues
 * correspond to indices in [NUM_RX_QUEUES, NUM_RX_QUEUES + NUM_TX_QUEUES - 1].
 */
#define BPFHV_IO_QUEUE_SELECT		40

/* A 64-bit register where the guest can write the physical address of the
 * receive or transmit context for the selected queue. */
#define BPFHV_IO_CTX_PADDR_LO		44
#define BPFHV_IO_CTX_PADDR_HI		48

/* Select the eBPF program to be read from the device. A guest can write to
 * the select register, and then read the program size (BPFHV_IO_PROG_SIZE)
 * and the actual eBPF code. The program size is expressed as a number of
 * eBPF instructions (with each instruction being 8 bytes wide). */
#define BPFHV_IO_PROG_SELECT		52
enum {
	BPFHV_PROG_NONE = 0,
	BPFHV_PROG_TX_PUBLISH,
	BPFHV_PROG_TX_COMPLETE,
	BPFHV_PROG_RX_PUBLISH,
	BPFHV_PROG_RX_COMPLETE,
	BPFHV_PROG_MAX,
};
#define BPFHV_IO_PROG_SIZE		56
#define BPFHV_PROG_SIZE_MAX		16384

/* A 64-bit register where the guest can write the Guest Virtual Address
 * of the doorbell region. This is needed by the hypervisor to relocate
 * the eBPF instructions that send notifications to the hypervisor itself
 * (since guest-->host notifications are triggered by memory writes into
 * the doorbell region). The guest is required to provide the GVA before
 * reading any eBPF program from the program mmio region. Note, however,
 * that notifications can also be performed directly by the guest native
 * code, and therefore the hypervisor is not required to implement a
 * relocation mechanism.  */
#define BPFHV_IO_DOORBELL_GVA_LO	60
#define BPFHV_IO_DOORBELL_GVA_HI	64

/* Marker for the end of valid registers, and size of the I/O region. */
#define BPFHV_IO_END			68
#define BPFHV_IO_MASK			0xff

#endif  /* __BPFHV_H__ */
