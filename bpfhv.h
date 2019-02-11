#ifndef __BPFHV_H__
#define __BPFHV_H__
/*
 *    Definitions for the eBPF paravirtual device, shared between
 *    the guest driver and the hypervisor.
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
 * When compiling user-space code include <stdint.h>,
 * when compiling kernel-space code include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else  /* !__KERNEL__ */
#include <stdint.h>
#endif /* !__KERNEL__ */

struct bpfhv_tx_buf {
	uint64_t cookie;
	uint64_t paddr;
	uint32_t len;
	uint32_t reserved;
};

/* Context for the transmit-side eBPF programs. */
struct bpfhv_tx_context {
	/* Reference to guest OS data structures, filled by the guest.
	 * This field can be used by the helper functions. */
	uint64_t		guest_priv;
	/*
	 * Array of buffer descriptors, representing a scatter-gather
	 * buffer. The number of valid descriptors is stored in 'num_bufs'.
	 * Each descriptor contains the guest physical address (GPA) of
	 * a buffer ('paddr'), the buffer length in bytes ('len') and
	 * a value private to the guest ('cookie'), that the guest can
	 * use to match published buffers to completed ones.
	 *
	 * On publication, 'packet', 'bufs' and 'num_bufs' are input argument
	 * for the eBPF program, and 'oflags' is an output argument. The
	 * BPFHV_OFLAGS_NOTIF_NEEDED bit is set if the guest is required
	 * to notify the hypervisor.
	 * On completion, 'bufs', 'num_bufs' and 'oflags' are output arguments.
	 * The 'bufs' and 'num_bufs' argument contain information about the
	 * packet that was successfully transmitted. Tha
	 * BPFHV_OFLAGS_RESCHED_NEEDED flag is set if more completion events
	 * are available.
	 */
	uint64_t		packet;
#define BPFHV_MAX_TX_BUFS		64
	struct bpfhv_tx_buf	bufs[BPFHV_MAX_TX_BUFS];
	uint32_t		num_bufs;
	uint32_t		oflags;
#define BPFHV_OFLAGS_NOTIF_NEEDED	(1 << 0)
#define BPFHV_OFLAGS_RESCHED_NEEDED	(1 << 1)
	uint32_t		min_completed_bufs;
	uint32_t		pad[13];

	/* Private hv-side context follows here. */
	char			opaque[0];
};

struct bpfhv_rx_buf {
	uint64_t cookie;
	uint64_t paddr;
	uint32_t len;
	uint32_t reserved;
};

/* Context for the receive-side eBPF programs. */
struct bpfhv_rx_context {
	/* Reference to guest OS data structures, filled by the guest.
	 * This field can be used by the helper functions. */
	uint64_t		guest_priv;
	/*
	 * Array of buffer descriptors, representing a list of independent
	 * buffers to be used for packet reception.
	 * The number of valid descriptors is stored in 'num_bufs'.
	 * Each descriptor contains the guest physical address (GPA) of
	 * a buffer ('paddr'), the buffer length in bytes ('len') and
	 * a value private to the guest ('cookie'), that the guest can
	 * use to match published buffers to completed ones.
	 *
	 * On publication, 'bufs' and 'num_bufs' are input argument for
	 * the eBPF program, and 'oflags' is an output argument. The
	 * BPFHV_OFLAGS_NOTIF_NEEDED bit is set if the guest is required
	 * to notify the hypervisor.
	 * On completion, 'bufs', 'num_bufs' and 'oflags' are output arguments.
	 * The 'bufs' and 'num_bufs' argument contain the list of buffers that
	 * were used to receive a packet. A pointer to the OS packet is
	 * available in the 'packet' field. The OS packet allocated by the
	 * receive eBPF program by means of a helper call.
	 */
	uint64_t		packet;
#define BPFHV_MAX_RX_BUFS		64
	struct bpfhv_rx_buf	bufs[BPFHV_MAX_RX_BUFS];
	uint32_t		num_bufs;
	uint32_t		oflags;
	uint32_t		min_completed_bufs;
	uint32_t		pad[13];

	/* Private hv-side context follows here. */
	char			opaque[0];
};

/* Numbers for the helper calls used by bpfhv programs. */
#define BPFHV_HELPER_MAGIC	0x4b8f0000
enum bpfhv_helper_id {
	BPFHV_FUNC_rx_pkt_alloc = BPFHV_HELPER_MAGIC,
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
#define BPFHV_REG_PCI_BAR		0
#define BPFHV_DOORBELL_PCI_BAR		1
#define BPFHV_MSIX_PCI_BAR		2
#define BPFHV_PROG_PCI_BAR		3

/*
 * Device status register (guest read only, hv read/write):
 *   - bit 0: link status: value is 0 if link is down, 1 if link is up;
 *   - bit 1: upgrade pending: value is 1 if a program upgrade is pending;
 *   - bit 2: receive enabled: value is 1 if receive operation is enabled;
 *   - bit 3: transmit enabled: value is 1 if transmit operation is enabled;
 */
#define BPFHV_REG_STATUS			0
#define		BPFHV_STATUS_LINK	(1 << 0)
#define		BPFHV_STATUS_UPGRADE	(1 << 1)
#define		BPFHV_STATUS_RX_ENABLED (1 << 2)
#define		BPFHV_STATUS_TX_ENABLED (1 << 3)

/*
 * Device control register (guest read/write, hv read only):
 *   - bit 0: receive enable: receive operation is enabled if set, and disabled
 *            if reset; setting may fail if receove contexts are not valid
 *   - bit 1: transmit enable: transmit operation is enabled if set, and
 *            disabled if reset; setting may fail if transmit contexts are
 *            not valid
 *   - bit 2: upgrade ready: writing 1 this bit tells the hypervisor that the
 *            guest is ready to proceed with the program upgrade; the
 *            hypervisor will then load the new program in the program MMIO
 *            and reset the BPFHV_STATUS_UPGRADE bit the status register;
 */
#define BPFHV_REG_CTRL			4
#define		BPFHV_CTRL_RX_ENABLE		(1 << 0)
#define		BPFHV_CTRL_TX_ENABLE		(1 << 1)
#define		BPFHV_CTRL_UPGRADE_READY	(1 << 2)

/* Device MAC address: the least significant 32 bits of the address are taken
 * from MAC_LO, while the most significant 16 bits are taken from the least
 * significant 16 bits of MAC_HI. */
#define BPFHV_REG_MAC_LO			8
#define BPFHV_REG_MAC_HI			12

/* Number of receive and transmit queues implemented by the device. */
#define BPFHV_REG_NUM_RX_QUEUES		16
#define BPFHV_REG_NUM_TX_QUEUES		20

/* The maximum number of pending buffers for receive and transmit queues. */
#define BPFHV_REG_NUM_RX_BUFS		24
#define BPFHV_REG_NUM_TX_BUFS		28

/* Size of per-queue context for receive and transmit queues. The context
 * size includes the size of struct bpfhv_rx_context (or struct
 * bpfhv_tx_context) plus the size of hypervisor-specific data structures. */
#define BPFHV_REG_RX_CTX_SIZE            32
#define BPFHV_REG_TX_CTX_SIZE            36

/* A guest can notify a queue by writing (any value) to a per-queue doorbell
 * register. Doorbell registers are exposed through a separate memory-mapped
 * I/O region, and laid out as an array. The BPFHV_REG_DOORBELL_SIZE reports
 * the size of each slot in the array. Writing to any address within the i-th
 * slot will ring the i-th doorbell. Indices in [0, NUM_RX_QUEUES-1] reference
 * receive queues, while transmit queues correspond to indices in
 * [NUM_RX_QUEUES, NUM_RX_QUEUES + NUM_TX_QUEUES - 1].
 */
#define BPFHV_REG_DOORBELL_SIZE		40

/* A register where the guest can write the index of a receive or transmit
 * queue, and subsequently perform an operation on that queue. Indices in
 * [0, NUM_RX_QUEUES-1] reference receive queues, while transmit queues
 * correspond to indices in [NUM_RX_QUEUES, NUM_RX_QUEUES + NUM_TX_QUEUES - 1].
 */
#define BPFHV_REG_QUEUE_SELECT		44

/* A 64-bit register where the guest can write the physical address of the
 * receive or transmit context for the selected queue. */
#define BPFHV_REG_CTX_PADDR_LO		48
#define BPFHV_REG_CTX_PADDR_HI		52

/* Select the eBPF program to be read from the device. A guest can write to
 * the select register, and then read the program size (BPFHV_REG_PROG_SIZE)
 * and the actual eBPF code. The program size is expressed as a number of
 * eBPF instructions (with each instruction being 8 bytes wide). */
#define BPFHV_REG_PROG_SELECT		56
enum {
	BPFHV_PROG_NONE = 0,
	BPFHV_PROG_RX_PUBLISH,
	BPFHV_PROG_RX_COMPLETE,
	BPFHV_PROG_RX_INTRS,
	BPFHV_PROG_RX_RECLAIM,
	BPFHV_PROG_TX_PUBLISH,
	BPFHV_PROG_TX_COMPLETE,
	BPFHV_PROG_TX_INTRS,
	BPFHV_PROG_TX_RECLAIM,
	BPFHV_PROG_MAX,
};
#define BPFHV_REG_PROG_SIZE		60
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
#define BPFHV_REG_DOORBELL_GVA_LO	64
#define BPFHV_REG_DOORBELL_GVA_HI	68

/* Read only register containing the device version. Used by the driver to
 * check that it was compiled with this same header file as the hypervisor. */
#define BPFHV_REG_VERSION		72
#define		BPFHV_VERSION	1

/* Marker for the end of valid registers, and size of the I/O region. */
#define BPFHV_REG_END			76
#define BPFHV_REG_MASK			0xff

#endif  /* __BPFHV_H__ */
