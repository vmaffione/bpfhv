/*
 * BPFHV paravirtual network device
 *   Definitions shared between the sring eBPF programs and the
 *   vring_packed hv implementation.
 *
 * Copyright (c) 2018 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BPFHV_VRING_PACKED_H__
#define __BPFHV_VRING_PACKED_H__

#include <stdint.h>

#define MY_CACHELINE_SIZE   64
#define MY_CACHELINE_ALIGNED    __attribute__((aligned(MY_CACHELINE_SIZE)))

struct vring_packed_desc {
    /* Buffer Address. */
    uint64_t addr;
    /* Buffer Length. */
    uint32_t len;
    /* Buffer ID. */
    uint16_t id;
    /* The flags depending on descriptor type. */
    uint16_t flags;
};

struct vring_packed_desc_state {
    /* Guest cookie associated to this descriptor. */
    uint64_t cookie;
    /* Number of descriptors in the chain. */
    uint16_t num;
    /* Next descriptor state in the chain. */
    uint16_t next;
    /* Last descriptor state in the chain. */
    uint16_t last;
    uint16_t pad1;
};

struct vring_packed_desc_event {
    /* Descriptor Ring Change Event Offset/Wrap Counter. */
    uint16_t off_wrap;
    /* Descriptor Ring Change Event Flags. */
    uint16_t flags;
};

struct vring_packed_virtq {
    /* Producer private. */
    uint32_t next_free_id;
    uint32_t next_avail_idx;
    uint32_t next_used_idx;
    uint8_t avail_wrap_counter;
    uint8_t used_wrap_counter;

    MY_CACHELINE_ALIGNED
    struct vring_packed_desc_event driver_event;

    MY_CACHELINE_ALIGNED
    struct vring_packed_desc_event device_event;

    MY_CACHELINE_ALIGNED
    struct vring_packed_desc desc[0];
/*
 *  struct vring_packed_desc_state state[0];
 */
};

#endif  /* __BPFHV_VRING_PACKED_H__ */
