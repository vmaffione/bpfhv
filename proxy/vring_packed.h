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

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE	0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE	0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC	0x2

/*
 * Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define VRING_PACKED_EVENT_F_WRAP_CTR	15
/*
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL	7
#define VRING_PACKED_DESC_F_USED	15


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
    /* Is this entry busy or free ? */
    uint16_t busy;
    /* Number of descriptors in the chain. */
    uint16_t num;
    /* Next descriptor state in the chain. */
    uint16_t next;
    /* Last descriptor state in the chain. */
    uint16_t last;
};

struct vring_packed_desc_event {
    /* Descriptor Ring Change Event Offset/Wrap Counter. */
    uint16_t off_wrap;
    /* Descriptor Ring Change Event Flags. */
    uint16_t flags;
};

struct vring_packed_virtq {
    /* Producer private. */
    struct {
        uint16_t next_free_id;
        uint16_t next_avail_idx;
        uint16_t next_used_idx;
        uint8_t avail_wrap_counter;
        uint8_t used_wrap_counter;
        uint16_t avail_used_flags;
    } g;

    /* Consumer private. */
    MY_CACHELINE_ALIGNED
    struct {
        uint16_t next_avail_idx;
        uint16_t next_used_idx;
        uint8_t avail_wrap_counter;
        uint8_t used_wrap_counter;
        uint16_t avail_used_flags;
        /* Shadow variable for vq->device_event.flags */
        uint16_t device_event_flags;
    } h;

    /* Read only. */
    MY_CACHELINE_ALIGNED
    uint64_t state_ofs;
    uint32_t num_desc;

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

/* Only valid after initialization. */
struct vring_packed_desc_state *
vring_packed_state(const struct vring_packed_virtq *vq)
{
    return (struct vring_packed_desc_state *)(((char *)vq) + vq->state_ofs);
}

#endif  /* __BPFHV_VRING_PACKED_H__ */
