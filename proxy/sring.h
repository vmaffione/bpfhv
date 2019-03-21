/*
 * BPFHV paravirtual network device
 *   Definitions shared between the sring eBPF programs and the
 *   sring hv implementation.
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

#ifndef __BPFHV_SRING_H__
#define __BPFHV_SRING_H__

#include <stdint.h>

struct sring_tx_desc {
    uint64_t cookie;
    uint64_t paddr;
    uint32_t len;
    uint32_t pad;
};

struct sring_tx_context {
    /* Guest write, hv reads. */
    uint32_t prod;
    uint32_t intr_at;
    uint32_t pad1[30];

    /* Guest reads, hv writes. */
    uint32_t cons;
    uint32_t kick_enabled;
    uint32_t pad2[30];

    /* Guest reads, hv reads. */
    uint32_t qmask;
    uint32_t pad3[31];

    /* Private to the guest. */
    uint32_t clear;
    uint32_t pad4[31];

    struct sring_tx_desc desc[0];
};

struct sring_rx_desc {
    uint64_t cookie;
    uint64_t paddr;
    uint32_t len;
    uint32_t pad;
};

struct sring_rx_context {
    /* Guest write, hv reads. */
    uint32_t prod;
    uint32_t intr_enabled;
    uint32_t pad1[30];

    /* Guest reads, hv writes. */
    uint32_t cons;
    uint32_t kick_enabled;
    uint32_t pad2[30];

    /* Guest reads, hv reads. */
    uint32_t qmask;
    uint32_t pad3[31];

    /* Private to the guest. */
    uint32_t clear;
    uint32_t pad4[31];

    struct sring_rx_desc desc[0];
};

#endif  /* __BPFHV_SRING_H__ */
