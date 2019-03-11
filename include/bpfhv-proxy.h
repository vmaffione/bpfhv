/*
 *    A control protocol to delegate the bpfhv packet processing work
 *    to a separate process.
 *    2019 Vincenzo Maffione <v.maffione@gmail.it>
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

#ifndef __BPFHV_PROXY_H__
#define __BPFHV_PROXY_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BPFHV_PROXY_MAX_REGIONS     8

typedef struct BpfhvProxyMemoryRegion {
    uint64_t        guest_physical_addr;
    uint64_t        size;
    uint64_t        hypervisor_virtual_addr;
    uint64_t        mmap_offset;
} BpfhvProxyMemoryRegion;

typedef struct BpfhvProxyMemoryMap {
    uint32_t                num_regions;
    uint32_t                pad;
    BpfhvProxyMemoryRegion  regions[BPFHV_PROXY_MAX_REGIONS];
} BpfhvProxyMemoryMap;

typedef struct BpfhvProxyParameters {
    uint32_t        num_rx_queues;
    uint32_t        num_tx_queues;
    uint32_t        num_rx_bufs;
    uint32_t        num_tx_bufs;
} BpfhvProxyParameters;

typedef struct BpfhvProxyCtxSizes {
    uint32_t        rx_ctx_size;
    uint32_t        tx_ctx_size;
} BpfhvProxyCtxSizes;

typedef struct BpfhvProxyQueueCtx {
    /* Queues [0..N-1] are for receive. Queues [N..2N-1] are for transmit. */
    uint32_t            queue_idx;
    uint32_t            pad;
    uint64_t            guest_physical_addr;
} BpfhvProxyQueueCtx;

typedef struct BpfhvProxyNotifier {
    /* Queues [0..N-1] are for receive. Queues [N..2N-1] are for transmit. */
    uint32_t            queue_idx;
} BpfhvProxyNotifier;

typedef enum BpfhvProxyReqType {
    BPFHV_PROXY_REQ_NONE = 0,
    BPFHV_PROXY_REQ_GET_FEATURES,
    BPFHV_PROXY_REQ_SET_FEATURES,
    BPFHV_PROXY_REQ_SET_PARAMETERS,
    BPFHV_PROXY_REQ_GET_PROGRAMS,
    BPFHV_PROXY_REQ_SET_MEM_TABLE,
    BPFHV_PROXY_REQ_SET_QUEUE_CTX,
    BPFHV_PROXY_REQ_SET_QUEUE_KICK,
    BPFHV_PROXY_REQ_SET_QUEUE_IRQ,
    BPFHV_PROXY_REQ_SET_UPGRADE,
    BPFHV_PROXY_REQ_RX_ENABLE,
    BPFHV_PROXY_REQ_TX_ENABLE,
    BPFHV_PROXY_REQ_RX_DISABLE,
    BPFHV_PROXY_REQ_TX_DISABLE,
} BpfhvProxyReqType;

typedef union BpfhvProxyMsgPayload {
    uint64_t                u64;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_GET_FEATURES (resp)
     *   - BPFHV_PROXY_REQ_SET_FEATURES
     *   - BPFHV_PROXY_REQ_SET_NUM_QUEUES
     */

    BpfhvProxyParameters    params;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_SET_PARAMETERS
     */

    BpfhvProxyCtxSizes      ctx_sizes;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_SET_PARAMETERS (resp)
     */

    BpfhvProxyMemoryMap     memory_map;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_SET_MEM_TABLE
     */

    BpfhvProxyQueueCtx      queue_ctx;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_SET_QUEUE_CTX
     */

    BpfhvProxyNotifier      notify;
    /* Associated messages:
     *   - BPFHV_PROXY_REQ_SET_QUEUE_KICK
     *   - BPFHV_PROXY_REQ_SET_QUEUE_IRQ
     *   - BPFHV_PROXY_REQ_SET_UPGRADE
     */
} BpfhvProxyMsgPayload;

typedef struct BpfhvProxyMsgHeader {
    BpfhvProxyReqType       reqtype;
    uint32_t                flags;
#define BPFHV_PROXY_VERSION             1
#define BPFHV_PROXY_F_VERSION_MASK      0x7
#define BPFHV_PROXY_F_ERROR             0x8
    uint32_t                size;
} BpfhvProxyMsgHeader;

typedef struct BpfhvProxyMessage {
    BpfhvProxyMsgHeader     hdr;
    BpfhvProxyMsgPayload    payload;
} __attribute__((packed)) BpfhvProxyMessage;

#ifdef __cplusplus
}
#endif

#endif  /* __BPFHV_PROXY_H__ */
