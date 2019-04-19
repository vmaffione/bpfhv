#include <stdlib.h>
#include <assert.h>

#include "backend.h"
#include "vring_packed.h"

static void
vring_packed_rxq_check_alignment(void)
{
    struct vring_packed_virtq *vq = NULL;

    assert(((uintptr_t)&vq->next_free_id) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->driver_event) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->device_event) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->desc[0]) % MY_CACHELINE_SIZE == 0);
}

static void
vring_packed_txq_check_alignment(void)
{
}

BeOps vring_packed_ops = {
/*
    .rx_ctx_size = vring_packed_rx_ctx_size,
    .tx_ctx_size = vring_packed_tx_ctx_size,
    .rx_ctx_init = vring_packed_rx_ctx_init,
    .tx_ctx_init = vring_packed_tx_ctx_init,
    .rxq_push = vring_packed_rxq_push,
    .txq_drain = vring_packed_txq_drain,
    .rxq_kicks = vring_packed_rxq_notification,
    .txq_kicks = vring_packed_txq_notification,
    .txq_pending = vring_packed_txq_pending,
    .rxq_dump = vring_packed_rxq_dump,
    .txq_dump = vring_packed_txq_dump,
*/
    .rxq_check_alignment = vring_packed_rxq_check_alignment,
    .txq_check_alignment = vring_packed_txq_check_alignment,
    .progfile = "proxy/vring_packed_progs.o",
};
