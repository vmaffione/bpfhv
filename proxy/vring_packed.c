#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "backend.h"
#include "vring_packed.h"

static void
vring_packed_rx_check_alignment(void)
{
    struct vring_packed_virtq *vq = NULL;

    assert(((uintptr_t)&vq->g.next_free_id) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->state_ofs) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->driver_event) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->device_event) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&vq->desc[0]) % MY_CACHELINE_SIZE == 0);
}

static void
vring_packed_tx_check_alignment(void)
{
    vring_packed_rx_check_alignment();
}

static size_t
vring_packed_rx_ctx_size(size_t num_rx_bufs)
{
    size_t desc_size = ROUNDUP(sizeof(struct vring_packed_desc) * num_rx_bufs,
                               MY_CACHELINE_SIZE);
    size_t state_size = ROUNDUP(
                    sizeof(struct vring_packed_desc_state) * num_rx_bufs,
                    MY_CACHELINE_SIZE);

    return sizeof(struct vring_packed_virtq) + desc_size + state_size;
}

static size_t
vring_packed_tx_ctx_size(size_t num_tx_bufs)
{
    return vring_packed_rx_ctx_size(num_tx_bufs);
}

static void
vring_packed_init(struct vring_packed_virtq *vq, size_t num)
{
    size_t desc_size = ROUNDUP(sizeof(struct vring_packed_desc) * num,
                               MY_CACHELINE_SIZE);
    struct vring_packed_desc_state *state;
    unsigned int i;

    memset(vq, 0, vring_packed_rx_ctx_size(num));

    vq->g.next_free_id = 0;
    vq->g.next_avail_idx = 0;
    vq->g.next_used_idx = 0;
    vq->g.avail_wrap_counter = 1;
    vq->g.used_wrap_counter = 1;
    vq->g.avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;

    vq->h.next_avail_idx = 0;
    vq->h.next_used_idx = 0;
    vq->h.avail_wrap_counter = 1;
    vq->h.used_wrap_counter = 1;

    vq->state_ofs = sizeof(struct vring_packed_virtq) + desc_size;
    vq->num_desc = num;

    vq->driver_event.flags = VRING_PACKED_EVENT_FLAG_ENABLE;
    vq->driver_event.off_wrap = 0;
    vq->device_event.flags = VRING_PACKED_EVENT_FLAG_ENABLE;
    vq->device_event.off_wrap = 0;

    state = vring_packed_state(vq);
    for (i = 0; i < num-1; i++) {
        state[i].next = i + 1;
        state[i].busy = 0;
    }
}

static void
vring_packed_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;

    vring_packed_init(vq, num_rx_bufs);
}

static void
vring_packed_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;

    vring_packed_init(vq, num_tx_bufs);
}

BeOps vring_packed_ops = {
    .rx_check_alignment = vring_packed_rx_check_alignment,
    .tx_check_alignment = vring_packed_tx_check_alignment,
    .rx_ctx_size = vring_packed_rx_ctx_size,
    .tx_ctx_size = vring_packed_tx_ctx_size,
    .rx_ctx_init = vring_packed_rx_ctx_init,
    .tx_ctx_init = vring_packed_tx_ctx_init,
/*
    .rxq_push = vring_packed_rxq_push,
    .txq_drain = vring_packed_txq_drain,
    .rxq_kicks = vring_packed_rxq_notification,
    .txq_kicks = vring_packed_txq_notification,
    .rxq_dump = vring_packed_rxq_dump,
    .txq_dump = vring_packed_txq_dump,
*/
    .progfile = "proxy/vring_packed_progs.o",
};
