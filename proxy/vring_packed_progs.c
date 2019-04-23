#include "bpfhv.h"
#include "vring_packed.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

static int BPFHV_FUNC(rx_pkt_alloc, struct bpfhv_rx_context *ctx);
static int BPFHV_FUNC(smp_mb_full);

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");
#define smp_mb_release()    compiler_barrier()
#define smp_mb_acquire()    compiler_barrier()

static inline void
vring_packed_add(struct vring_packed_virtq *vq, struct bpfhv_buf *b,
                 uint16_t flags)
{
    struct vring_packed_desc_state *state = vring_packed_state(vq);
    uint16_t head_avail_idx;
    uint16_t head_flags;
    uint16_t avail_idx;
    uint16_t state_idx;
    uint16_t id;

    head_avail_idx = avail_idx = vq->g.next_avail_idx;
    head_flags = vq->g.avail_used_flags | flags;
    id = state_idx = vq->g.next_free_id;

    vq->desc[avail_idx].addr = b->paddr;
    vq->desc[avail_idx].len = b->len;
    vq->desc[avail_idx].id = id;
    state[state_idx].cookie = b->cookie;

    if (++avail_idx >= vq->num_desc) {
        avail_idx = 0;
        vq->g.avail_used_flags ^= 1 << VRING_PACKED_DESC_F_AVAIL |
                                1 << VRING_PACKED_DESC_F_USED;
        vq->g.avail_wrap_counter ^= 1;
    }

    vq->g.next_avail_idx = avail_idx;
    vq->g.next_free_id = state[id].next;
    state[id].busy = 1;
#if 0
    state[id].num = 1;
    state[id].last = id;
#endif

    /* Publish the new descriptor chain by exposing the flags of the first
     * descriptor in the chain. */
    smp_mb_release();
    vq->desc[head_avail_idx].flags = head_flags;
}

/* Check if the hypervisor needs a notification. */
static inline int
vring_packed_kick_needed(struct vring_packed_virtq *vq)
{
    /* TODO implement EVENT_IDX */
    union {
        struct {
            uint16_t off_wrap;
            uint16_t flags;
        };
        uint32_t u32;
    } device_event;

    smp_mb_full();
    device_event.u32 = *((uint32_t *)(&vq->device_event));

    return (device_event.flags == VRING_PACKED_EVENT_FLAG_ENABLE);
}

__section("txp")
int vring_packed_txp(struct bpfhv_tx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    struct bpfhv_buf *txb = ctx->bufs + 0;

    if (ctx->num_bufs != 1) {
        return -1;
    }

    vring_packed_add(vq, txb, 0);
    ctx->oflags = vring_packed_kick_needed(vq) ? BPFHV_OFLAGS_KICK_NEEDED : 0;

    return 0;
}

static inline int
vring_packed_more_used(struct vring_packed_virtq *vq)
{
    uint16_t flags = vq->desc[vq->g.next_used_idx].flags;
    int avail, used;

    avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
    used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));

    smp_mb_acquire();

    return avail == used && used == vq->g.used_wrap_counter;
}

static inline int
vring_packed_more_pending(struct vring_packed_virtq *vq)
{
    uint16_t flags = vq->desc[vq->g.next_used_idx].flags;
    int avail, used;

    avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
    used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));

    smp_mb_acquire();

    return avail != used && used != vq->g.used_wrap_counter;
}

static inline int
vring_packed_get(struct vring_packed_virtq *vq, struct bpfhv_buf *txb)
{
    struct vring_packed_desc_state *state = vring_packed_state(vq);
    uint16_t used_idx;
    uint16_t id;

    used_idx = vq->g.next_used_idx;
    id = vq->desc[used_idx].id;
    if (id >= vq->num_desc || !state[id].busy) {
        return -1;  /* This is a bug. */
    }

    txb->cookie = state[id].cookie;
    txb->paddr = vq->desc[used_idx].addr;
    txb->len = vq->desc[used_idx].len;

    state[id].busy = 0;
    state[id].next = vq->g.next_free_id;
    vq->g.next_free_id = id;

    if (++used_idx >= vq->num_desc) {
        used_idx = 0;
        vq->g.used_wrap_counter ^= 1;
    }
    vq->g.next_used_idx = used_idx;

    return 0;
}

__section("txc")
int vring_packed_txc(struct bpfhv_tx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    struct bpfhv_buf *txb = ctx->bufs + 0;
    int ret;

    if (!vring_packed_more_used(vq)) {
        return 0;
    }

    ret = vring_packed_get(vq, txb);
    if (ret == 0) {
        ctx->num_bufs = 1;
        ctx->oflags = 0;
    }

    return ret;
}

__section("txr")
int sring_txr(struct bpfhv_tx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    struct bpfhv_buf *txb = ctx->bufs + 0;
    int ret;

    if (!vring_packed_more_pending(vq)) {
        return 0;
    }

    ret = vring_packed_get(vq, txb);
    if (ret == 0) {
        ctx->num_bufs = 1;
        ctx->oflags = 0;
    }

    return ret;
}

__section("txi")
int sring_txi(struct bpfhv_tx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;

    if (ctx->min_completed_bufs == 0) {
        vq->driver_event.flags = VRING_PACKED_EVENT_FLAG_DISABLE;
        return 0;
    }
    vq->driver_event.flags = VRING_PACKED_EVENT_FLAG_ENABLE;
    smp_mb_full();

    return vring_packed_more_used(vq);
}

__section("rxp")
int sring_rxp(struct bpfhv_rx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    unsigned int i;

    if (ctx->num_bufs > BPFHV_MAX_RX_BUFS) {
        return -1;
    }

    for (i = 0; i < ctx->num_bufs; i++) {
        struct bpfhv_buf *rxb = ctx->bufs + i;

        vring_packed_add(vq, rxb, VRING_DESC_F_WRITE);

    }
    ctx->oflags = vring_packed_kick_needed(vq) ? BPFHV_OFLAGS_KICK_NEEDED : 0;

    return 0;
}

__section("rxc")
int sring_rxc(struct bpfhv_rx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    struct bpfhv_buf *rxb = ctx->bufs + 0;
    int ret;

    if (!vring_packed_more_used(vq)) {
        return 0;
    }

    ret = vring_packed_get(vq, rxb);
    if (ret == 0) {
        ctx->num_bufs = 1;
        ctx->oflags = 0;

        ret = rx_pkt_alloc(ctx);
        if (ret < 0) {
            return ret;
        }
    }

    return ret;
}

__section("rxr")
int sring_rxr(struct bpfhv_rx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;
    unsigned int i;

    if (!vring_packed_more_pending(vq)) {
        return 0;
    }

    for (i = 0; i < BPFHV_MAX_RX_BUFS; i++) {
        struct bpfhv_buf *rxb = ctx->bufs + i;
        int ret;

        ret = vring_packed_get(vq, rxb);
        if (ret) {
            if (i == 0) {
                return ret;
            }
            break;
        }

        if (!vring_packed_more_pending(vq)) {
            break;
        }
    }

    ctx->num_bufs = i;
    ctx->oflags = 0;

    return 1;
}

__section("rxi")
int sring_rxi(struct bpfhv_rx_context *ctx)
{
    struct vring_packed_virtq *vq = (struct vring_packed_virtq *)ctx->opaque;

    if (ctx->min_completed_bufs == 0) {
        vq->driver_event.flags = VRING_PACKED_EVENT_FLAG_DISABLE;
        return 0;
    }
    vq->driver_event.flags = VRING_PACKED_EVENT_FLAG_ENABLE;
    smp_mb_full();

    return vring_packed_more_used(vq);
}
