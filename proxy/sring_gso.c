#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/uio.h>

#include "backend.h"
#include "sring_gso.h"

#define MY_CACHELINE_SIZE   64

static void
sring_gso_rx_check_alignment(void)
{
    struct sring_gso_rx_context *priv = NULL;

    assert(((uintptr_t)&priv->prod) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->cons) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->qmask) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->clear) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->desc[0]) % MY_CACHELINE_SIZE == 0);
}

static void
sring_gso_tx_check_alignment(void)
{
    struct sring_gso_tx_context *priv = NULL;

    assert(((uintptr_t)&priv->prod) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->cons) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->qmask) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->clear) % MY_CACHELINE_SIZE == 0);
    assert(((uintptr_t)&priv->desc[0]) % MY_CACHELINE_SIZE == 0);
}

static size_t
sring_gso_rx_ctx_size(size_t num_rx_bufs)
{
    return sizeof(struct bpfhv_rx_context) + sizeof(struct sring_gso_rx_context) +
	num_rx_bufs * sizeof(struct sring_gso_rx_desc);
}

static size_t
sring_gso_tx_ctx_size(size_t num_tx_bufs)
{
    return sizeof(struct bpfhv_tx_context) + sizeof(struct sring_gso_tx_context) +
	num_tx_bufs * sizeof(struct sring_gso_tx_desc);
}

static void
sring_gso_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
    struct sring_gso_rx_context *priv = (struct sring_gso_rx_context *)ctx->opaque;

    assert((num_rx_bufs & (num_rx_bufs - 1)) == 0);
    priv->qmask = num_rx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_rx_bufs * sizeof(priv->desc[0]));
}

static void
sring_gso_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct sring_gso_tx_context *priv = (struct sring_gso_tx_context *)ctx->opaque;

    assert((num_tx_bufs & (num_tx_bufs - 1)) == 0);
    priv->qmask = num_tx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = 1;
    priv->intr_at = 0;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}

static inline void
__sring_rxq_notification(struct sring_gso_rx_context *priv, int enable)
{
    priv->kick_enabled = !!enable;
}

static void
sring_gso_rxq_notification(struct bpfhv_rx_context *ctx, int enable)
{
    struct sring_gso_rx_context *priv = (struct sring_gso_rx_context *)ctx->opaque;

    __sring_rxq_notification(priv, enable);
}

static inline void
__sring_gso_txq_notification(struct sring_gso_tx_context *priv, int enable)
{
    priv->kick_enabled = !!enable;
}

static void
sring_gso_txq_notification(struct bpfhv_tx_context *ctx, int enable)
{
    struct sring_gso_tx_context *priv = (struct sring_gso_tx_context *)ctx->opaque;

    __sring_gso_txq_notification(priv, enable);
}

static void
sring_gso_rxq_dump(struct bpfhv_rx_context *ctx)
{
    struct sring_gso_rx_context *priv = (struct sring_gso_rx_context *)ctx->opaque;

    printf("sring.rxq cl %u co %u pr %u kick %u intr %u\n",
           ACCESS_ONCE(priv->clear), ACCESS_ONCE(priv->cons),
           ACCESS_ONCE(priv->prod), ACCESS_ONCE(priv->kick_enabled),
           ACCESS_ONCE(priv->intr_enabled));
}

static void
sring_gso_txq_dump(struct bpfhv_tx_context *ctx)
{
    struct sring_gso_tx_context *priv = (struct sring_gso_tx_context *)ctx->opaque;

    printf("sring.txq cl %u co %u pr %u kick %u intr_at %u\n",
           ACCESS_ONCE(priv->clear), ACCESS_ONCE(priv->cons),
           ACCESS_ONCE(priv->prod), ACCESS_ONCE(priv->kick_enabled),
           ACCESS_ONCE(priv->intr_at));
}

static size_t
sring_gso_rxq_push(BpfhvBackend *be, BpfhvBackendQueue *rxq,
                   int *can_receive)
{
    struct bpfhv_rx_context *ctx = rxq->ctx.rx;
    struct sring_gso_rx_context *priv = (struct sring_gso_rx_context *)ctx->opaque;
    size_t max_pkt_size = be->max_rx_pkt_size;
    int vnet_hdr_len = be->vnet_hdr_len;
    uint32_t prod = ACCESS_ONCE(priv->prod);
    uint32_t cons = priv->cons;
    struct iovec iov[BPFHV_MAX_RX_BUFS+1];
    int count = 0;

    /* Make sure the load of from priv->prod is not delayed after the
     * loads from the ring. */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    rxq->notify = 0;

    if (unlikely(priv->kick_enabled)) {
        __sring_rxq_notification(priv, /*enable=*/0);
    }

    for (;;) {
        struct virtio_net_hdr_v1 hdr;
        uint32_t cons_first = cons;
        struct sring_gso_rx_desc *rxd;
        size_t iovsize = 0;
        int iovcnt = 0;
        int pktsize;

        /* Collect enough receive descriptors to make room for a maximum
         * sized packet, plus virtio-net header, if needed. */
        if (vnet_hdr_len != 0) {
            iov[0].iov_base = &hdr;
            iov[0].iov_len = sizeof(hdr);
            iovcnt = 1;
        }
        do {
            if (unlikely(cons == prod)) {
                /* We ran out of RX descriptors. In busy-wait mode we can just
                 * bail out. Otherwise we enable RX kicks and double check for
                 * more available descriptors. */
                if (can_receive == NULL) {
                    cons = cons_first;
                    goto out;
                }
                __sring_rxq_notification(priv, /*enable=*/1);
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                prod = ACCESS_ONCE(priv->prod);
                if (cons == prod) {
                    /* Not enough space. We need to rewind to the first unused
                     * descriptor and stop. */
                    cons = cons_first;
                    *can_receive = 0;
                    goto out;
                }
                __sring_rxq_notification(priv, /*enable=*/0);
                /* Make sure the load of from priv->prod is not delayed after the
                 * loads from the ring. */
                __atomic_thread_fence(__ATOMIC_ACQUIRE);
            }

            rxd = priv->desc + (cons & priv->qmask);
            iov[iovcnt].iov_base = translate_addr(be, rxd->paddr, rxd->len);
            if (unlikely(iov[iovcnt].iov_base == NULL)) {
                /* Invalid descriptor. */
                rxd->len = 0;
                rxd->flags = 0;
                if (verbose) {
                    fprintf(stderr, "Invalid RX descriptor: gpa%"PRIx64", "
                                    "len %u\n", rxd->paddr, rxd->len);
                }
            } else {
                iov[iovcnt].iov_len = rxd->len;
                iovsize += rxd->len;
                iovcnt++;
            }
            cons++;
        } while (iovsize < max_pkt_size && iovcnt < BPFHV_MAX_RX_BUFS);

        if (unlikely(count >= BPFHV_BE_RX_BUDGET)) {
            break;
        }

        /* Read into the scatter-gather buffer referenced by the collected
         * descriptors. */
        pktsize = be->recv(be, iov, iovcnt);
        if (pktsize <= 0) {
            /* No more data to read (or error). We need to rewind to the
             * first unused descriptor and stop. */
            cons = cons_first;
            if (unlikely(pktsize < 0 && errno != EAGAIN)) {
                fprintf(stderr, "recv() failed: %s\n", strerror(errno));
            }
            break;
        }
#if 0
        printf("Received %d bytes\n", ret);
#endif

        /* Write back to the receive descriptors effectively used. */
        pktsize -= vnet_hdr_len;
        for (cons = cons_first; pktsize > 0; cons++) {
            rxd = priv->desc + (cons & priv->qmask);

            if (unlikely(rxd->len == 0)) {
                /* This was an invalid descriptor. */
                continue;
            }

            rxd->flags = 0;
            rxd->len = (rxd->len <= pktsize) ? rxd->len : pktsize;
            pktsize -= rxd->len;
        }
        /* Complete the last descriptor. */
        rxd->flags = SRING_DESC_F_EOP;
        if (vnet_hdr_len != 0) {
#if 0
            printf("rx hdr: {fl %x, cs %u, co %u, hl %u, gs %u, "
                    "gt %u}\n",
                    hdr.flags, hdr.csum_start, hdr.csum_offset,
                    hdr.hdr_len, hdr.gso_size, hdr.gso_type);
#endif
            rxd->csum_start = hdr.csum_start;
            rxd->csum_offset = hdr.csum_offset;
            rxd->hdr_len = hdr.hdr_len;
            rxd->gso_size = hdr.gso_size;
            rxd->gso_type = hdr.gso_type;
            if (hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
                rxd->flags |= SRING_DESC_F_NEEDS_CSUM;
            }
        }
        rxq->stats.bufs += cons - cons_first;
        count++;
    }

out:
    if (count > 0) {
        /* Barrier between store(sring entries) and store(priv->cons). */
        __atomic_thread_fence(__ATOMIC_RELEASE);
        priv->cons = cons;
        /* Full memory barrier to ensure store(priv->cons) happens before
         * load(priv->intr_enabled). See the double-check in sring_gso_rxi().*/
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        rxq->notify = ACCESS_ONCE(priv->intr_enabled);
        rxq->stats.pkts += count;
        rxq->stats.batches++;
    }

    return count;
}

static size_t
sring_gso_txq_drain(BpfhvBackend *be, BpfhvBackendQueue *txq, int *can_send)
{
    struct bpfhv_tx_context *ctx = txq->ctx.tx;
    struct sring_gso_tx_context *priv = (struct sring_gso_tx_context *)ctx->opaque;
    struct iovec iov[BPFHV_MAX_TX_BUFS+1];
    uint32_t prod = ACCESS_ONCE(priv->prod);
    int vnet_hdr_len = be->vnet_hdr_len;
    uint32_t cons = priv->cons;
    uint32_t cons_first = cons;
    int iovcnt_start = vnet_hdr_len != 0 ? 1 : 0;
    int iovcnt = iovcnt_start;
    int count = 0;

    if (can_send) {
        /* Disable further kicks and start processing. */
        __sring_gso_txq_notification(priv, /*enable=*/0);
    }

    /* Make sure the load of from priv->prod is not delayed after the
     * loads from the ring. */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    txq->notify = 0;

    for (;;) {
        struct sring_gso_tx_desc *txd = priv->desc + (cons & priv->qmask);

        if (unlikely(cons == prod)) {
            /* Before stopping, check if more work came while we were
             * not looking at priv->prod. */
            prod = ACCESS_ONCE(priv->prod);
            if (cons == prod) {
                /* We ran out of TX descriptors. In busy-wait mode we can just
                 * bail out. Otherwise we enable TX kicks and double check for
                 * more available descriptors. */
                if (can_send == NULL) {
                    break;
                }
                /* Re-enable notifications and double check for
                 * more work. */
                __sring_gso_txq_notification(priv, /*enable=*/1);
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                prod = ACCESS_ONCE(priv->prod);
                if (cons == prod) {
                    break;
                }
                /* More work found: keep going. */
                __sring_gso_txq_notification(priv, /*enable=*/0);
            }
            /* Make sure the load of from priv->prod is not delayed after the
             * loads from the ring. */
            __atomic_thread_fence(__ATOMIC_ACQUIRE);
        }

        if (unlikely(count >= BPFHV_BE_TX_BUDGET)) {
            break;
        }

        cons++;

        iov[iovcnt].iov_base = translate_addr(be, txd->paddr, txd->len);
        iov[iovcnt].iov_len = txd->len;
        if (unlikely(iov[iovcnt].iov_base == NULL)) {
            /* Invalid descriptor, just skip it. */
            if (verbose) {
                fprintf(stderr, "Invalid TX descriptor: gpa%"PRIx64", "
                                "len %u\n", txd->paddr, txd->len);
            }
        } else {
            iovcnt++;
        }

        if (txd->flags & SRING_DESC_F_EOP) {
            struct virtio_net_hdr_v1 hdr;
            int ret;

            if (vnet_hdr_len != 0) {
                hdr.flags = (txd->flags & SRING_DESC_F_NEEDS_CSUM) ?
                    VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
                hdr.csum_start = txd->csum_start;
                hdr.csum_offset = txd->csum_offset;
                hdr.hdr_len = txd->hdr_len;
                hdr.gso_size = txd->gso_size;
                hdr.gso_type = txd->gso_type;
                hdr.num_buffers = 0;
#if 0
                printf("tx hdr: {fl %x, cs %u, co %u, hl %u, gs %u, gt %u}\n",
                        hdr.flags, hdr.csum_start, hdr.csum_offset,
                        hdr.hdr_len, hdr.gso_size, hdr.gso_type);
#endif
                iov[0].iov_base = &hdr;
                iov[0].iov_len = sizeof(hdr);
            }

            ret = be->send(be, iov, iovcnt);
            if (unlikely(ret <= 0)) {
                /* Backend is blocked (or failed), so we need to stop.
                 * The last packet was not transmitted, so we need to
                 * rewind 'cons'. */
                if (ret < 0) {
                    if (can_send != NULL && errno == EAGAIN) {
                        *can_send = 0;
                    } else if (verbose) {
                        fprintf(stderr, "send() failed: %s\n",
                                strerror(errno));
                    }
                }
                cons = cons_first;
                break;
            }
#if 0
            printf("Transmitted iovcnt %u --> %d\n", iovcnt, ret);
#endif
            txq->stats.bufs += cons - cons_first;
            count++;

            iovcnt = iovcnt_start;
            cons_first = cons;
        }
    }

    if (count > 0) {
        uint32_t old_cons = priv->cons;
        uint32_t intr_at;

        /* Barrier between stores to sring entries and store to priv->cons. */
        __atomic_thread_fence(__ATOMIC_RELEASE);
        priv->cons = cons;
        /* Full memory barrier to ensure store(priv->cons) happens before
         * load(priv->intr_at). See the double-check in sring_gso_txi(). */
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        intr_at = ACCESS_ONCE(priv->intr_at);
        txq->notify =
            (uint32_t)(cons - intr_at - 1) < (uint32_t)(cons - old_cons);
        txq->stats.pkts += count;
        txq->stats.batches++;
    }

    return count;
}

BeOps sring_gso_ops = {
    .rx_check_alignment = sring_gso_rx_check_alignment,
    .tx_check_alignment = sring_gso_tx_check_alignment,
    .rx_ctx_size = sring_gso_rx_ctx_size,
    .tx_ctx_size = sring_gso_tx_ctx_size,
    .rx_ctx_init = sring_gso_rx_ctx_init,
    .tx_ctx_init = sring_gso_tx_ctx_init,
    .rxq_push = sring_gso_rxq_push,
    .txq_drain = sring_gso_txq_drain,
    .rxq_kicks = sring_gso_rxq_notification,
    .txq_kicks = sring_gso_txq_notification,
    .rxq_dump = sring_gso_rxq_dump,
    .txq_dump = sring_gso_txq_dump,
    .progfile = "proxy/sring_gso_progs.o",
};
