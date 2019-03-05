#include "bpfhv.h"
#include "sring.h"

#define WITH_GSO

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");

#if defined(WITH_CSUM) || defined(WITH_GSO)
/* Imported from Linux (include/uapi/linux/virtio_net.h). */
struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1       /* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID     2       /* Csum is valid */
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE         0       /* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4        1       /* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP          3       /* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6        4       /* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN          0x80    /* TCP has ECN set */
    uint8_t gso_type;
    uint16_t hdr_len;             /* Ethernet + IP + tcp/udp hdrs */
    uint16_t gso_size;            /* Bytes to append to hdr_len per frame */
    uint16_t csum_start;  /* Position to start checksumming from */
    uint16_t csum_offset; /* Offset after that to place checksum */
};
#endif

static int BPFHV_FUNC(rx_pkt_alloc, struct bpfhv_rx_context *ctx);
#ifdef WITH_CSUM
static int BPFHV_FUNC(pkt_l4_csum_md_get, struct bpfhv_tx_context *ctx,
                      uint16_t *csum_start, uint16_t *csum_offset);
static int BPFHV_FUNC(pkt_l4_csum_md_set, struct bpfhv_rx_context *ctx,
                      uint16_t csum_start, uint16_t csum_offset);
#endif
#ifdef WITH_GSO
static int BPFHV_FUNC(pkt_virtio_net_md_get, struct bpfhv_tx_context *ctx,
                      struct virtio_net_hdr *hdr);
static int BPFHV_FUNC(pkt_virtio_net_md_set, struct bpfhv_rx_context *ctx,
                      const struct virtio_net_hdr *hdr);
#endif

__section("txp")
int sring_txp(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t prod = priv->prod;
    struct sring_tx_desc *txd;
    uint32_t i;

    if (ctx->num_bufs > BPFHV_MAX_TX_BUFS) {
        return -1;
    }

    for (i = 0; i < ctx->num_bufs; i++, prod++) {
        struct bpfhv_tx_buf *txb = ctx->bufs + i;

        txd = priv->desc + (prod & priv->qmask);
        txd->cookie = txb->cookie;
        txd->paddr = txb->paddr;
        txd->len = txb->len;
        txd->flags = 0;
    }
    txd->flags = SRING_DESC_F_EOP;
#ifdef WITH_GSO
    {
        struct virtio_net_hdr hdr;

        pkt_virtio_net_md_get(ctx, &hdr);
        txd->csum_start = hdr.csum_start;
        txd->csum_offset = hdr.csum_offset;
        txd->hdr_len = hdr.hdr_len;
        txd->gso_size = hdr.gso_size;
        txd->gso_type = hdr.gso_type;
        if (hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            txd->flags |= SRING_DESC_F_NEEDS_CSUM;
        }
    }
#elif defined(WITH_CSUM)
    if (pkt_l4_csum_md_get(ctx, &txd->csum_start, &txd->csum_offset)) {
        txd->flags |= SRING_DESC_F_NEEDS_CSUM;
    }
#endif
    compiler_barrier();
    ACCESS_ONCE(priv->prod) = prod;
    compiler_barrier();
    ctx->oflags = ACCESS_ONCE(priv->kick_enabled) ?
                  BPFHV_OFLAGS_NOTIF_NEEDED : 0;

    return 0;
}

static inline uint32_t
sring_tx_get_one(struct bpfhv_tx_context *ctx,
                 struct sring_tx_context *priv, uint32_t start)
{
    uint32_t i;

    for (i = 0; i < BPFHV_MAX_TX_BUFS; ) {
        struct bpfhv_tx_buf *txb = ctx->bufs + i;
        struct sring_tx_desc *txd;

        txd = priv->desc + (start & priv->qmask);
        start++;
        i++;
        txb->paddr = txd->paddr;
        txb->len = txd->len;
        txb->cookie = txd->cookie;
        if (txd->flags & SRING_DESC_F_EOP) {
            break;
        }
    }

    ctx->num_bufs = i;

    return start;
}

__section("txc")
int sring_txc(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t clear = priv->clear;
    uint32_t cons = ACCESS_ONCE(priv->cons);

    if (clear == cons) {
        return 0;
    }
    compiler_barrier();

    priv->clear = sring_tx_get_one(ctx, priv, clear);
    ctx->oflags = 0;

    return 1;
}

__section("txr")
int sring_txr(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t cons = ACCESS_ONCE(priv->cons);
    uint32_t prod = priv->prod;

    if (cons == prod) {
        return 0;
    }
    compiler_barrier();

    ACCESS_ONCE(priv->cons) = priv->clear = sring_tx_get_one(ctx, priv, cons);
    ctx->oflags = 0;

    return 1;
}

__section("txi")
int sring_txi(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t ncompl;
    uint32_t cons;

    cons = ACCESS_ONCE(priv->cons);
    ncompl = cons - priv->clear;

    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }
    ACCESS_ONCE(priv->intr_enabled) = 1;
    compiler_barrier();
    ncompl += ACCESS_ONCE(priv->cons) - cons;
    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }

    return 0;
}

__section("rxp")
int sring_rxp(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t prod = priv->prod;
    struct sring_rx_desc *rxd;
    uint32_t i;

    if (ctx->num_bufs > BPFHV_MAX_RX_BUFS) {
        return -1;
    }

    for (i = 0; i < ctx->num_bufs; i++, prod++) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;

        rxd = priv->desc + (prod & priv->qmask);
        rxd->cookie = rxb->cookie;
        rxd->paddr = rxb->paddr;
        rxd->len = rxb->len;
        rxd->flags = 0;
    }
    compiler_barrier();
    ACCESS_ONCE(priv->prod) = prod;
    compiler_barrier();
    ctx->oflags = ACCESS_ONCE(priv->kick_enabled) ?
                  BPFHV_OFLAGS_NOTIF_NEEDED : 0;

    return 0;
}

__section("rxc")
int sring_rxc(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t clear = priv->clear;
    uint32_t cons = ACCESS_ONCE(priv->cons);
    struct sring_rx_desc *rxd;
    uint32_t i;
    int ret;

    if (clear == cons) {
        return 0;
    }
    compiler_barrier();

    /* Prepare the input arguments for rx_pkt_alloc(). */
    for (i = 0; clear != cons && i < BPFHV_MAX_RX_BUFS;) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;

        rxd = priv->desc + (clear & priv->qmask);
        clear++;
        i++;
        rxb->cookie = rxd->cookie;
        rxb->paddr = rxd->paddr;
        rxb->len = rxd->len;

        if (rxd->flags & SRING_DESC_F_EOP) {
            break;
        }
    }

    priv->clear = clear;
    ctx->num_bufs = i;

    ret = rx_pkt_alloc(ctx);
    if (ret < 0) {
        return ret;
    }

#ifdef WITH_GSO
    {
        struct virtio_net_hdr hdr;

        hdr.flags = (rxd->flags & SRING_DESC_F_NEEDS_CSUM) ?
                    VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
        hdr.csum_start = rxd->csum_start;
        hdr.csum_offset = rxd->csum_offset;
        hdr.hdr_len = rxd->hdr_len;
        hdr.gso_size = rxd->gso_size;
        hdr.gso_type = rxd->gso_type;
        pkt_virtio_net_md_set(ctx, &hdr);
    }
#elif defined(WITH_CSUM)
    if (rxd->flags & SRING_DESC_F_NEEDS_CSUM) {
        pkt_l4_csum_md_set(ctx, rxd->csum_start, rxd->csum_offset);
    }
#endif

    /* Now ctx->packet contains the allocated OS packet. Return 1 to tell
     * the driver that ctx->packet is valid. Also set ctx->oflags to tell
     * the driver whether rescheduling is necessary. */
    ctx->oflags = 0;

    return 1;
}

__section("rxr")
int sring_rxr(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t cons = ACCESS_ONCE(priv->cons);
    uint32_t prod = priv->prod;
    uint32_t i = 0;

    if (cons == prod) {
        return 0;
    }
    compiler_barrier();

    for (; cons != prod && i < BPFHV_MAX_RX_BUFS; i++) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;
        struct sring_rx_desc *rxd;

        rxd = priv->desc + (cons & priv->qmask);
        cons++;
        rxb->cookie = rxd->cookie;
        rxb->paddr = rxd->paddr;
        rxb->len = rxd->len;
    }

    ACCESS_ONCE(priv->cons) = priv->clear = cons;
    ctx->num_bufs = i;
    ctx->oflags = 0;

    return 1;
}

__section("rxi")
int sring_rxi(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t ncompl;
    uint32_t cons;

    cons = ACCESS_ONCE(priv->cons);
    ncompl = cons - priv->clear;

    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }
    ACCESS_ONCE(priv->intr_enabled) = 1;
    compiler_barrier();
    ncompl += ACCESS_ONCE(priv->cons) - cons;
    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }

    return 0;
}
