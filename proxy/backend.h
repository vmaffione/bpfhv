#ifndef __BACKEND_H__
#define __BACKEND_H__

#include "bpfhv-proxy.h"
#include "bpfhv.h"

#ifndef likely
#define likely(x)           __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x)         __builtin_expect((x), 0)
#endif
#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif
#define compiler_barrier() __asm__ __volatile__ ("");

#define ROUNDUP(sz, one) ((((sz) + (one) - 1) / (one)) * (one))

#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define BPFHV_MAX_QUEUES        16

typedef struct BpfhvBackendMemoryRegion {
    uint64_t    gpa_start;
    uint64_t    gpa_end;
    uint64_t    size;
    uint64_t    hv_vaddr;
    uint64_t    mmap_offset;
    void        *mmap_addr;
    void        *va_start;
} BpfhvBackendMemoryRegion;

typedef struct BpfhvBackendQueueStats {
    uint64_t    bufs;
    uint64_t    pkts;
    uint64_t    batches;
    uint64_t    kicks;
    uint64_t    irqs;
} BpfhvBackendQueueStats;

typedef struct BpfhvBackendQueue {
    union {
        struct bpfhv_rx_context *rx;
        struct bpfhv_tx_context *tx;
    } ctx;
    int kickfd;
    int irqfd;
    int notify;
    BpfhvBackendQueueStats stats;
    BpfhvBackendQueueStats pstats;
    struct iovec *iov;
    char name[8];
} BpfhvBackendQueue;

struct BpfhvBackend;

typedef ssize_t (*BeSendFun)(struct BpfhvBackend *be, const struct iovec *iov,
                             size_t iovcnt);
typedef ssize_t (*BeRecvFun)(struct BpfhvBackend *be, const struct iovec *iov,
                             size_t iovcnt);
typedef void (*BeSyncFun)(struct BpfhvBackend *be);

typedef struct BeOps {
    void (*rx_check_alignment)(void);
    void (*tx_check_alignment)(void);
    size_t (*rx_ctx_size)(size_t num_rx_bufs);
    size_t (*tx_ctx_size)(size_t num_rx_bufs);
    void (*rx_ctx_init)(struct bpfhv_rx_context *ctx, size_t num_rx_bufs);
    void (*tx_ctx_init)(struct bpfhv_tx_context *ctx, size_t num_tx_bufs);
    size_t (*rxq_push)(struct BpfhvBackend *be,
                      BpfhvBackendQueue *rxq, int *can_receive);
    size_t (*txq_drain)(struct BpfhvBackend *be,
                       BpfhvBackendQueue *txq, int *can_send);
    void (*rxq_kicks)(struct bpfhv_rx_context *ctx, int enable);
    void (*txq_kicks)(struct bpfhv_tx_context *ctx, int enable);
    int (*txq_pending)(struct bpfhv_tx_context *ctx);
    void (*rxq_dump)(struct bpfhv_rx_context *ctx);
    void (*txq_dump)(struct bpfhv_tx_context *ctx);

    /* Path of the object file containing the ebpf programs. */
    char *progfile;
} BeOps;

/* Main data structure supporting a single bpfhv vNIC. */
typedef struct BpfhvBackend {
    /* A file containing the PID of this process. */
    const char *pidfile;

    /* Socket file descriptor to exchange control message with the
     * hypervisor. */
    int cfd;

    /* Backend type (tap, netmap). */
    const char *backend;

    /* Functions that process receive and transmit queues. */
    BeOps ops;

    /* Set to 1 if we are collecting run-time statistics,
     * and timestamp useful to compute statistics. */
    int collect_stats;
    struct timeval stats_ts;

    /* The features we support. */
    uint64_t features_avail;

    /* The features selected by the guest. */
    uint64_t features_sel;

    /* Set if the backend is working in busy wait mode. If unset,
     * blocking synchronization is used. */
    int busy_wait;

    /* Guest memory map. */
    BpfhvBackendMemoryRegion regions[BPFHV_PROXY_MAX_REGIONS];
    size_t num_regions;

    /* Queue parameters. */
    unsigned int num_queue_pairs;
    unsigned int num_rx_bufs;
    unsigned int num_tx_bufs;

    /* Total number of queues (twice as num_queue_pairs). */
    unsigned int num_queues;

    /* Flags defined for BPFHV_REG_STATUS. */
    uint32_t status;

    /* Is the backend running, (e.g. actively processing packets or
     * waiting for more processing to come) ? */
    unsigned int running;

    /* An event file descriptor to signal in case of upgrades. */
    int upgrade_fd;

    /* Thread dedicated to packet processing. */
    pthread_t th;

    /* An eventfd useful to stop the processing thread. */
    int stopfd;
    int stopflag;

    /* File descriptor of the TAP device or the netmap port
     * (the real net backend). */
    int befd;

    /* Virtio-net header length used by the TAP interface. */
    int vnet_hdr_len;

    /* Maximum size of a received packet. */
    size_t max_rx_pkt_size;

    /* Use sleep() to improve fast consumer situations. */
    int sleep_usecs;

#ifdef WITH_NETMAP
    struct {
        struct nmport_d *port;
        struct netmap_ring *txr;
        struct netmap_ring *rxr;
    } nm;
#endif

    /* Send and receive functions for real send/receive operations. */
    BeSendFun send;
    BeRecvFun recv;
    BeSyncFun sync;

    /* RX and TX queues (in this order). */
    BpfhvBackendQueue q[BPFHV_MAX_QUEUES];
} BpfhvBackend;

struct virtio_net_hdr_v1 {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1       /* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID     2       /* Csum is valid */
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE         0       /* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4        1       /* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP          3       /* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6        4       /* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN          0x80    /* TCP has ECN set */
    uint8_t gso_type;
    uint16_t hdr_len;     /* Ethernet + IP + tcp/udp hdrs */
    uint16_t gso_size;    /* Bytes to append to hdr_len per frame */
    uint16_t csum_start;  /* Position to start checksumming from */
    uint16_t csum_offset; /* Offset after that to place checksum */
    uint16_t num_buffers; /* Number of merged rx buffers */
};

#define BPFHV_BE_TX_BUDGET      128
#define BPFHV_BE_RX_BUDGET      128

/* Translate guest physical address into host virtual address.
 * This is not thread-safe at the moment being. */
static inline void *
translate_addr(BpfhvBackend *be, uint64_t gpa, uint64_t len)
{
    BpfhvBackendMemoryRegion  *re = be->regions + 0;

    if (unlikely(!(re->gpa_start <= gpa && gpa + len <= re->gpa_end))) {
        int i;

        for (i = 1; i < be->num_regions; i++) {
            re = be->regions + i;
            if (re->gpa_start <= gpa && gpa + len <= re->gpa_end) {
                /* Match. Move this entry to the first position. */
                BpfhvBackendMemoryRegion tmp = *re;

                *re = be->regions[0];
                be->regions[0] = tmp;
                re = be->regions + 0;
                break;
            }
        }
        if (i >= be->num_regions) {
            return NULL;
        }
    }

    return re->va_start + (gpa - re->gpa_start);
}

extern int verbose;
extern BeOps sring_ops;
extern BeOps sring_gso_ops;
extern BeOps vring_packed_ops;

#endif  /* __BACKEND_H__ */
