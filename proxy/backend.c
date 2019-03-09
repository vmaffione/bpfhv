#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <assert.h>
#include <poll.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <stdlib.h>

#include "bpfhv-proxy.h"
#include "bpfhv.h"
#include "sring.h"

#ifndef likely
#define likely(x)           __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x)         __builtin_expect((x), 0)
#endif

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

typedef struct BpfhvBackendQueue {
    union {
        struct bpfhv_rx_context *rx;
        struct bpfhv_tx_context *tx;
    } ctx;
    int kickfd;
    int irqfd;
    char name[8];
} BpfhvBackendQueue;

/* Main data structure supporting a single bpfhv vNIC. */
typedef struct BpfhvBackend {
    /* Socket file descriptor to exchange control message with the
     * hypervisor. */
    int cfd;

    /* Path of the object file containing the ebpf programs. */
    const char *progfile;

    /* The features we support. */
    uint64_t features_avail;

    /* The features selected by the guest. */
    uint64_t features_sel;

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

    /* RX and TX queues (in this order). */
    BpfhvBackendQueue q[BPFHV_MAX_QUEUES];
} BpfhvBackend;

/* Translate guest physical address into host virtual address.
 * This is not thread-safe at the moment being. */
static void *
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

/*
 * The sring implementation.
 */

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");

static size_t
sring_rx_ctx_size(size_t num_rx_bufs)
{
    return sizeof(struct bpfhv_rx_context) + sizeof(struct sring_rx_context) +
	num_rx_bufs * sizeof(struct sring_rx_desc);
}

static size_t
sring_tx_ctx_size(size_t num_tx_bufs)
{
    return sizeof(struct bpfhv_tx_context) + sizeof(struct sring_tx_context) +
	num_tx_bufs * sizeof(struct sring_tx_desc);
}

void
sring_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;

    assert((num_rx_bufs & (num_rx_bufs - 1)) == 0);
    priv->qmask = num_rx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_rx_bufs * sizeof(priv->desc[0]));
}

void
sring_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    assert((num_tx_bufs & (num_tx_bufs - 1)) == 0);
    priv->qmask = num_tx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}

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

#define BPFHV_HV_TX_BUDGET      64

static size_t
iov_size(struct iovec *iov, size_t iovcnt)
{
    size_t len = 0;
    size_t i;

    for (i = 0; i < iovcnt; i++) {
        len += iov[i].iov_len;
    }

    return len;
}

static ssize_t
sring_txq_drain(BpfhvBackend *be,
                struct bpfhv_tx_context *ctx,
                int vnet_hdr_len, int *notify)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    struct iovec iov[BPFHV_MAX_TX_BUFS];
    uint32_t prod = ACCESS_ONCE(priv->prod);
    uint32_t cons = priv->cons;
    uint32_t first = cons;
    int iovcnt_start = vnet_hdr_len != 0 ? 1 : 0;
    int iovcnt = iovcnt_start;
    int count = 0;

    while (cons != prod) {
        struct sring_tx_desc *txd = priv->desc + (cons & priv->qmask);

        cons++;

        iov[iovcnt].iov_base = translate_addr(be, txd->paddr, txd->len);
        iov[iovcnt].iov_len = txd->len;
        if (unlikely(iov[iovcnt].iov_base == NULL)) {
            /* Invalid descriptor, just skip it. */
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

            ret = 1; /* TODO output packet, return bytes sent */
            printf("Fake transmit iovcnt %u size %zu\n", iovcnt,
                   iov_size(iov, iovcnt));

            if (ret == 0) {
                /* Backend is blocked, we need to stop. The last packet was not
                 * transmitted, so we need to rewind 'cons'. */
                cons = first;
                break;
            }

            if (++count >= BPFHV_HV_TX_BUDGET) {
                break;
            }

            iovcnt = iovcnt_start;
            first = cons;
        }
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    priv->cons = cons;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    *notify = ACCESS_ONCE(priv->intr_enabled);

    return count;
}

void
sring_txq_notification(struct bpfhv_tx_context *ctx, int enable)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->kick_enabled = !!enable;
    if (enable) {
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    }
}

static void
sring_txq_dump(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    printf("sring.txq cl %u co %u pr %u kick %u intr %u\n",
           ACCESS_ONCE(priv->clear), ACCESS_ONCE(priv->cons),
           ACCESS_ONCE(priv->prod), ACCESS_ONCE(priv->kick_enabled),
           ACCESS_ONCE(priv->intr_enabled));
}

static inline void
eventfd_drain(int fd)
{
    uint64_t x = 123;
    int n;

    n = read(fd, &x, sizeof(x));
    if (unlikely(n != sizeof(x))) {
        assert(n < 0);
        fprintf(stderr, "read() failed: %s\n", strerror(errno));
    }
}

static void *
process_packets(void *opaque)
{
    BpfhvBackend *be = opaque;
    struct pollfd *pfd;
    unsigned int nfds;
    unsigned int i;

    printf("Thread started\n");

    nfds = 1 + be->num_queue_pairs * 2;
    pfd = calloc(nfds, sizeof(pfd[0]));
    assert(pfd != NULL);

    for (i = 0; i < be->num_queues; i++) {
        pfd[i].fd = be->q[i].kickfd;
        pfd[i].events = POLLIN;
    }
    pfd[nfds-1].fd = be->stopfd;
    pfd[nfds-1].events = POLLIN;

    for (;;) {
        int n;

        n = poll(pfd, nfds, -1);
        if (unlikely(n <= 0)) {
            assert(n < 0);
            fprintf(stderr, "poll() failed: %s\n", strerror(errno));
            break;
        }

        for (i = 0; i < be->num_queue_pairs; i++) {
            if (pfd[i].revents & POLLIN) {
                printf("Kick on RX%u\n", i);
                eventfd_drain(pfd[i].fd);
            }
        }

        for (; i < 2 * be->num_queue_pairs; i++) {
            if (pfd[i].revents & POLLIN) {
                BpfhvBackendQueue *txq = be->q + i;
                int notify;

                printf("Kick on TX%u\n", i-be->num_queue_pairs);
                sring_txq_drain(be, txq->ctx.tx, 0, &notify);
                sring_txq_dump(txq->ctx.tx);
                eventfd_drain(pfd[i].fd);
            }
        }

        if (unlikely(pfd[nfds-1].revents & POLLIN)) {
            eventfd_drain(pfd[nfds-1].fd);
            printf("Thread stopped\n");
            break;
        }
    }

    free(pfd);

    return NULL;
}

/* Helper function to validate the number of buffers. */
static int
num_bufs_valid(uint64_t num_bufs)
{
    if (num_bufs < 16 || num_bufs > 8192 ||
            (num_bufs & (num_bufs - 1)) != 0) {
        return 0;
    }
    return 1;
}

/* Is the backend ready to process packets ? */
static int
backend_ready(BpfhvBackend *be)
{
    int i;

    for (i = 0; i < be->num_queues; i++) {
        if (be->q[i].ctx.rx == NULL) {
            return 0;
        }

        if (be->q[i].kickfd < 0) {
            return 0;
        }

        if (be->q[i].irqfd < 0) {
            return 0;
        }
    }

    return be->num_queue_pairs > 0 && num_bufs_valid(be->num_rx_bufs) &&
           num_bufs_valid(be->num_tx_bufs) && be->num_regions > 0;
}

/* Control loop to process requests coming from the hypervisor. */
static int
main_loop(BpfhvBackend *be)
{
    int ret = -1;
    int i;

    be->features_avail = BPFHV_F_SG;
    be->features_sel = 0;
    be->num_queue_pairs = be->num_queues = 0;
    be->num_rx_bufs = 0;
    be->num_tx_bufs = 0;
    be->running = 0;
    be->status = 0;
    be->upgrade_fd = -1;

    for (i = 0; i < BPFHV_MAX_QUEUES; i++) {
        be->q[i].ctx.rx = NULL;
        be->q[i].kickfd = be->q[i].irqfd = -1;
    }

    be->stopfd = eventfd(0, 0);
    if (be->stopfd < 0) {
        fprintf(stderr, "eventfd() failed: %s\n", strerror(errno));
        return -1;
    }

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMessage resp = { };

        /* Variables to store recvmsg() ancillary data. */
        int fds[BPFHV_PROXY_MAX_REGIONS];
        size_t num_fds = 0;

        /* Variables to store sendmsg() ancillary data. */
        int outfds[BPFHV_PROXY_MAX_REGIONS];
        size_t num_outfds = 0;

        /* Support variables for reading a bpfhv-proxy message header. */
        char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))] = {};
        BpfhvProxyMessage msg = { };
        struct iovec iov = {
            .iov_base = &msg.hdr,
            .iov_len = sizeof(msg.hdr),
        };
        struct msghdr mh = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t n;

        /* Wait for the next message to arrive. */
        struct pollfd pfd[1];

        pfd[0].fd = be->cfd;
        pfd[0].events = POLLIN;
        n = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1);
        assert(n != 0);
        if (n < 0) {
            fprintf(stderr, "poll() failed: %s\n", strerror(errno));
            break;
        }

        /* Read a bpfhv-proxy message header plus ancillary data. */
        do {
            n = recvmsg(be->cfd, &mh, 0);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "recvmsg(cfd) failed: %s\n", strerror(errno));
            break;
        }

        if (n == 0) {
            /* EOF */
            printf("Connection closed by the hypervisor\n");
            break;
        }

        /* Scan ancillary data looking for file descriptors. */
        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&mh, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                size_t arr_size = cmsg->cmsg_len - CMSG_LEN(0);

                num_fds = arr_size / sizeof(fds[0]);
                if (num_fds > BPFHV_PROXY_MAX_REGIONS) {
                    fprintf(stderr, "Message contains too much ancillary data "
                            "(%zu file descriptors)\n", num_fds);
                    return -1;
                }
                memcpy(fds, CMSG_DATA(cmsg), arr_size);

                break; /* Discard any other ancillary data. */
            }
        }

        if (n < (ssize_t)sizeof(msg.hdr)) {
            fprintf(stderr, "Message too short (%zd bytes)\n", n);
            break;
        }

        if ((msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK)
                != BPFHV_PROXY_VERSION) {
            fprintf(stderr, "Protocol version mismatch: expected %u, got %u",
                    BPFHV_PROXY_VERSION,
                    msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK);
            break;
        }

        /* Check that payload size is correct. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_GET_FEATURES:
        case BPFHV_PROXY_REQ_GET_PROGRAMS:
        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
            payload_size = 0;
            break;

        case BPFHV_PROXY_REQ_SET_FEATURES:
            payload_size = sizeof(msg.payload.u64);
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS:
            payload_size = sizeof(msg.payload.params);
            break;

        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
            payload_size = sizeof(msg.payload.memory_map);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
            payload_size = sizeof(msg.payload.queue_ctx);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
        case BPFHV_PROXY_REQ_SET_UPGRADE:
            payload_size = sizeof(msg.payload.notify);
            break;

        default:
            fprintf(stderr, "Invalid request type (%d)\n", msg.hdr.reqtype);
            return -1;
        }

        if (payload_size != msg.hdr.size) {
            fprintf(stderr, "Payload size mismatch: expected %zd, got %u\n",
                    payload_size, msg.hdr.size);
            break;
        }

        /* Read payload. */
        do {
            n = read(be->cfd, &msg.payload, payload_size);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "read(cfd, payload) failed: %s\n",
                    strerror(errno));
            break;
        }

        if (n != payload_size) {
            fprintf(stderr, "Truncated payload: expected %zd bytes, "
                    "but only %zd were read\n", payload_size, n);
            break;
        }

        resp.hdr.reqtype = msg.hdr.reqtype;
        resp.hdr.flags = BPFHV_PROXY_VERSION;

        /* Process the request. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
            be->features_sel = be->features_avail & msg.payload.u64;
            printf("Negotiated features %"PRIx64"\n", be->features_sel);
            break;

        case BPFHV_PROXY_REQ_GET_FEATURES:
            resp.hdr.size = sizeof(resp.payload.u64);
            resp.payload.u64 = be->features_avail;
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS: {
            BpfhvProxyParameters *params = &msg.payload.params;

            if (params->num_rx_queues != 1 || params->num_tx_queues != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else if (!num_bufs_valid(params->num_rx_bufs) ||
                       !num_bufs_valid(params->num_tx_bufs)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else {
                unsigned int i;

                be->num_queue_pairs = (unsigned int)params->num_rx_queues;
                be->num_rx_bufs = (unsigned int)params->num_rx_bufs;
                be->num_tx_bufs = (unsigned int)params->num_tx_bufs;
                printf("Set queue parameters: %u queue pairs, %u rx bufs, "
                       "%u tx bufs\n", be->num_queue_pairs,
                        be->num_rx_bufs, be->num_tx_bufs);

                be->num_queues = 2 * be->num_queue_pairs;

                resp.hdr.size = sizeof(resp.payload.ctx_sizes);
                resp.payload.ctx_sizes.rx_ctx_size =
                    sring_rx_ctx_size(be->num_rx_bufs);
                resp.payload.ctx_sizes.tx_ctx_size =
                    sring_tx_ctx_size(be->num_tx_bufs);

                for (i = 0; i < be->num_queue_pairs; i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "RX%u", i);
                }
                for (i = be->num_queue_pairs; i < be->num_queues; i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "TX%u", i-be->num_queue_pairs);
                }
            }
            break;
        }

        case BPFHV_PROXY_REQ_SET_MEM_TABLE: {
            BpfhvProxyMemoryMap *map = &msg.payload.memory_map;
            size_t i;

            /* Perform sanity checks. */
            if (map->num_regions > BPFHV_PROXY_MAX_REGIONS) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many memory regions: %u\n",
                        map->num_regions);
                return -1;
            }
            if (num_fds != map->num_regions) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Mismatch between number of regions (%u) and "
                        "number of file descriptors (%zu)\n",
                        map->num_regions, num_fds);
                return -1;
            }

            /* Clean up previous table. */
            for (i = 0; i < be->num_regions; i++) {
                munmap(be->regions[i].mmap_addr,
                       be->regions[i].mmap_offset + be->regions[i].size);
            }
            memset(be->regions, 0, sizeof(be->regions));
            be->num_regions = 0;

            /* Setup the new table. */
            for (i = 0; i < map->num_regions; i++) {
                void *mmap_addr;

                be->regions[i].gpa_start = map->regions[i].guest_physical_addr;
                be->regions[i].size = map->regions[i].size;
                be->regions[i].gpa_end = be->regions[i].gpa_start +
                                         be->regions[i].size;
                be->regions[i].hv_vaddr =
                        map->regions[i].hypervisor_virtual_addr;
                be->regions[i].mmap_offset = map->regions[i].mmap_offset;

                /* We don't feed mmap_offset into the offset argument of
                 * mmap(), because the mapped address has to be page aligned,
                 * and we use huge pages. Instead, we map the file descriptor
                 * from the beginning, with a map size that includes the
                 * region of interest. */
                mmap_addr = mmap(0, /*size=*/be->regions[i].mmap_offset +
                                 be->regions[i].size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, /*fd=*/fds[i], /*offset=*/0);
                if (mmap_addr == MAP_FAILED) {
                    fprintf(stderr, "mmap(#%zu) failed: %s\n", i,
                            strerror(errno));
                    return -1;
                }
                be->regions[i].mmap_addr = mmap_addr;
                be->regions[i].va_start = mmap_addr +
                                          be->regions[i].mmap_offset;
            }
            be->num_regions = map->num_regions;

            printf("Guest memory map:\n");
            for (i = 0; i < be->num_regions; i++) {
                printf("    gpa %16"PRIx64", size %16"PRIu64", "
                       "hv_vaddr %16"PRIx64", mmap_ofs %16"PRIx64", "
                       "va_start %p\n",
                       be->regions[i].gpa_start, be->regions[i].size,
                       be->regions[i].hv_vaddr, be->regions[i].mmap_offset,
                       be->regions[i].va_start);
            }
            break;
        }

        case BPFHV_PROXY_REQ_GET_PROGRAMS: {
            resp.hdr.size = 0;
            outfds[0] = open(be->progfile, O_RDONLY, 0);
            if (outfds[0] < 0) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "open(%s) failed: %s\n", be->progfile,
                        strerror(errno));
                break;
            }
            num_outfds = 1;
            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX: {
            uint64_t gpa = msg.payload.queue_ctx.guest_physical_addr;
            uint32_t queue_idx = msg.payload.queue_ctx.queue_idx;
            int is_rx = queue_idx < be->num_queue_pairs;
            size_t ctx_size;
            void *ctx;

            if (is_rx) {
                ctx_size = sring_rx_ctx_size(be->num_rx_bufs);
            } else if (queue_idx < be->num_queues) {
                ctx_size = sring_tx_ctx_size(be->num_tx_bufs);
            } else {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                break;
            }

            ctx = translate_addr(be, gpa, ctx_size);
            if (gpa && ctx == NULL) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Failed to translate gpa %"PRIx64"\n", gpa);
                break;
            }

            if (is_rx) {
                be->q[queue_idx].ctx.rx = (struct bpfhv_rx_context *)ctx;
                if (ctx) {
                    sring_rx_ctx_init(be->q[queue_idx].ctx.rx,
                                      be->num_rx_bufs);
                }
            } else {
                be->q[queue_idx].ctx.tx = (struct bpfhv_tx_context *)ctx;
                if (ctx) {
                    sring_tx_ctx_init(be->q[queue_idx].ctx.tx,
                                      be->num_tx_bufs);
                }
            }
            printf("Set queue %s gpa to %"PRIx64", va %p\n",
                   be->q[queue_idx].name, gpa, ctx);

            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ: {
            int is_kick = msg.hdr.reqtype == BPFHV_PROXY_REQ_SET_QUEUE_KICK;
            uint32_t queue_idx = msg.payload.notify.queue_idx;
            int is_rx = queue_idx < be->num_queue_pairs;
            int *fdp = NULL;

            if (!is_rx) {
                if (queue_idx < 2 * be->num_queue_pairs) {
                } else {
                    resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                    fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                    break;
                }
            }

            if (num_fds > 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many %sfds\n", is_kick ? "kick" : "irq");
                break;
            }

            fdp = is_kick ? &be->q[queue_idx].kickfd : &be->q[queue_idx].irqfd;

            /* Clean up previous file descriptor and install the new one. */
            if (*fdp >= 0) {
                close(*fdp);
            }
            *fdp = (num_fds == 1) ? fds[0] : -1;

            /* Steal it from the fds array to skip close(). */
            fds[0] = -1;

            printf("Set queue %s %sfd to %d\n", be->q[queue_idx].name,
                   is_kick ? "kick" : "irq", *fdp);

            break;
        }

        case BPFHV_PROXY_REQ_SET_UPGRADE: {
            if (num_fds != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Missing upgrade fd\n");
                break;
            }

            /* Steal the file descriptor from the fds array to skip close(). */
            if (be->upgrade_fd >= 0) {
                close(be->upgrade_fd);
            }
            be->upgrade_fd = fds[0];
            fds[0] = -1;

            printf("Set upgrade notifier to %d\n", be->upgrade_fd);
            break;
        }

        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_ENABLE;
            int ret;

            /* Check that backend is ready for packet processing. */
            if (!backend_ready(be)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Cannot enable %s operation: backend is "
                        "not ready\n", is_rx ? "receive" : "transmit");
                break;
            }

            /* Update be->status. */
            if (is_rx) {
                be->status |= BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status |= BPFHV_STATUS_TX_ENABLED;
            }

            if (be->running) {
                break;  /* Nothing to do */
            }

            ret = pthread_create(&be->th, NULL, process_packets, be);
            if (ret) {
                fprintf(stderr, "pthread_create() failed: %s\n",
                        strerror(ret));
                break;
            }
            be->running = 1;
            printf("Backend starts processing\n");
            break;
        }

        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_DISABLE;
            int ret;

            /* Update be->status. */
            if (is_rx) {
                be->status &= ~BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status &= ~BPFHV_STATUS_TX_ENABLED;
            }

            if (!be->running || ((be->status & (BPFHV_STATUS_RX_ENABLED |
                                BPFHV_STATUS_TX_ENABLED)) != 0)) {
                break;  /* Nothing to do. */
            }

            /* Notify the worker thread and join it. */
            {
                uint64_t x = 1;
                int n;

                n = write(be->stopfd, &x, sizeof(x));
                if (n != sizeof(x)) {
                    assert(n < 0);
                    fprintf(stderr, "write() failed: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
            ret = pthread_join(be->th, NULL);
            if (ret) {
                fprintf(stderr, "pthread_join() failed: %s\n",
                        strerror(ret));
                break;
            }
            be->running = 0;
            printf("Backend stops processing\n");
            break;
        }

        default:
            /* Not reached (see switch statement above). */
            assert(0);
            break;
        }

        /* Send back the response. */
        {
            char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))];
            size_t totsize = sizeof(resp.hdr) + resp.hdr.size;
            struct iovec iov = {
                .iov_base = &resp,
                .iov_len = totsize,
            };
            struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
            };

            if (num_outfds > 0) {
                /* Set ancillary data. */
                size_t data_size = num_outfds * sizeof(fds[0]);
                struct cmsghdr *cmsg;

                assert(num_outfds <= BPFHV_PROXY_MAX_REGIONS);

                mh.msg_control = control;
                mh.msg_controllen = CMSG_SPACE(data_size);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = CMSG_LEN(data_size);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(cmsg), outfds, data_size);
            }

            do {
                n = sendmsg(be->cfd, &mh, 0);
            } while (n < 0 && (errno == EINTR || errno == EAGAIN));
            if (n < 0) {
                fprintf(stderr, "sendmsg(cfd) failed: %s\n", strerror(errno));
                break;
            } else if (n != totsize) {
                fprintf(stderr, "Truncated send (%zu/%zu)\n", n, totsize);
                break;
            }
        }

        /* Close all the file descriptors passed as ancillary data. */
        {
            size_t i;

            for (i = 0; i < num_fds; i++) {
                if (fds[i] >= 0) {
                    close(fds[i]);
                }
            }
            for (i = 0; i < num_outfds; i++) {
                if (outfds[i] >= 0) {
                    close(outfds[i]);
                }
            }
        }
    }

    close(be->stopfd);

    return ret;
}

static void
usage(const char *progname)
{
    printf("%s:\n"
           "    -h (show this help and exit)\n"
           "    -p UNIX_SOCKET_PATH\n"
           "    -f EBPF_PROGS_PATH\n",
            progname);
}

int
main(int argc, char **argv)
{
    struct sockaddr_un server_addr = { };
    const char *path = NULL;
    BpfhvBackend be = { };
    int opt;
    int cfd;
    int ret;

    be.progfile = "proxy/sring_progs.o";

    while ((opt = getopt(argc, argv, "hp:f:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'p':
            path = optarg;
            break;

        case 'f':
            be.progfile = optarg;
            break;
        }
    }

    if (path == NULL) {
        fprintf(stderr, "Missing UNIX socket path\n");
        usage(argv[0]);
        return -1;
    }

    cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) {
        fprintf(stderr, "socket(AF_UNIX) failed: %s\n", strerror(errno));
        return -1;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, path, sizeof(server_addr.sun_path) - 1);

    if (connect(cfd, (const struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        fprintf(stderr, "connect(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    be.cfd = cfd;
    ret = main_loop(&be);
    close(cfd);

    return ret;
}
