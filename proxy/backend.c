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

#include "bpfhv-proxy.h"
#include "bpfhv.h"

typedef struct BpfhvBackendMemoryRegion {
    uint64_t    gpa;
    uint64_t    size;
    uint64_t    hva;
    uint64_t    mmap_offset;
    void        *mmap_addr;
} BpfhvBackendMemoryRegion;

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
} BpfhvBackend;

static int
main_loop(BpfhvBackend *be)
{
    int ret = -1;

    be->features_avail = BPFHV_F_SG;
    be->features_sel = 0;

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMessage resp;

        /* Variables to store recvmsg() ancillary data. */
        int fds[BPFHV_PROXY_MAX_REGIONS];
        size_t num_fds = 0;

        /* Variables to store sendmsg() ancillary data. */
        int outfds[BPFHV_PROXY_MAX_REGIONS];
        size_t num_outfds = 0;

        /* Support variables for reading a bpfhv-proxy message header. */
        char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))] = {};
        BpfhvProxyMessage msg;
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
        memset(&msg.hdr, 0, sizeof(msg.hdr));
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

        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
            payload_size = sizeof(msg.payload.memory_map);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
            payload_size = sizeof(msg.payload.queue_ctx);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
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
        memset(&msg.payload, 0, sizeof(msg.payload));
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

        memset(&resp, 0, sizeof(resp));
        resp.hdr.reqtype = BPFHV_PROXY_REQ_NONE;

        /* Process the request. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
            be->features_sel = be->features_avail & msg.payload.u64;
            break;

        case BPFHV_PROXY_REQ_GET_FEATURES:
            resp.hdr.reqtype = msg.hdr.reqtype;
            resp.hdr.size = sizeof(resp.payload.u64);
            resp.payload.u64 = be->features_avail;
            break;

        case BPFHV_PROXY_REQ_SET_MEM_TABLE: {
            BpfhvProxyMemoryMap *map = &msg.payload.memory_map;
            size_t i;

            /* Perform sanity checks. */
            if (map->num_regions > BPFHV_PROXY_MAX_REGIONS) {
                fprintf(stderr, "Too many memory regions: %u\n",
                        map->num_regions);
                return -1;
            }
            if (num_fds != map->num_regions) {
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

                be->regions[i].gpa = map->regions[i].guest_physical_addr;
                be->regions[i].size = map->regions[i].size;
                be->regions[i].hva = map->regions[i].hypervisor_virtual_addr;
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
                    fprintf(stderr, "mmap(#%zu) failed: %s\n", i, strerror(errno));
                    return -1;
                }
                be->regions[i].mmap_addr = mmap_addr;
            }
            be->num_regions = map->num_regions;

            printf("Guest memory map:\n");
            for (i = 0; i < be->num_regions; i++) {
                printf("    gpa %16"PRIx64", size %16"PRIu64", "
                       "hva %16"PRIx64", mmap_ofs %16"PRIx64", "
                       "mmap_addr %p\n",
                       be->regions[i].gpa, be->regions[i].size,
                       be->regions[i].hva, be->regions[i].mmap_offset,
                       be->regions[i].mmap_addr);
            }
            break;
        }

        case BPFHV_PROXY_REQ_GET_PROGRAMS:
            outfds[0] = open(be->progfile, O_RDONLY, 0);
            if (outfds[0] < 0) {
                fprintf(stderr, "open(%s) failed: %s\n", be->progfile,
                        strerror(errno));
                return -1;
            }
            num_outfds = 1;
            break;

        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
            printf("Handling message ...\n");
            break;

        default:
            /* Not reached (see switch statement above). */
            assert(0);
            break;
        }

        /* Send back the response, if any. */
        if (resp.hdr.reqtype != BPFHV_PROXY_REQ_NONE) {
            size_t totsize = sizeof(resp.hdr) + resp.hdr.size;
            struct iovec iov = {
                .iov_base = &resp,
                .iov_len = totsize,
            };
            struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                //.msg_control = control,
                //.msg_controllen = sizeof(control),
            };

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
                close(fds[i]);
            }
            for (i = 0; i < num_outfds; i++) {
                close(outfds[i]);
            }
        }
    }

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
    struct sockaddr_un server_addr;
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

    memset(&server_addr, 0, sizeof(server_addr));
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
