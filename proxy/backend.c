#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <poll.h>

#include "bpfhv-proxy.h"
#include "bpfhv.h"

static void
usage(const char *progname)
{
    printf("%s:\n"
           "    -h (show this help and exit)\n"
           "    -p UNIX_SOCKET_PATH\n",
            progname);
}

typedef struct BpfhvProxyBackend {
    /* The features we support. */
    uint64_t features_avail;

    /* The features selected by the guest. */
    uint64_t features_sel;
} BpfhvProxyBackend;

static int
main_loop(int cfd)
{
    BpfhvProxyBackend be;
    int ret = -1;

    be.features_avail = BPFHV_F_SG;
    be.features_sel = 0;

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMessage msg;
        BpfhvProxyMessage resp;
        struct pollfd pfd[1];
        ssize_t n;

        pfd[0].fd = cfd;
        pfd[0].events = POLLIN;
        n = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1);
        assert(n != 0);
        if (n < 0) {
            fprintf(stderr, "poll() failed: %s\n", strerror(errno));
            break;
        }

        /* Read message header. */
        memset(&msg.hdr, 0, sizeof(msg.hdr));
        n = read(cfd, &msg.hdr, sizeof(msg.hdr));
        if (n < 0) {
            fprintf(stderr, "read(cfd) failed: %s\n", strerror(errno));
            break;
        }

        if (n == 0) {
            /* EOF */
            printf("Connection closed by the hypervisor\n");
            break;
        }

        if (n < (ssize_t)sizeof(msg.hdr)) {
            fprintf(stderr, "Message too short (%zd bytes)\n", n);
            break;
        }

        /* Check that payload size is correct. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_GET_FEATURES:
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
        n = read(cfd, &msg.payload, payload_size);
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

        /* Process request. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
            be.features_sel = be.features_avail & msg.payload.u64;
            break;

        case BPFHV_PROXY_REQ_GET_FEATURES:
            resp.hdr.reqtype = msg.hdr.reqtype;
            resp.hdr.size = sizeof(resp.payload.u64);
            resp.payload.u64 = be.features_avail;
            break;

        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
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

            n = write(cfd, &resp, totsize);
            if (n < 0) {
                fprintf(stderr, "write(cfd) failed: %s\n", strerror(errno));
                break;
            } else if (n != totsize) {
                fprintf(stderr, "Truncated write (%zu/%zu)\n", n, totsize);
                break;
            }
        }
    }

    return ret;
}

int
main(int argc, char **argv)
{
    struct sockaddr_un server_addr;
    const char *path = NULL;
    int opt;
    int cfd;
    int ret;

    while ((opt = getopt(argc, argv, "hp:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'p':
            path = optarg;
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

    ret = main_loop(cfd);

    close(cfd);

    return ret;
}
