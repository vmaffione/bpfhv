#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cassert>
#include <poll.h>

#include "bpfhv-proxy.h"

static void
usage(const char *progname)
{
    std::cout << progname << ": " << std::endl
        << "    -h (show this help and exit)" << std::endl
        << "    -p UNIX_SOCKET_PATH" << std::endl
        << std::endl;
}

int
main(int argc, char **argv)
{
    struct sockaddr_un server_addr;
    const char *path = NULL;
    int opt;
    int cfd;

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
        std::cerr << "Missing UNIX socket path" << std::endl;
        usage(argv[0]);
        return -1;
    }

    cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) {
        std::cerr << "socket(AF_UNIX) failed: " << strerror(errno)
                << std::endl;
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, path, sizeof(server_addr.sun_path) - 1);

    if (connect(cfd, (const struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        std::cerr << "connect(" << path << ") failed: "
                    << strerror(errno) << std::endl;
        return -1;
    }

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMsgPayload payload;
        BpfhvProxyMessage msg;
        struct pollfd pfd[1];
        char buf[1024];
        ssize_t n;

        pfd[0].fd = cfd;
        pfd[0].events = POLLIN;
        n = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1);
        assert(n != 0);
        if (n < 0) {
            std::cerr << "poll() failed: " << strerror(errno) << std::endl;
            break;
        }

        memset(&msg, 0, sizeof(msg));
        n = read(cfd, buf, sizeof(msg));
        if (n < 0) {
            std::cerr << "read(cfd) failed: " << strerror(errno) << std::endl;
            break;
        }

        if (n == 0) {
            /* EOF */
            std::cout << "Connection closed by the hypervisor" << std::endl;
            break;
        }

        if (n < (ssize_t)sizeof(msg)) {
            std::cerr << "Message too short (" << n << " bytes)" << std::endl;
            break;
        }

        switch (msg.reqtype) {
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
            std::cerr << "Invalid request type (" << msg.reqtype << ")"
                    << std::endl;
            goto out;
            break;
        }

        if (payload_size != msg.size) {
            std::cerr << "Payload size mismatch: expected " << payload_size
                << ", got " << msg.size << std::endl;
            break;
        }

        memset(&payload, 0, sizeof(payload));
        n = read(cfd, buf, payload_size);
        if (n < 0) {
            std::cerr << "read(cfd, payload) failed: " << strerror(errno)
                    << std::endl;
            break;
        }

        if (n != payload_size) {
            std::cerr << "Truncated payload: expected " << payload_size
                    << " bytes, but only " << n << " were read" << std::endl;
            break;
        }

        switch (msg.reqtype) {
        case BPFHV_PROXY_REQ_GET_FEATURES:
        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
        case BPFHV_PROXY_REQ_SET_FEATURES:
        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
            std::cout << "Handling message ..." << std::endl;
            break;

        default:
            /* Not reached (see switch statement above). */
            assert(false);
            break;
        }
    }

out:
    close(cfd);

    return 0;
}
