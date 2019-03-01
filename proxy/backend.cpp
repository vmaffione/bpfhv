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
        std::cerr << "socket(AF_UNIX) failed: " << strerror(errno) << std::endl;
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
        struct pollfd pfd[1];
        int n;

        pfd[0].fd = cfd;
        pfd[0].events = POLLIN;
        n = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1);
        assert(n != 0);
        if (n < 0) {
            std::cerr << "poll() failed: " << strerror(errno) << std::endl;
            return -1;
        }

        char buf[1024];

        n = read(cfd, buf, sizeof(buf));
        if (n < 0) {
            std::cerr << "read(cfd) failed: " << strerror(errno) << std::endl;
            return -1;
        }

        std::cout << "Got message, size " << n << std::endl;
        if (n == 0) {
            /* EOF */
            break;
        }
    }

    close(cfd);

    return 0;
}
