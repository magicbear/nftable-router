/*
 * markexec: LD_PRELOAD shim that stamps SO_MARK on every inet socket the
 * child process creates, so tools without mark support (mtr, ping, curl...)
 * get routed by the existing `ip rule fwmark M table M` policy -- used by
 * webadmin per-line path tests. Built on demand by webadmin (needs cc).
 *
 * usage: MARK=0x387 LD_PRELOAD=markexec.so mtr -n --report 1.1.1.1
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>

#ifndef SO_MARK
#define SO_MARK 36 /* x86/arm linux */
#endif

int socket(int domain, int type, int protocol)
{
    static int (*real_socket)(int, int, int);
    static long mark = -2;
    int fd;
    if (!real_socket)
        real_socket = dlsym(RTLD_NEXT, "socket");
    if (mark == -2) {
        const char *m = getenv("MARK");
        mark = m ? strtol(m, NULL, 0) : 0;
    }
    fd = real_socket(domain, type, protocol);
    if (fd >= 0 && mark && (domain == AF_INET || domain == AF_INET6)) {
        int v = (int)mark;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &v, sizeof(v));
    }
    return fd;
}
