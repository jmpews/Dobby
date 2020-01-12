#include <stdlib.h> /* getenv */
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <fstream>

#include <set>

#include <unordered_map>

#include <sys/types.h>
#include <sys/socket.h>
int (*orig_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int fake_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
}

int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
}

ssize_t (*orig_send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t(fake_send)(int sockfd, const void *buf, size_t len, int flags) {
}

ssize_t (*orig_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t fake_recv(int sockfd, void *buf, size_t len, int flags) {
}