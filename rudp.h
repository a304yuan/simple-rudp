#ifndef SIMPLE_RUDP_H
#define SIMPLE_RUDP_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 20
#define PACKETS_PER_WINDOW 8
#define DEFAULT_LATENCY 300
#define MIN_LATENCY 50

typedef struct rudp rudp;
typedef struct rudp_msg rudp_msg;

enum net_socket_errno {
    ERROR_CREATE_SOCKET = 1,
    ERROR_BIND,
    ERROR_CONNECT,
    ERROR_READ,
    ERROR_WRITE,
    ERROR_CLOSE,
    ERROR_TIMEOUT
};

struct rudp_msg {
    size_t len;
    char data[];
};

struct rudp {
    int fd;
    int latency; // average latency in ms
    long total_time; // total time (ms) on transfering
    long total_packets; // total packets transfered
    struct sockaddr_in src_addr;
    struct sockaddr_in dest_addr;
};

extern rudp * rudp_new();
extern int rudp_bind(rudp * udp, const char * addr, int port);
extern int rudp_connect(rudp * udp, const char * addr, int port);
extern int rudp_send(rudp * udp, const void * msg, size_t len, int max_resend);
extern int rudp_recv(rudp * udp, rudp_msg ** msg, long time_out_ms);
extern int rudp_close(rudp * udp);
extern void rudp_free(rudp * udp);

#endif /* end of include guard: SIMPLE_RUDP_H */
