#include "rudp.h"

struct udp_packet {
    uint32_t len;
    uint32_t idx;
    uint32_t packets;
    char data[];
};

struct ack_flag {
    int ack;
    int count;
    long time;
};

static inline long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

rudp * rudp_new() {
    rudp * udp = malloc(sizeof(rudp));
    udp->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    udp->latency = DEFAULT_LATENCY;
    udp->total_packets = 0;
    udp->total_time = 0;
    memset(&udp->src_addr, 0, sizeof(struct sockaddr_in));
    memset(&udp->dest_addr, 0, sizeof(struct sockaddr_in));
    return udp;
}

int rudp_bind(rudp * udp, const char * addr, int port) {
    struct sockaddr_in * _addr = &udp->src_addr;
    _addr->sin_family = AF_INET;
    _addr->sin_port = htons(port);
    _addr->sin_addr.s_addr = inet_addr(addr);
    int retcode = bind(udp->fd, (struct sockaddr *)_addr, sizeof(struct sockaddr_in));
    if (retcode) {
        return ERROR_BIND;
    }
    return 0;
}

int rudp_connect(rudp * udp, const char * addr, int port) {
    struct sockaddr_in * _addr = &udp->dest_addr;
    _addr->sin_family = AF_INET;
    _addr->sin_port = htons(port);
    _addr->sin_addr.s_addr = inet_addr(addr);
    int retcode = connect(udp->fd, (struct sockaddr *)_addr, sizeof(struct sockaddr_in));
    if (retcode) {
        return ERROR_CONNECT;
    }
    return 0;
}

int rudp_close(rudp * udp) {
    if (close(udp->fd) < 0)
        return ERROR_CLOSE;
    else
        return 0;
}

void rudp_free(rudp * udp) {
    free(udp);
}

int rudp_send(rudp * udp, const void * msg, size_t len, int max_resend) {
    int packet_data_size = MAX_PACKET_SIZE - sizeof(struct udp_packet);
    uint32_t window_start_idx = 0;
    const void * msg_end = msg + len;
    const void * window_start = msg;
    const void * window_end = window_start + packet_data_size * PACKETS_PER_WINDOW;
    const void * p = window_start;
    struct ack_flag ack_flags[PACKETS_PER_WINDOW] = {0};
    struct udp_packet * buf = malloc(MAX_PACKET_SIZE);
    buf->packets = len / packet_data_size + (len % packet_data_size ? 1 : 0);
    while (window_start < msg_end) {
        if (p >= window_end || p < window_start) {
            p = window_start;
        }
        uint32_t i = (p - window_start) / packet_data_size;
        // check if it is acked otherwise resend
        long time_ms = get_time_ms();
        if (!ack_flags[i].ack && time_ms - ack_flags[i].time >= udp->latency) {
            size_t send = msg_end - p > packet_data_size ? packet_data_size : msg_end - p;
            buf->idx = window_start_idx + i;
            if (p < msg_end) {
                memcpy(buf->data, p, send);
                buf->len = send;
            }
            else {
                buf->len = 0;
            }
            // handle time out
            if (ack_flags[i].count++ == max_resend) {
                return ERROR_TIMEOUT;
            }
            write(udp->fd, buf, MAX_PACKET_SIZE);
            ack_flags[i].time = time_ms;
        }
        p += packet_data_size;
        // recv ack info
        uint32_t ack_idx;
        while (read(udp->fd, &ack_idx, sizeof(ack_idx)) > 0) {
            if (ack_idx >= window_start_idx) {
                struct ack_flag * flag = &ack_flags[ack_idx - window_start_idx];
                // update latency
                if (flag->count == ++flag->ack) {
                    udp->total_packets++;
                    udp->total_time += time_ms - flag->time;
                    udp->latency = udp->total_time / udp->total_packets;
                    if (udp->latency < MIN_LATENCY) {
                        udp->latency = MIN_LATENCY;
                    }
                }
            }
        }

        // move window
        int moves = 0;
        for (int i = 0; i < PACKETS_PER_WINDOW && ack_flags[i].ack; i++, moves++);
        memmove(ack_flags, ack_flags + moves, sizeof(struct ack_flag) * (PACKETS_PER_WINDOW - moves));
        for (int i = 0; i < moves; i++) {
            memset(&ack_flags[PACKETS_PER_WINDOW - 1 - i], 0, sizeof(struct ack_flag));
        }
        window_start_idx += moves;
        window_start += moves * packet_data_size;
        window_end += moves * packet_data_size;
    }
    return 0;
}

int rudp_recv(rudp * udp, rudp_msg ** msg, long time_out_ms) {
    struct udp_packet * buf = malloc(MAX_PACKET_SIZE);
    *msg = NULL;
    int ack_flags[PACKETS_PER_WINDOW] = {0};
    int packet_data_size = MAX_PACKET_SIZE - sizeof(struct udp_packet);
    uint32_t window_start_idx = 0;
    uint32_t total_packets = 1;
    uint32_t recv_packets = 0;
    long last_recv = get_time_ms();
    while (recv_packets < total_packets + PACKETS_PER_WINDOW) {
        long now = get_time_ms();
        // read a packet
        if (read(udp->fd, buf, MAX_PACKET_SIZE) > 0) {
            last_recv = now;
        }
        else {
            if (now - last_recv >= time_out_ms) {
                if (window_start_idx >= total_packets)
                    break;
                else
                    return ERROR_TIMEOUT;
            }
            else {
                continue;
            }
        }
        total_packets = buf->packets;
        // allocate space at first packet
        if (!(*msg)) {
            size_t len = total_packets * packet_data_size;
            *msg = malloc(sizeof(rudp_msg) + len);
            (*msg)->len = 0;
        }
        // copy data from packet
        if (buf->idx >= window_start_idx && !ack_flags[buf->idx - window_start_idx]) {
            ack_flags[buf->idx - window_start_idx] = 1;
            recv_packets++;
            if (buf->idx < total_packets) {
                memcpy((*msg)->data + buf->idx * packet_data_size, buf->data, buf->len);
                (*msg)->len += buf->len;
            }
        }
        // ack packet idx
        write(udp->fd, &buf->idx, sizeof(buf->idx));
        // move window
        int moves = 0;
        for (int i = 0; i < PACKETS_PER_WINDOW && ack_flags[i]; i++, moves++);
        memmove(ack_flags, ack_flags + moves, sizeof(int) * (PACKETS_PER_WINDOW - moves));
        for (int i = 0; i < moves; i++) {
            ack_flags[PACKETS_PER_WINDOW - 1 - i] = 0;
        }
        window_start_idx += moves;
    }
    return 0;
}
