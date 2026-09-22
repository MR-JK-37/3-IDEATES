/*
 * loader.c
 * libbpf-based loader and ring buffer consumer for av_monitor.bpf.o
 * Emits filename strings to a Unix datagram socket for the Rust av-service to consume.
 * Build: make (requires libbpf dev and pkg-config)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;
static const char *SOCK_PATH = "/var/run/av_event.sock";

struct event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
};

static void handle_signal(int sig)
{
    exiting = 1;
}

static int send_filename_to_socket(int sockfd, const char *filename)
{
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    ssize_t n = sendto(sockfd, filename, strnlen(filename, 256), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
    if (n < 0) {
        fprintf(stderr, "sendto failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    int sockfd = *(int *)ctx;
    if (data_sz < sizeof(struct event_t))
        return 0;

    struct event_t *e = data;
    /* Ensure filename is null-terminated */
    e->filename[sizeof(e->filename)-1] = '\0';
    /* Send only the filename string to the Rust service socket */
    send_filename_to_socket(sockfd, e->filename);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct ring_buffer *rb = NULL;
    int sockfd = -1;
    const char *bpf_obj_file = "av_monitor.bpf.o";

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* open unix datagram socket (no bind required for client sendto) */
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    obj = bpf_object__open_file(bpf_obj_file, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", bpf_obj_file);
        close(sockfd);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        close(sockfd);
        return 1;
    }

    /* Note: for LSM programs libbpf should attach them automatically on load if kernel supports */

    /* Find the map fd for the ringbuf named 'events' */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "Map 'events' not found in BPF object\n");
        bpf_object__close(obj);
        close(sockfd);
        return 1;
    }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Invalid map fd\n");
        bpf_object__close(obj);
        close(sockfd);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, &sockfd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        close(sockfd);
        return 1;
    }

    fprintf(stderr, "loader: listening for events; sending filenames to %s\n", SOCK_PATH);

    while (!exiting) {
        int ret = ring_buffer__poll(rb, 100 /* ms */);
        if (ret < 0 && errno != EINTR) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", ret);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    close(sockfd);
    fprintf(stderr, "loader: exiting\n");
    return 0;
}
