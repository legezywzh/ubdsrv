#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


static long (*bpf_ublk_queue_sqe)(void *ctx, struct io_uring_sqe *sqe,
		u32 sqe_len, u32 fd) = (void *) 211;

int target_fd = -1;

struct sqe_key {
	struct ublk_bpf_ctx *ctx;
	u64 offset;
};

struct sqe_data {
	char data[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct sqe_key);
	__type(value, struct sqe_data);
} sqes_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__type(key, int);
	__type(value, int);
} uring_fd_map SEC(".maps");

static inline void io_uring_prep_rw(__u8 op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->fsync_flags = 0;
	sqe->buf_index = 0;
	sqe->personality = 0;
	sqe->splice_fd_in = 0;
	sqe->addr3 = 0;
	sqe->__pad2[0] = 0;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe)
{
	io_uring_prep_rw(IORING_OP_NOP, sqe, -1, 0, 0, 0);
}

static inline void io_uring_prep_read(struct io_uring_sqe *sqe, int fd,
			void *buf, unsigned nbytes, off_t offset)
{
	io_uring_prep_rw(IORING_OP_READ, sqe, fd, buf, nbytes, offset);
}

static inline void io_uring_prep_write(struct io_uring_sqe *sqe, int fd,
	const void *buf, unsigned nbytes, off_t offset)
{
	io_uring_prep_rw(IORING_OP_WRITE, sqe, fd, buf, nbytes, offset);
}

static u64 submit_sqe(struct bpf_map *map, void *key, void *value, void *data)
{
	struct io_uring_sqe *sqe = (struct io_uring_sqe *)value;
	struct sqe_key *skey = (struct sqe_key *)key;
	char fmt[] ="submit sqe for req[qid:%u tag:%u]\n";
	u16 qid, tag;
	int q_id, *ring_fd;

	bpf_probe_read_kernel(&qid, 2, &(skey->ctx->q_id));
	bpf_probe_read_kernel(&tag, 2, &(skey->ctx->tag));
	q_id = qid;
	ring_fd = bpf_map_lookup_elem(&uring_fd_map, &q_id);
	if (ring_fd) {
		bpf_trace_printk(fmt, sizeof(fmt), qid, tag);
		bpf_ublk_queue_sqe(skey->ctx, sqe, 128, *ring_fd);
		bpf_map_delete_elem(map, key);
	}
	return 0;
}

static inline __u64 build_user_data(unsigned tag, unsigned op,
			unsigned tgt_data, unsigned is_target_io,
			unsigned is_bpf_io)
{
	return tag | (op << 16) | (tgt_data << 24) | (__u64)is_target_io << 63 |
		(__u64)is_bpf_io << 60;
}

SEC("ublk.s/")
int ublk_io_prep_prog(struct ublk_bpf_ctx *ctx)
{
	struct io_uring_sqe *sqe;
	struct sqe_data sd = {0};
	struct sqe_key key;
	u16 q_id = ctx->q_id;
        u16 tag = ctx->tag;
        u8 op = ctx->op;
        u32 nr_sectors = ctx->nr_sectors;
        u64 start_sector = ctx->start_sector;

	key.ctx = ctx;
	key.offset = 0;

	sqe = (struct io_uring_sqe *)&sd;
	if (op == REQ_OP_READ) {
		io_uring_prep_read(sqe, target_fd,  0, nr_sectors << 9,
				   start_sector << 9);
		sqe->user_data = build_user_data(tag, op, 0, 1, 1);
		bpf_map_update_elem(&sqes_map, &key, &sd, BPF_NOEXIST);
	} else if (op == REQ_OP_WRITE) {
		io_uring_prep_write(sqe, target_fd, 0, nr_sectors << 9,
				    start_sector << 9);
		sqe->user_data = build_user_data(tag, op, 0, 1, 1);
		bpf_map_update_elem(&sqes_map, &key, &sd, BPF_NOEXIST);
	} else {
		;
	}
	return 0;
}

SEC("ublk.s/")
int ublk_io_submit_prog(struct ublk_bpf_ctx *ctx)
{
	bpf_for_each_map_elem(&sqes_map, submit_sqe, NULL, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
