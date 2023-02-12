#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


static long (*bpf_ublk_queue_sqe)(void *ctx, struct io_uring_sqe *sqe,
		u32 sqe_len, u32 fd) = (void *) 212;

int target_fd = -1;

struct sqe_key {
	u16 q_id;
	u16 tag;
	u32 res;
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

/*
static u64 submit_sqe(struct bpf_map *map, void *key, void *value, void *data)
{
	struct io_uring_sqe *sqe = (struct io_uring_sqe *)value;
	struct ublk_bpf_ctx *ctx = ((struct callback_ctx *)data)->ctx;
	struct sqe_key *skey = (struct sqe_key *)key;
	char fmt[] ="submit sqe for req[qid:%u tag:%u]\n";
	char fmt2[] ="submit sqe test prep\n";
	u16 qid, tag;
	int q_id = skey->q_id, *ring_fd;

	bpf_trace_printk(fmt2, sizeof(fmt2));
	ring_fd = bpf_map_lookup_elem(&uring_fd_map, &q_id);
	if (ring_fd) {
		bpf_trace_printk(fmt, sizeof(fmt), qid, skey->tag);
		bpf_ublk_queue_sqe(ctx, sqe, 128, *ring_fd);
		bpf_map_delete_elem(map, key);
	}
	return 0;
}
*/

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
	u8 op; // = ctx->op;
	u32 nr_sectors = ctx->nr_sectors;
	u64 start_sector = ctx->start_sector;
	char fmt_1[] ="ublk_io_prep_prog %d %d\n";

	key.q_id = ctx->q_id;
	key.tag = ctx->tag;
	key.offset = 0;
	key.res = 0;

	bpf_probe_read_kernel(&op, 1, &ctx->op);
	bpf_trace_printk(fmt_1, sizeof(fmt_1), q_id, op);
	sqe = (struct io_uring_sqe *)&sd;
	if (op == REQ_OP_READ) {
		char fmt[] ="add read sae\n";

		bpf_trace_printk(fmt, sizeof(fmt));
		io_uring_prep_read(sqe, target_fd, 0, nr_sectors << 9,
				   start_sector << 9);
		sqe->user_data = build_user_data(ctx->tag, op, 0, 1, 1);
		bpf_map_update_elem(&sqes_map, &key, &sd, BPF_NOEXIST);
	} else if (op == REQ_OP_WRITE) {
		char fmt[] ="add write sae\n";

		bpf_trace_printk(fmt, sizeof(fmt));

		io_uring_prep_write(sqe, target_fd, 0, nr_sectors << 9,
				    start_sector << 9);
		sqe->user_data = build_user_data(ctx->tag, op, 0, 1, 1);
		bpf_map_update_elem(&sqes_map, &key, &sd, BPF_NOEXIST);
	} else {
		;
	}
	return 0;
}

SEC("ublk.s/")
int ublk_io_submit_prog(struct ublk_bpf_ctx *ctx)
{
	struct io_uring_sqe *sqe;
	char fmt[] ="submit sqe for req[qid:%u tag:%u]\n";
	int q_id = ctx->q_id, *ring_fd;
	struct sqe_key key;

	key.q_id = ctx->q_id;
	key.tag = ctx->tag;
	key.offset = 0;
	key.res = 0;

	sqe = bpf_map_lookup_elem(&sqes_map, &key);
	ring_fd = bpf_map_lookup_elem(&uring_fd_map, &q_id);
	if (ring_fd) {
		bpf_trace_printk(fmt, sizeof(fmt), key.q_id, key.tag);
		bpf_ublk_queue_sqe(ctx, sqe, 128, *ring_fd);
		bpf_map_delete_elem(&sqes_map, &key);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
