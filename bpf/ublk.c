// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ublk.skel.h"

static void ublk_ebp_prep(struct ublk_bpf **pobj)
{
	struct ublk_bpf *obj;
	int ret, prog_fds;

	obj = ublk_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		exit(1);
	}
	ret = ublk_bpf__load(obj);
	if (ret) {
		fprintf(stderr, "failed to load BPF object: %d\n", ret);
		exit(1);
	}

	prog_fds = bpf_program__fd(obj->progs.ublk_io_prep_prog);
	*pobj = obj;


	ret = bpf_map__set_max_entries(obj->maps.uring_fd_map, 16);

	printf("prog_fds: %d\n", prog_fds);
}

static int ublk_ebpf_test(void)
{
	struct ublk_bpf *obj;

	ublk_ebp_prep(&obj);
	sleep(5);
	ublk_bpf__destroy(obj);
	return 0;
}

int main(int arg, char **argv)
{
	fprintf(stderr, "test1() ============\n");
	ublk_ebpf_test();

	return 0;
}
