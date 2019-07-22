
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>


#include <libtlp.h>


#include "util.h"

static int nostdout = 0;

#define pr_info(fmt, ...) do {						\
		if (!nostdout) {					\
			fprintf(stdout, "%s: " fmt, __func__, ##__VA_ARGS__); \
		}							\
	} while(0)

#define pr_warn(fmt, ...) fprintf(stdout, "\x1b[1m\x1b[31m"     \
				  "%s:WARN: " fmt "\x1b[0m",    \
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "%s:ERR: " fmt,	\
				 __func__, ##__VA_ARGS__)


#define MAX_CPUS	16	/* due to NetTLP adapter v0.15.1 */

#define MPS	256	/* Max Payload Size */
#define MRRS	512	/* Max Read Request Size */


#define DMA_DIRECTION_READ	0
#define DMA_DIRECTION_WRITE	1
const char *direction_str[] = { "read", "write" };

#define DMA_REGION_SPLIT_SAME	0
#define DMA_REGION_SPLIT_DIFF	1
const char *split_str[] = { "same", "diff" };

#define DMA_PATTERN_SEQ		0
#define DMA_PATTERN_FIX		1
#define DMA_PATTERN_RANDOM	2
const char *pattern_str[] = { "seq", "fix", "random" };

void usage(void)
{
	printf("usage\n"
	       "  basic parameters\n"
	       "    -r X.X.X.X  remote addr\n"
	       "    -l X.X.X.X   local addr\n"
	       "    -b XX:XX    bus number of requester\n"
	       "\n"
	       "  benchmark DMA parameters\n"
	       "    -d read|write  DMA direction\n"
	       "    -a 0xADDR      DMA target region address (physical)\n"
	       "    -s u_int       DMA target region size\n"
	       "    -L u_int       DMA length (spilited into MPS and MRRS)\n"
	       "\n"
	       "  benchmark style parameters\n"
	       "    -N u_int           number of thread\n"
	       "    -R same|diff       how to split DMA region for threads\n"
	       "    -P fix|seq|random  access pattern on each reagion\n"
	       "\n"
	       "  benchmark options\n"
	       "    -c int   count of interations on each thread\n"
	       "    -i msec  interval for each iteration\n"
	       "\n"
		);
}

/* structure describing benchmark */
struct benchmark {
	/* basic parameters*/
	struct in_addr	remote, local;
	uint16_t	requester;	/* requester number */

	/* DMA parameters*/
	int		direction;	/* DMA direction */
	uintptr_t	region_addr;	/* DMA target region address */
	size_t		region_size;	/* DMA target region size */
	size_t		dma_len;	/* DMA length */

	/* bencharmk parameters */
	int		nthreads;	/* number of threads */
	int		split;		/* region split */
	int		pattern;	/* access pattern*/

	/* benchmark options */
	int		count;		/* count of iterations for bench */
	int		interval;	/* interval between iterations */
};

void print_benchmark(struct benchmark *b)
{
	printf("========= benchmark =========\n");
	printf("-r remote:              %s\n", inet_ntoa(b->remote));
	printf("-l local:               %s\n", inet_ntoa(b->local));
	printf("-b requester:           %02x:%02x\n",
	       (b->requester & 0xFF00) >> 8, b->requester & 0x00FF);

	printf("\n");
	printf("-d direction:           %s\n", direction_str[b->direction]);
	printf("-a DMA region:          0x%#lx\n", b->region_addr);
	printf("-s DMA region size:     %lu\n", b->region_size);
	printf("-L DMA length           %lu\n", b->dma_len);

	printf("\n");
	printf("-N nthreads:            %d\n", b->nthreads);
	printf("-R how to split:        %s\n", split_str[b->split]);
	printf("-P pattern:             %s\n", pattern_str[b->pattern]);

	printf("\n");
	printf("-c count:               %d\n", b->count);
	printf("-i interval:            %d\n", b->interval);

	printf("=============================\n");
}

void benchmark(struct benchmark *b);

int main(int argc, char **argv)
{
	int ch;
	uint16_t busn, devn;
	struct benchmark b;

	/* initialize benchmark parameters with the default values */
	memset(&b, 0, sizeof(b));
	b.region_size = 1024 * 1024 * 256;	/* 256M */
	b.dma_len = 256;
	b.nthreads = 1;

	while ((ch = getopt(argc, argv, "r:l:b:d:a:s:L:N:R:P:c:i:")) != -1) {
		switch (ch) {
		case 'r':
			if (inet_pton(AF_INET, optarg, &b.remote) < 1)
				return -1;
			break;
		case 'l':
			if (inet_pton(AF_INET, optarg, &b.local) < 1)
				return -1;
			break;
		case 'b':
			if (sscanf(optarg, "%hx:%hx", &busn, &devn) != 2) {
				pr_err("invalid bus number '%s'\n", optarg);
				return -1;
			}
			b.requester = ((busn << 8) | devn);
			break;
		case 'd':
			if (strncmp("read", optarg, 4) == 0)
				b.direction = DMA_DIRECTION_READ;
			else if (strncmp("write", optarg, 5) == 0)
				b.direction = DMA_DIRECTION_WRITE;
			else {
				pr_err("invalid direction '%s'\n", optarg);
				return -1;
			}
			break;
		case 'a':
			b.region_addr = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid address '%s'\n", optarg);
				return -1;
			}
			break;
		case 's':
			b.region_size = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid size '%s'\n", optarg);
				return -1;
			}
			break;
		case 'L':
			b.dma_len = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid len '%s'\n", optarg);
				return -1;
			}
			break;
		case 'N':
			b.nthreads = atoi(optarg);
			if (b.nthreads < 1 || b.nthreads > MAX_CPUS) {
				pr_err("invalid thread num '%s'\n", optarg);
				return -1;
			}
			break;
		case 'R':
			if (strncmp("same", optarg, 4) == 0)
				b.split = DMA_REGION_SPLIT_SAME;
			else if(strncmp("diff", optarg, 4) == 0)
				b.split = DMA_REGION_SPLIT_DIFF;
			else {
				pr_err("invalid region split '%s'\n", optarg);
				return -1;
			}
			break;
		case 'P':
			if (strncmp("fix", optarg, 3) == 0)
				b.pattern = DMA_PATTERN_FIX;
			else if (strncmp("seq", optarg, 3) == 0)
				b.pattern = DMA_PATTERN_SEQ;
			else if (strncmp("random", optarg, 5) == 0)
				b.pattern = DMA_PATTERN_RANDOM;
			else {
				pr_err("invalid pattern '%s'\n", optarg);
				return -1;
			}
			break;
		case 'c':
			b.count = atoi(optarg);
			break;
		case 'i':
			b.interval = atoi(optarg);
			if (b.interval < 0) {
				pr_err("invalid interval '%s'\n", optarg);
				return -1;
			}
			break;
		default:
			usage();
			return -1;
		}
	}

	print_benchmark(&b);
	benchmark(&b);

	return 0;
}




/* structure describing nettlp benchmark thread */
struct nettlp_thread {

	struct benchmark *b;

	pthread_t tid;

	/* thread specific parameters */
	struct nettlp nt;
	int		cpu;		/* cpu this thread running on */
	uintptr_t	region_addr;	/* address of DMA target region */
	size_t		region_size;	/* size of DMA target region */

	/* counters */
	uint64_t	ntrans;	/* number of transactions invoked */
	uint64_t	nbytes; /* number of bytes transferred */

	/* benchmark options */
	int	count;	/* count of interations */
};


static int caught_signal = 0;
void sig_handler(int sig)
{
	pr_info("stop benchmark threads\n");
	caught_signal = 1;
}

int count_online_cpus(void)
{
	cpu_set_t cpu_set;
	if (sched_getaffinity(0, sizeof(cpu_set_t), &cpu_set) == 0)
		return CPU_COUNT(&cpu_set);
	return -1;
}


struct counter {
	uint64_t after, before;
};

#define _gather(when, cs, ths, param)			\
	do {						\
		int __n;				\
		for(__n = 0; __n < MAX_CPUS; __n++) {	\
			cs[__n].when = ths[__n].param;	\
		}						\
	} while(0)
#define gather_before(cs, ths, param) _gather(before, cs, ths, param)
#define gather_after(cs, ths, param) _gather(after, cs, ths, param)

#define gather_diff_sum(cs, param, sum)			\
	do {							\
		sum = 0;					\
		int __n;					\
		for(__n = 0; __n < MAX_CPUS; __n++) {		\
			sum += cs[__n].after - cs[__n].before;	\
		}						\
	} while(0)





void *count_thread(void *param)
{
	struct nettlp_thread *ths = param;
	cpu_set_t target_cpu_set;
	struct counter ntrans[MAX_CPUS];
	struct counter nbytes[MAX_CPUS];
	uint64_t ntrans_sum, nbytes_sum;
	uint64_t count = 1;

	/* set this thread on the last cpu */
	CPU_ZERO(&target_cpu_set);
	CPU_SET(count_online_cpus() - 1, &target_cpu_set);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
			       &target_cpu_set);
	
	pr_info("start count thread\n");

	while (1) {
		if (caught_signal)
			break;
		
		gather_before(ntrans, ths, ntrans);
		gather_before(nbytes, ths, nbytes);
		sleep(1);
		gather_after(ntrans, ths, ntrans);
		gather_after(nbytes, ths, nbytes);
		
		gather_diff_sum(ntrans, ntrans, ntrans_sum);
		gather_diff_sum(nbytes, nbytes, nbytes_sum);

		printf("%4lu: %lu bps\n", count, nbytes_sum * 8);
		printf("%4lu: %lu tps\n", count, ntrans_sum);
		count++;
	}

	return NULL;
}

uintptr_t next_target_addr(uintptr_t current, uintptr_t start, uintptr_t end,
			   size_t len, int pattern)
{
	/*
	 * @current: current target address
	 * @start: start of region
	 * @end: end of region
	 * @len: dma length
	 * @int: access pattern
	 */

	switch (pattern) {

	case DMA_PATTERN_SEQ:
		return (current + len > end) ? start : current + len;

	case DMA_PATTERN_FIX:
		return current;

	case DMA_PATTERN_RANDOM:
		return (((rand() % (end - start - len)) + start) >> 12) << 12;

	default:
		pr_err("invalid access pattern\n");
		exit(1);
	}
	
	/* not reached */
	return 0;
}


void *benchmark_thread(void *param)
{
	struct nettlp_thread *th = param;
	uintptr_t addr;
	size_t dma_len, one_dma_len, len;
	ssize_t ret;
	char buf[MPS * 2];	/* x2 is just a buffer */
	cpu_set_t target_cpu_set;
	ssize_t (*dma)(struct nettlp *nt, uintptr_t addr,
		       void *buf, size_t count);

	CPU_ZERO(&target_cpu_set);
	CPU_SET(th->cpu, &target_cpu_set);
	pthread_setaffinity_np(th->tid, sizeof(cpu_set_t), &target_cpu_set);

	pr_info("start on cpu %d, address %#lx, size %lu, len %lu\n",
		th->cpu, th->region_addr, th->region_size, th->b->dma_len);

	switch (th->b->direction) {
	case DMA_DIRECTION_READ:
		one_dma_len = MRRS;
		dma = dma_read;
		break;
	case DMA_DIRECTION_WRITE:
		one_dma_len = MPS;
		dma = dma_write;
		break;
	default:
		pr_err("invalid direction on cpu %d\n", th->cpu);
		return NULL;
	}

	addr = th->region_addr;
	dma_len = th->b->dma_len;

	while (1) {

		if (caught_signal)
			break;

		len = dma_len < one_dma_len ? dma_len : one_dma_len;
		ret = dma(&th->nt, addr, buf, len);
		if (ret < 0) {
			fprintf(stderr,
				"dma error on cpu %d. "
				"addr %#lx, len %lu: %s\n",
				th->cpu, addr, len, strerror(errno));
			return NULL;
			goto next;
		}

		th->ntrans++;
		th->nbytes += ret;
		dma_len -= ret;
		addr = next_target_addr(addr, th->region_addr,
					th->region_addr + th->region_size,
					th->b->dma_len, th->b->pattern);

		if (dma_len == 0) {
			/* 1 transaction finished */
			dma_len = th->b->dma_len;
		}

	next:
		if (th->count > 0) {
			th->count--;
			if (th->count == 0)
				break;
		}

		if (th->b->interval)
			usleep(th->b->interval * 1000);
	}

	return NULL;
}

void benchmark(struct benchmark *b)
{
	int n;
	pthread_t ctid;	/* count_thread tid */
	struct nettlp_thread ths[MAX_CPUS];

	if (pthread_create(&ctid, NULL, count_thread, ths) < 0) {
		pr_err("failed to create count thread\n");
		perror("pthread_create");
		exit(-1);
	}

	memset(ths, 0, sizeof(ths));

	for (n = 0; n < b->nthreads; n++) {
		struct nettlp_thread *th = &ths[n];

		th->b = b;

		/* initialize nettlp for this thread */
		th->nt.remote_addr = b->remote;
		th->nt.local_addr = b->local;
		th->nt.requester = b->requester;
		th->nt.tag = n;	/* XXX */
		if (nettlp_init(&th->nt) < 0) {
			perror("nettlp_init");
			return;
		}

		/* fill the thread-specific parameters */
		th->cpu = n;	/* XXX */
		th->count = b->count;
		if (b->split == DMA_REGION_SPLIT_SAME) {
			th->region_addr = b->region_addr;
			th->region_size = b->region_size;
		} else if (b->split == DMA_REGION_SPLIT_DIFF) {
			th->region_addr = ((b->region_addr +
					    b->region_size / b->nthreads * n)
					   >> 12) << 12; /* 4k-byte align */
			th->region_size = b->region_size / b->nthreads;
		} else {
			pr_err("invalid region split pattern\n");
			return;
		}
		
		if (pthread_create(&th->tid, NULL, benchmark_thread, th) < 0) {
			pr_err("failed to create thread for cpu %d\n", n);
			perror("pthread_create");
			return;
		}

		usleep(20);	/* to serialize start output on each thread */
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("cannot set seginal\n");
		return;
	}
	
	for (n = 0; n < b->nthreads; n++)
		pthread_join(ths[n].tid, NULL);
		
	pthread_join(ctid, NULL);

	return;
}
