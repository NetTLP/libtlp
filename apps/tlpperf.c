
#define _GNU_SOURCE

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include "thread_affinity_apple.h"

/* use superpage instead of hugepage */
#define MAP_LOCKED	0
#define MAP_HUGETLB	VM_FLAGS_SUPERPAGE_SIZE_2MB
#endif

#include <libtlp.h>


#include "util.h"

static int nostdout = 0;
static int debug = 0;

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

#define pr_debug(fmt, ...) do {						\
		if (debug) {						\
			fprintf(stdout, "%s:DEBUG: " fmt,		\
				__func__, ##__VA_ARGS__);		\
		}							\
	} while(0)


#define MAX_CPUS	16	/* due to NetTLP adapter v0.15.1 */

#define MPS	256	/* Max Payload Size */
#define MRRS	512	/* Max Read Request Size */



/* target mode */

static uintptr_t phy_addr(void *virt) {
	uintptr_t entry = 0;
	long pagesize;
	ssize_t rc;
	off_t ret;
	int fd;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		err(1, "open /proc/self/pagemap: %s\n", strerror(errno));

	pagesize = sysconf(_SC_PAGESIZE);

	ret = lseek(fd, (uintptr_t)virt / pagesize * sizeof(uintptr_t),
		    SEEK_SET);
	if (ret < 0)
		err(1, "lseek for /proc/self/pagemap: %s\n", strerror(errno));


	rc = read(fd, &entry, sizeof(entry));
	if (rc < 1 || entry == 0)
		err(1, "read for /proc/self/pagemap: %s\n", strerror(errno));

	close(fd);

	return (entry & 0x7fffffffffffffULL) * pagesize +
		   ((uintptr_t)virt) % pagesize;
}


void tlpperf_target_mode(size_t target_size)
{
	/* target mode allocates 'size'-byte hugepage and wait forever */
	void *mem;
	uintptr_t paddr;
	size_t size = ((target_size >> 12) + 1) << 12;

	mem = mmap(0, size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED | MAP_HUGETLB,
		   -1, 0);
	if (mem == MAP_FAILED) {
		pr_err("failed to allocate %lu-byte from hugepage\n", size);
		perror("mmap");
		return;
	}

	paddr = phy_addr(mem);
	printf("%lu-byte allocated, physical address is %#lx\n", size, paddr);

	while (1)
		sleep(1);
}


/* benchmark mode */

#define DMA_DIRECTION_READ	0
#define DMA_DIRECTION_WRITE	1
const char *direction_str[] = { "read", "write" };

#define DMA_REGION_SPLIT_SAME	0
#define DMA_REGION_SPLIT_DIFF	1
const char *split_str[] = { "same", "diff" };

#define DMA_PATTERN_SEQ		0
#define DMA_PATTERN_SEQ512	1
#define DMA_PATTERN_FIX		2
#define DMA_PATTERN_RANDOM	3
const char *pattern_str[] = { "seq", "seq512", "fix", "random" };

void usage(void)
{
	printf("tlpperf usage\n"
	       "\n"
	       "  basic parameters\n"
	       "    -r X.X.X.X  remote addr\n"
	       "    -l X.X.X.X  local addr\n"
	       "    -b XX:XX    bus number of requester\n"
	       "\n"
	       "  DMA parameters\n"
	       "    -d read|write  DMA direction\n"
	       "    -a 0xADDR      DMA target region address (physical)\n"
	       "    -s u_int       DMA target region size\n"
	       "    -L u_int       DMA length (spilited into MPS and MRRS)\n"
	       "\n"
	       "  benchmark style parameters\n"
	       "    -N u_int                  number of thread\n"
	       "    -R same|diff              how to split DMA region for threads\n"
	       "    -P fix|seq|seq512|random  access pattern on each reagion\n"
	       "    -M                        measuring latency mode\n"
	       "\n"
	       "  options\n"
	       "    -c int   count of interations on each thread\n"
	       "    -i msec  interval for each iteration\n"
	       "    -t sec   duration\n"
	       "    -D       debug mode\n"
	       "\n"
	       "  for target host\n"
	       "    -S size  size to allocate hugepage as tlpperf target\n"
		);
}

/* structure describing tlpperf */
struct tlpperf {
	/* basic parameters*/
	struct in_addr	remote, local;
	uint16_t	requester;	/* requester number */

	/* DMA parameters*/
	int		direction;	/* DMA direction */
	uintptr_t	region_addr;	/* DMA target region address */
	size_t		region_size;	/* DMA target region size */
	size_t		dma_len;	/* DMA length */

	/* bencharmk style parameters */
	int		nthreads;	/* number of threads */
	int		split;		/* region split */
	int		pattern;	/* access pattern*/
	int		latency_mode;	/* latency measurement mode */

	/* benchmark options */
	int		count;		/* count of iterations for bench */
	int		interval;	/* interval between iterations */
	int		duration;	/* benchmark duration */
};

static struct tlpperf *tlpperf;


void print_tlpperf(struct tlpperf *t)
{
	printf("============ tlpperf ============\n");
	printf("-r remote:              %s\n", inet_ntoa(t->remote));
	printf("-l local:               %s\n", inet_ntoa(t->local));
	printf("-b requester:           %02x:%02x\n",
	       (t->requester & 0xFF00) >> 8, t->requester & 0x00FF);

	printf("\n");
	printf("-d direction:           %s\n", direction_str[t->direction]);
	printf("-a DMA region:          %#lx\n", t->region_addr);
	printf("-s DMA region size:     %lu\n", t->region_size);
	printf("-L DMA length           %lu\n", t->dma_len);

	printf("\n");
	printf("-N nthreads:            %d\n", t->nthreads);
	printf("-R how to split:        %s\n", split_str[t->split]);
	printf("-P pattern:             %s\n", pattern_str[t->pattern]);
	printf("-M latency mode:        %s\n", t->latency_mode ? "on" : "off");

	printf("\n");
	printf("-c count:               %d\n", t->count);
	printf("-i interval:            %d\n", t->interval);
	printf("-t duration             %d\n", t->duration);
	printf("-D debug:               %s\n", debug ? "on" : "off");

	printf("=================================\n");
}

void benchmark(struct tlpperf *t);

int main(int argc, char **argv)
{
	int ch;
	uint16_t busn, devn;
	size_t target_size = 0;
	struct tlpperf t;

	tlpperf = &t;

	/* initialize benchmark parameters with the default values */
	memset(&t, 0, sizeof(t));
	t.region_size = 1024 * 1024 * 8;	/* 8M */
	t.dma_len = 256;
	t.nthreads = 1;

	while ((ch = getopt(argc, argv, "r:l:b:d:a:s:L:N:R:P:Mc:i:t:DS:"))
	       != -1) {
		switch (ch) {
		case 'r':
			if (inet_pton(AF_INET, optarg, &t.remote) < 1)
				return -1;
			break;
		case 'l':
			if (inet_pton(AF_INET, optarg, &t.local) < 1)
				return -1;
			break;
		case 'b':
			if (sscanf(optarg, "%hx:%hx", &busn, &devn) != 2) {
				pr_err("invalid bus number '%s'\n", optarg);
				return -1;
			}
			t.requester = ((busn << 8) | devn);
			break;
		case 'd':
			if (strncmp("read", optarg, 4) == 0)
				t.direction = DMA_DIRECTION_READ;
			else if (strncmp("write", optarg, 5) == 0)
				t.direction = DMA_DIRECTION_WRITE;
			else {
				pr_err("invalid direction '%s'\n", optarg);
				return -1;
			}
			break;
		case 'a':
			t.region_addr = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid address '%s'\n", optarg);
				return -1;
			}
			break;
		case 's':
			t.region_size = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid size '%s'\n", optarg);
				return -1;
			}
			break;
		case 'L':
			t.dma_len = strtoul(optarg, NULL, 0);
			if (errno == ERANGE) {
				pr_err("invalid len '%s'\n", optarg);
				return -1;
			}
			break;
		case 'N':
			t.nthreads = atoi(optarg);
			if (t.nthreads < 1 || t.nthreads > MAX_CPUS) {
				pr_err("invalid thread num '%s'\n", optarg);
				return -1;
			}
			break;
		case 'R':
			if (strncmp("same", optarg, 4) == 0)
				t.split = DMA_REGION_SPLIT_SAME;
			else if(strncmp("diff", optarg, 4) == 0)
				t.split = DMA_REGION_SPLIT_DIFF;
			else {
				pr_err("invalid region split '%s'\n", optarg);
				return -1;
			}
			break;
		case 'P':
			if (strncmp("fix", optarg, 3) == 0)
				t.pattern = DMA_PATTERN_FIX;
			else if (strncmp("seq512", optarg, 6) == 0)
				t.pattern = DMA_PATTERN_SEQ512;
			else if (strncmp("seq", optarg, 3) == 0)
				t.pattern = DMA_PATTERN_SEQ;
			else if (strncmp("random", optarg, 5) == 0)
				t.pattern = DMA_PATTERN_RANDOM;
			else {
				pr_err("invalid pattern '%s'\n", optarg);
				return -1;
			}
			break;
		case 'M':
			t.latency_mode = 1;
			break;
		case 'c':
			t.count = atoi(optarg);
			break;
		case 'i':
			t.interval = atoi(optarg);
			if (t.interval < 0) {
				pr_err("invalid interval '%s'\n", optarg);
				return -1;
			}
			break;
		case 't':
			t.duration = atoi(optarg);
			break;
		case 'D':
			debug = 1;
			break;

		case 'S':
			target_size = strtoul(optarg, NULL, 0);
			tlpperf_target_mode(target_size);
			return 0;
		default:
			usage();
			return -1;
		}
	}

	print_tlpperf(&t);
	benchmark(&t);

	return 0;
}




/* structure describing tlpperf thread */
struct tlpperf_thread {

	struct tlpperf *t;

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
void stop_all(int sig)
{
	pr_info("stopping...\n");
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
	struct tlpperf_thread *ths = param;
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

#ifdef __APPLE__
		printf("%4llu: %llu bps\n", count, nbytes_sum * 8);
		printf("%4llu: %llu tps\n", count, ntrans_sum);
#else
		printf("%4lu: %lu bps\n", count, nbytes_sum * 8);
		printf("%4lu: %lu tps\n", count, ntrans_sum);
#endif
		count++;

		if (tlpperf->duration > 0) {
			tlpperf->duration--;
			if (tlpperf->duration == 0)
				stop_all(0);
		}
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

	case DMA_PATTERN_SEQ512:
		return (current + 512 > end) ? start : current + 512;

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

unsigned long get_usec_elapsed(struct timeval start, struct timeval end)
{
	 unsigned long usec;
	 if (end.tv_usec < start.tv_usec) {
		  end.tv_usec += 1000000;
		  end.tv_sec -= 1;
	 }

	 usec = (end.tv_sec - start.tv_sec) * 1000000 +
		 end.tv_usec - start.tv_usec;
	 return usec;
}


void *benchmark_thread(void *param)
{
	struct tlpperf_thread *th = param;
	uintptr_t addr;
	size_t dma_len, one_dma_len, len;
	ssize_t ret;
	char buf[MPS * 2];	/* x2 is just a buffer */
	cpu_set_t target_cpu_set;
	ssize_t (*dma)(struct nettlp *nt, uintptr_t addr,
		       void *buf, size_t count);
	struct timeval start, end;	/* for latency mode */

	CPU_ZERO(&target_cpu_set);
	CPU_SET(th->cpu, &target_cpu_set);
	pthread_setaffinity_np(th->tid, sizeof(cpu_set_t), &target_cpu_set);

	pr_info("start on cpu %d, address %#lx, size %lu, len %lu\n",
		th->cpu, th->region_addr, th->region_size, th->t->dma_len);

	switch (th->t->direction) {
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
	dma_len = th->t->dma_len;

	while (1) {

		if (caught_signal)
			break;

		pr_debug("DMA to %#lx, cpu %d\n", addr, th->cpu);

		len = dma_len < one_dma_len ? dma_len : one_dma_len;

		if (tlpperf->latency_mode)
			gettimeofday(&start, NULL);

		ret = dma(&th->nt, addr, buf, len);

		if (tlpperf->latency_mode)
			gettimeofday(&end, NULL);

		if (ret < 0) {
			fprintf(stderr,
				"dma error on cpu %d. "
				"addr %#lx, len %lu: %s\n",
				th->cpu, addr, len, strerror(errno));
			return NULL;
			goto next;
		}

		if (tlpperf->latency_mode) {
			printf("latency: cpu on %d, %lu usec\n",
			       th->cpu, get_usec_elapsed(start, end));
		}

		th->ntrans++;
		th->nbytes += ret;
		dma_len -= ret;
		addr = next_target_addr(addr, th->region_addr,
					th->region_addr + th->region_size,
					th->t->dma_len, th->t->pattern);

		if (dma_len == 0) {
			/* 1 transaction finished */
			dma_len = th->t->dma_len;
		}

	next:
		if (th->count > 0) {
			th->count--;
			if (th->count == 0)
				break;
		}

		if (th->t->interval)
			usleep(th->t->interval * 1000);
	}

	return NULL;
}

void benchmark(struct tlpperf *t)
{
	int n;
	pthread_t ctid;	/* count_thread tid */
	struct tlpperf_thread ths[MAX_CPUS];

	if (pthread_create(&ctid, NULL, count_thread, ths) < 0) {
		pr_err("failed to create count thread\n");
		perror("pthread_create");
		exit(-1);
	}

	memset(ths, 0, sizeof(ths));

	for (n = 0; n < t->nthreads; n++) {
		struct tlpperf_thread *th = &ths[n];

		th->t = t;

		/* initialize nettlp for this thread */
		th->nt.remote_addr = t->remote;
		th->nt.local_addr = t->local;
		th->nt.requester = t->requester;
		th->nt.tag = n;	/* XXX */
		if (nettlp_init(&th->nt) < 0) {
			perror("nettlp_init");
			return;
		}

		/* fill the thread-specific parameters */
		th->cpu = n;	/* XXX */
		th->count = t->count;
		if (t->split == DMA_REGION_SPLIT_SAME) {
			th->region_addr = t->region_addr;
			th->region_size = t->region_size;
		} else if (t->split == DMA_REGION_SPLIT_DIFF) {
			th->region_addr = ((t->region_addr +
					    t->region_size / t->nthreads * n)
					   >> 12) << 12; /* 4k-byte align */
			th->region_size = t->region_size / t->nthreads;
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

	if (signal(SIGINT, stop_all) == SIG_ERR) {
		perror("cannot set seginal\n");
		return;
	}
	
	for (n = 0; n < t->nthreads; n++)
		pthread_join(ths[n].tid, NULL);
		
	pthread_join(ctid, NULL);

	return;
}
