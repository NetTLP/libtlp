
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
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

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include "thread_affinity_apple.h"
#endif

static int nostdout = 0;
static int nohex = 0;
static int mrd_sleep = 0;

#define pr_info(fmt, ...) do {						\
		if (!nostdout) {					\
			fprintf(stdout, "%s: " fmt, __func__, ##__VA_ARGS__); \
		}							\
	} while(0)

#define pr_warn(fmt, ...) fprintf(stdout, "\x1b[1m\x1b[31m"     \
                                  "%s:WARN: " fmt "\x1b[0m",    \
                                  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "%s:ERR: " fmt,        \
                                 __func__, ##__VA_ARGS__)


#define MAXPAYLOADSIZE	256




void build_pkt(void *buf, int len, unsigned int id)
{
	struct ether_header *eth;
	struct ip *ip;
	struct udphdr *udp;

	memset(buf, 0, len);

	eth = (struct ether_header *)buf;
	eth->ether_shost[0] = 0x01;
	eth->ether_shost[1] = 0x02;
	eth->ether_shost[2] = 0x03;
	eth->ether_shost[3] = 0x04;
	eth->ether_shost[4] = 0x05;
	eth->ether_shost[5] = 0x06;

	eth->ether_dhost[0] = 0xff;
	eth->ether_dhost[1] = 0xff;
	eth->ether_dhost[2] = 0xff;
	eth->ether_dhost[3] = 0xff;
	eth->ether_dhost[4] = 0xff;
	eth->ether_dhost[5] = 0xff;

	eth->ether_type = htons(ETHERTYPE_IP);

	ip = (struct ip*)(eth + 1);
	ip->ip_v	= IPVERSION;
	ip->ip_hl       = 5;
	ip->ip_id       = 0;
	ip->ip_tos      = 0;
	ip->ip_len      = htons(len - sizeof(*eth));
	ip->ip_off      = 0;
	ip->ip_ttl      = 16;
	ip->ip_p	= IPPROTO_UDP;
	ip->ip_sum      = 0;
	ip->ip_src.s_addr = inet_addr("10.0.0.2");
	ip->ip_dst.s_addr = inet_addr("10.0.0.1");


	udp = (struct udphdr*)(ip + 1);
	udp->uh_ulen    = htons(len - sizeof(*eth) - sizeof(*ip));
	udp->uh_dport   = htons(60000);
	udp->uh_sport   = htons(id);
	udp->uh_sum     = 0;
}

void initialize_with_packets(void *p, int pktlen, int pktnum)
{
	int n;

	for (n = 0; n < pktlen; n++)
		build_pkt(p + (2048 * n), pktlen, 0);
}


struct pmem {
	uintptr_t addr;
	size_t size;
	void *mem;
};

struct pmem_thread {
	pthread_t tid;
	struct nettlp nt;
	struct pmem *pmem;
	struct nettlp_cb *cb;
};

int send_cpl_abort(struct nettlp *nt, struct tlp_mr_hdr *mh)
{
	return 0;
}



int pmem_mrd(struct nettlp *nt, struct tlp_mr_hdr *mh, void *arg)
{
	int ret;
	struct pmem *p = arg;
	ssize_t len, data_len;
	uintptr_t addr;
	struct nettlp_hdr nh;
	struct tlp_cpl_hdr ch;
	struct iovec iov[3];

	usleep(mrd_sleep);

	/* CplD packet */
	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &ch;
	iov[1].iov_len = sizeof(ch);

	len = tlp_length(mh->tlp.falen) << 2;
	addr = tlp_mr_addr(mh);
	data_len = tlp_mr_data_length(mh);	/* actuary transfer data len */

	pr_info("MRd to 0x%lx, tag 0x%02x %lu byte\n",
		(addr >> 2) << 2, mh->tag, data_len);

	if (addr < p->addr || addr + len > p->addr + p->size) {
		pr_err("MRd request to 0x%lx, "
		       "stick out of the pseudo memory region\n", addr);
		send_cpl_abort(nt, mh);
		return -1;
	}

	do {
		ssize_t send_len;
		send_len = len < MAXPAYLOADSIZE ? len : MAXPAYLOADSIZE;
		
		memset(&nh, 0, sizeof(nh));
		memset(&ch, 0, sizeof(ch));

		/* XXX: copy flag and attribute. should handle properly */
		memcpy(&ch.tlp, &mh->tlp, sizeof(struct tlp_hdr));

		/* Build CplD header */
		tlp_set_fmt(ch.tlp.fmt_type, TLP_FMT_3DW, TLP_FMT_W_DATA);
		tlp_set_type(ch.tlp.fmt_type, TLP_TYPE_Cpl);
		tlp_set_length(ch.tlp.falen, send_len >> 2);
		tlp_set_cpl_status(ch.stcnt, TLP_CPL_STATUS_SC);
		tlp_set_cpl_bcnt(ch.stcnt, data_len);
		ch.completer = htons(nt->requester);
		ch.requester = mh->requester;
		ch.tag = mh->tag;
		ch.lowaddr = addr & 0x7F;

		/* memory to be sent */
		iov[2].iov_base = p->mem + (((addr >> 2) << 2) - p->addr);
		iov[2].iov_len = send_len;

		ret = writev(nt->sockfd, iov, 3);
		if (ret < 0) {
			pr_err("writev failed\n");
			perror("writev");
		}

		len -= send_len;
		data_len -= send_len - (addr & 0x3);
		addr = ((addr >> 2) << 2) + send_len;

	} while (data_len > 0);

	return 0;
}

int pmem_mwr(struct nettlp *nt, struct tlp_mr_hdr *mh,
	     void *m, size_t count, void *arg)
{
	struct pmem *p = arg;
	uintptr_t addr;
	
	addr = tlp_mr_addr(mh);
	
	pr_info("MWr to 0x%lx, tag 0x%02x, %lu byte\n", addr, mh->tag, count);

	if (addr < p->addr || addr + count > p->addr + p->size) {
		pr_err("MWr request to 0x%lx, "
		       "stick out of the pseudo memory region\n", addr);
		send_cpl_abort(nt, mh);
		return -1;
	}

	if (!nohex && !nostdout)
		hexdump(m, count);

	memcpy(p->mem + (addr - p->addr), m, count);

	return 0;
}


int count_online_cpus(void)
{
	cpu_set_t cpu_set;

	if (sched_getaffinity(0, sizeof(cpu_set_t), &cpu_set) == 0)
		return CPU_COUNT(&cpu_set);

	return -1;
}

void sig_handler(int sig)
{
	pr_info("stop callbacks\n");
	nettlp_stop_cb();	/* stop all callbacks */
}

void *nettlp_cb_thread(void *arg)
{
	struct pmem_thread *pt = arg;
	int cpu = pt->nt.tag % count_online_cpus();
	cpu_set_t target_cpu_set;
	struct nettlp *nt = &pt->nt;
	
	CPU_ZERO(&target_cpu_set);
	CPU_SET(cpu, &target_cpu_set);
	pthread_setaffinity_np(pt->tid, sizeof(cpu_set_t), &target_cpu_set);

	pr_info("start callback on cpu %d, port %u\n", cpu, pt->nt.port);
	nettlp_run_cb(&(nt), 1, pt->cb, pt->pmem);

	return NULL;
}

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr at NetTLP link\n"
	       "    -l local addr at NetTLP link\n"
	       "\n"
	       "    -R remote host addr to get BAR4 start address\n"
	       "    or\n"
	       "    -a start addess (HEX)\n"
	       "    -b bus number, XX:XX\n"
	       "\n"
	       "  initialize with packets options\n"
	       "    -n nuber of packets\n"
	       "    -s packet size\n"
	       "\n"
	       "  testing options\n"
	       "    -m sleep on mrd (usec)\n"
	       "\n"
	       "  output options\n"
	       "    -H no hexdump\n"
	       "    -S no stdout\n"
		);
}

int main(int argc, char **argv)
{

#define NTHREADS	16	/* adapter v0.15.1 uses tag & 0xF for ports */

	int ret, ch, n;
	struct in_addr remote_host;
	struct pmem pmem;
	struct nettlp nt;	/* the original nettlp */
	struct nettlp_cb cb;
	struct pmem_thread pth[NTHREADS];
	uintptr_t addr;
	uint16_t busn, devn;
	int pktnum, pktlen;

	memset(&nt, 0, sizeof(nt));
	addr = 0;
	busn = 0;
	devn = 0;

	pktnum = 0;
	pktlen = 0;

	while ((ch = getopt(argc, argv, "r:l:b:R:a:m:HSn:s:")) != -1) {
		switch (ch) {
		case 'r':
			ret = inet_pton(AF_INET, optarg, &nt.remote_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'l':
			ret = inet_pton(AF_INET, optarg, &nt.local_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'b':
			ret = sscanf(optarg, "%hx:%hx", &busn, &devn);
			nt.requester = (busn << 8 | devn);
			break;

		case 'R':
			ret = inet_pton(AF_INET, optarg, &remote_host);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}

			addr = nettlp_msg_get_bar4_start(remote_host);
			if (addr == 0) {
				perror("nettlp_msg_get_bar4_start");
				return -1;
			}

			nt.requester = nettlp_msg_get_dev_id(remote_host);
			break;

		case 'a':
			ret = sscanf(optarg, "0x%lx", &addr);
			break;

		case 'm':
			mrd_sleep = atoi(optarg);
			break;

		case 'H':
			nohex = 1;
			break;

		case 'S':
			nostdout = 1;
			break;

		case 'n':
			pktnum = atoi(optarg);
			break;

		case 's':
			pktlen = atoi(optarg);
			break;

		default :
			usage();
			return -1;
		}
	}

	/* initalize pmem area and callback */
	pmem.addr = addr;
	pmem.mem = malloc(1024 * 1024 * 256);	/* 256MB */
	pmem.size = 1024 * 1024 * 256;

	memset(&cb, 0, sizeof(cb));
	cb.mrd = pmem_mrd;
	cb.mwr = pmem_mwr;

	if (pktnum > 0 && pktlen >= 60) {
		if (pktlen > 2048) {
			pr_err("too large packet size. must be <= 2048\n");
			return -1;
		}

		pr_info("initalize the region with %d %d-byte packets\n",
			pktnum, pktlen);
		initialize_with_packets(pmem.mem, pktlen, pktnum);
	}

	printf("start pmem callbacks. BAR4 is %#lx, Dev is 0x%x\n",
	       addr, nt.requester);

	/* initalize and start threads on each port 0x3000 + 0x0 ~ 0xF */
	for (n = 0; n < NTHREADS; n++) {
		pth[n].pmem = &pmem;
		pth[n].cb = &cb;
		pth[n].nt = nt;
		pth[n].nt.tag = n;

		ret = nettlp_init(&pth[n].nt);
		if (ret < 0) {
			pr_err("nettlp_init for tag %u failed", pth[n].nt.tag);
			perror("nettlp_init");
			return ret;
		}

		ret = pthread_create(&pth[n].tid, NULL, nettlp_cb_thread,
				     &pth[n]);
		if (ret < 0) {
			pr_err("failed to create thread for cpu %u",
			       pth[n].nt.tag);
			perror("pthread_create");
			return ret;
		}

		usleep(20);	/*XXX: to serialiez start output on threads */
	}

	/* set signal handler to stop callback threads */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("cannot set signal\n");
		return -1;
	}

	/* thread join */
	for (n = 0; n < NTHREADS; n++)
		pthread_join(pth[n].tid, NULL);

	return 0;
}
