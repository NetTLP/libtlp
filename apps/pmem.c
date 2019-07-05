#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <libtlp.h>

#include "util.h"

#define pr_info(fmt, ...) fprintf(stdout, "%s: " fmt, \
                                  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stdout, "\x1b[1m\x1b[31m"     \
                                  "%s:WARN: " fmt "\x1b[0m",    \
                                  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "%s:ERR: " fmt,        \
                                 __func__, ##__VA_ARGS__)

#define MAXPAYLOADSIZE	256

struct pmem {
	uintptr_t addr;
	size_t size;
	void *mem;
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

	/* CplD packet */
	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &ch;
	iov[1].iov_len = sizeof(ch);

	len = tlp_length(mh->tlp.falen) << 2;
	addr = tlp_mr_addr(mh);
	data_len = tlp_mwr_data_length(mh);	/* actuary transfer data len */

	if (addr < p->addr || addr + len > p->addr + p->size) {
		pr_err("MRd request stick out of the pseudo memory region\n");
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

		len -= send_len;
		addr = ((addr >> 2) << 2) + send_len;
		data_len -= send_len;

		ret = writev(nt->sockfd, iov, 3);
		if (ret < 0) {
			pr_err("writev failed\n");
			perror("writev");
		}

	} while (len > 0);

	return 0;
}

int pmem_mwr(struct nettlp *nt, struct tlp_mr_hdr *mh,
	     void *m, size_t count, void *arg)
{
	struct pmem *p = arg;
	uintptr_t addr;
	
	addr = tlp_mr_addr(mh);
	
	pr_info("MWr to %#lx, %lu byte\n", addr, count);

	if (addr < p->addr || addr + count > p->addr + p->size) {
		pr_err("MWr stick out of the pseudo memory region\n");
		send_cpl_abort(nt, mh);
		return -1;
	}

	memcpy(p->mem + (addr - p->addr), m, count);

	return 0;
}

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -R remote port (default 14198)\n"
	       "    -L local port (default 14198)\n"
	       "    -b bus number, XX:XX\n"
	       "    -a start addess (HEX)\n"
		);
}

int main(int argc, char **argv)
{
	int ret, ch;
	struct pmem pmem;
	struct nettlp nt;
	struct nettlp_cb cb;
	uintptr_t addr;
	uint16_t busn, devn;

	memset(&nt, 0, sizeof(nt));
	nt.remote_port = 14198;
	nt.local_port = 14198;
	addr = 0;
	busn = 0;
	devn = 0;

	while ((ch = getopt(argc, argv, "r:l:R:L:b:t:a:")) != -1) {
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

		case 'R':
			nt.remote_port = atoi(optarg);
			break;

		case 'L':
			nt.local_port = atoi(optarg);
			break;

		case 'b':
			ret = sscanf(optarg, "%hx:%hx", &busn, &devn);
			nt.requester = (busn << 8 | devn);
			break;

		case 't':
			nt.tag = atoi(optarg);
			break;

		case 'a':
			ret = sscanf(optarg, "0x%lx", &addr);
			break;
		default :
			usage();
			return -1;
		}
	}

	ret = nettlp_init(&nt);
	if (ret < 0) {
		perror("nettlp_init");
		return ret;
	}
	dump_nettlp(&nt);

	pmem.addr = addr;
	pmem.mem = malloc(1024 * 1024 * 256);	/* 256MB */
	pmem.size = 1024 * 1024 * 256;

	memset(&cb, 0, sizeof(cb));
	cb.mrd = pmem_mrd;
	cb.mwr = pmem_mwr;

	printf("start pmem callback, start address is 0x%#lx\n", addr);

	nettlp_run_cb(&nt, &cb, &pmem);

	return 0;
}
