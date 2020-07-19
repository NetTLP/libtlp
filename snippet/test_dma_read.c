#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <libtlp.h>

#include "util.h"

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -b bus number, XX:XX\n"
	       "    -t tag\n"
	       "    -a target address\n"
	       "    -s transfer size (default 4-byte)\n"
		);
}

int main(int argc, char **argv)
{
	int ret, ch, size;
	struct nettlp nt;
	uintptr_t addr;
	uint16_t busn, devn;
	char buf[4096];

	memset(&nt, 0, sizeof(nt));
	size = 4;
	addr = 0;
	busn = 0;
	devn = 0;

	while ((ch = getopt(argc, argv, "r:l:b:t:a:s:")) != -1) {
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

		case 't':
			nt.tag = atoi(optarg);
			break;

		case 'a':
			ret = sscanf(optarg, "0x%lx", &addr);
			break;

		case 's':
			size = atoi(optarg);
			if (size < 1 || size > 4096) {
				fprintf(stderr, "size must be 0 > | < 4096\n");
				return -1;
			}
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

	memset(buf, 0, sizeof(buf));


	ret = dma_read(&nt, addr, buf, size);

	printf("tlp_length is %u\n", tlp_calculate_length(addr, size));


	printf("\n\n");
	printf("dma_read returns %d\n", ret);
	printf("\n");
	printf("Last 0x%x, 1st 0x%x\n",
	       tlp_calculate_lstdw(addr, size),
	       tlp_calculate_fstdw(addr, size));

	printf("dma_read returns %d\n", ret);
	if (ret < 0)
		perror("dma_read");


	if (ret > 0)
		hexdump(buf, size);


	return 0;
}
