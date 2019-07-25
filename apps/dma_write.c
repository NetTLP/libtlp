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
	       "    -a dma address, 0xHEXADDR\n"
	       "    -s size\n"
	       "    -p payload as ascii string (default )\n"
	       "    -m MaxPayloadSize\n"
		);
}

int main(int argc, char **argv)
{
	int ret, ch, size, mps;
	struct nettlp nt;
	uintptr_t addr;
	uint16_t busn, devn;
	char buf[4096];

	memset(&nt, 0, sizeof(nt));
	addr = 0;
	busn = 0;
	devn = 0;
	mps = 0;

	size = 0;

	while ((ch = getopt(argc, argv, "r:l:b:t:a:s:p:m:")) != -1) {
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

		case 'p':
			strncpy(buf, optarg, sizeof(buf));
			break;

		case 's':
			size = atoi(optarg);
			if (size > 4096) {
				fprintf(stderr, "too large size\n");
				return -1;
			}
			break;

		case 'm':
			mps = atoi(optarg);
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

	printf("start DMA write, to 0x%lx, payload='%s', size %d-byte\n",
	       addr, buf, size);

	if (mps)
		ret = dma_write_aligned(&nt, addr, buf, size, mps);
	else
		ret = dma_write(&nt, addr, buf, size);

	printf("dma_write to 0x%lx returns %d\n", addr, ret);

	if (ret < 0)
		perror("dma_read");


	return 0;
}
