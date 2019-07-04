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
	       "    -R remote port (default 14198)\n"
	       "    -L local port (default 14198)\n"
	       "    -b bus number, XX:XX\n"
	       "    -t tag\n"
	       "    -a dma address, 0xHEXADDR\n"
	       "    -s transfer size (default 4-byte)\n"
	       "    -p payload as ascii string (default )\n"
		);
}

int main(int argc, char **argv)
{
	int ret, ch, size;
	struct nettlp nt;
	uintptr_t addr;
	uint16_t busn, devn;
	char *payload;

	memset(&nt, 0, sizeof(nt));
	nt.remote_port = 14198;
	nt.local_port = 14198;
	addr = 0;
	busn = 0;
	devn = 0;

	payload = "hog";	/* 4-byte */
	size = strlen(payload) + 1;

	while ((ch = getopt(argc, argv, "r:l:R:L:b:t:a:p:")) != -1) {
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

		case 'p':
			payload = optarg;
			size = strlen(payload) + 1;	/* +1 for '\0' */
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

	printf("start DMA write, to 0x%#lx, payload='%s', size %d-byte\n",
	       addr, payload, size);

	ret = dma_write(&nt, addr, payload, size);

	printf("tlp_length is %u\n", tlp_calculate_length(addr, size));

	printf("\n\n");
	printf("dma_write returns %d\n", ret);
	printf("\n");
	printf("Last 0x%x, 1st 0x%x\n",
	       tlp_calculate_lstdw(addr, size),
	       tlp_calculate_fstdw(addr, size));

	if (ret < 0)
		perror("dma_read");


	return 0;
}
