#include <stdio.h>
#include <stdlib.h>
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
	       "    -a 0xXX (hex), target addr in PCIe configuration space\n"
	       "    -s size to read\n");
}

int main(int argc, char **argv)
{
	int ret, ch;
	char buf[2048];
	int size = 0;
	uint16_t addr = 0;
	struct nettlp_pcie_cfg ntpc;

	memset(buf, 0, sizeof(buf));
	memset(&ntpc, 0, sizeof(ntpc));

	while ((ch = getopt(argc, argv, "r:l:a:s:h")) != -1) {
		switch (ch) {
		case 'r':
			ret = inet_pton(AF_INET, optarg, &ntpc.remote_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'l':
			ret = inet_pton(AF_INET, optarg, &ntpc.local_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'a':
			ret = sscanf(optarg, "0x%hx", &addr);
			if (ret < 1) {
				fprintf(stderr, "invalid address\n");
				return -1;
			}
			break;
				
		case 's':
			size = atoi(optarg);
			if (size < 1 || size > sizeof(buf)) {
				fprintf(stderr, "invalid size\n");
				return -1;
			}
			break;

		case 'h':
		default:
			usage();
			return -1;
		}
	}

	ret = nettlp_pcie_cfg_init(&ntpc);
	if (ret < 0) {
		perror("nettlp_pcie_cfg_init");
		return -1;
	}

	ret = nettlp_pcie_cfg_read(&ntpc, addr, buf, size);
	if (ret < 0) {
		perror("nettlp_pcie_cfg_read");
		return -1;
	}
	
	hexdump(buf, size);

	return 0;
}
