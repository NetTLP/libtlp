#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <libtlp.h>

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -a 0xXX (hex), target addr in PCIe configuration space\n"
	       "    -d 0xXX (hex) data to be written\n"
	       "    -s size in bytes\n");
}

int main(int argc, char **argv)
{
	int ret, ch;
	int size = 0;
	uint16_t addr = 0;
	uint32_t data = 0;
	struct nettlp_pcie_cfg ntpc;

	memset(&ntpc, 0, sizeof(ntpc));

	while ((ch = getopt(argc, argv, "r:l:a:d:s:h")) != -1) {
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
				
		case 'd':
			ret = sscanf(optarg, "0x%x", &data);
			if (ret < 1) {
				fprintf(stderr, "invalid data\n");
				return -1;
			}
			break;

		case 's':
			size = atoi(optarg);
			if (size < 0 || size > 4) {
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

	ret = nettlp_pcie_cfg_write(&ntpc, addr, &data, size);
	if (ret < 0) {
		perror("nettlp_pcie_cfg_write");
		return -1;
	}
	
	return 0;
}
