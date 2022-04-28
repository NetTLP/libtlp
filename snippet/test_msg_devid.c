#include <stdio.h>
#include <arpa/inet.h>
#include <libtlp.h>

int main(int argc, char **argv)
{
	struct in_addr addr;
	uint16_t devid;

	if (argc < 2) {
		printf("usage: %s [NetTLP host addr]\n", argv[0]);
		return -1;
	}

	if (inet_pton(AF_INET, argv[1], &addr) < 1) {
		printf("invalid addr %s\n", argv[1]);
		return -1;
	}

	devid = nettlp_msg_get_dev_id(addr);
	printf("dev id is 0x%x\n", devid);

	return 0;
}
