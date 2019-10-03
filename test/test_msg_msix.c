#include <stdio.h>
#include <arpa/inet.h>
#include <libtlp.h>

int main(int argc, char **argv)
{
	int ret, n;
	struct in_addr addr;
	struct nettlp_msix msix[16];

	if (argc < 2) {
		printf("usage: %s [NetTLP host addr]\n", argv[0]);
		return -1;
	}

	if (inet_pton(AF_INET, argv[1], &addr) < 1) {
		printf("invalid addr %s\n", argv[1]);
		return -1;
	}

	ret = nettlp_msg_get_msix_table(addr, msix, 16);
	if (ret < 0) {
		perror("nettlp_msg_get_msix_table");
		return -1;
	}

	for (n = 0; n < 16; n++) {
		printf("MSIX[%d] ADDR=%#llx DATA=%x\n",
		       n, msix[n].addr, msix[n].data);
	}


	return 0;
}
