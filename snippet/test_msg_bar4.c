#include <stdio.h>
#include <arpa/inet.h>
#include <libtlp.h>

int main(int argc, char **argv)
{
	struct in_addr addr;
	uintptr_t bar4;

	if (argc < 2) {
		printf("usage: %s [NetTLP host addr]\n", argv[0]);
		return -1;
	}

	if (inet_pton(AF_INET, argv[1], &addr) < 1) {
		printf("invalid addr %s\n", argv[1]);
		return -1;
	}

	bar4 = nettlp_msg_get_bar4_start(addr);
	printf("BAR4 is %#lx\n", bar4);

	return 0;
}
