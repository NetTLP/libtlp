#include <stdio.h>
#include <arpa/inet.h>
#include <libtlp.h>


int main(int argc, char **argv)
{
	int ret;
	char buf[128];
	uintptr_t addr = 0x0;
	struct nettlp nt;

	inet_pton(AF_INET, "192.168.10.1", &nt.remote_addr);
	inet_pton(AF_INET, "192.168.10.3", &nt.local_addr);
	nt.requester = (0x1a << 8 | 0x00);
	nt.tag = 0;

	nettlp_init(&nt);

	ret = dma_read(&nt, addr, buf, sizeof(buf));
	if (ret < 0) {
		perror("dma_read");
		return ret;
	}

	printf("DMA read: %d bytes from 0x%lx\n", ret, addr);
	return 0;
}
