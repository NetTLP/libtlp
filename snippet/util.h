/* utility for test */

#ifndef _TLP_TEST_UTIL_H_
#define _TLP_TEST_UTIL_H_

#include <libtlp.h>

void dump_nettlp(struct nettlp *nt)
{
	printf("======== struct nettlp ========\n");
	printf("port:        %d\n", nt->port);
	printf("remote_addr: %s\n", inet_ntoa(nt->remote_addr));
	printf("local_addr:  %s\n", inet_ntoa(nt->local_addr));
	printf("requester:   %02x:%02x\n",
	       (nt->requester & 0xFF00) >> 8, nt->requester & 0x00FF);
	printf("sockfd:      %d\n", nt->sockfd);
	printf("===============================\n");
}

void hexdump(void *buf, int len)
{
        int n;
        unsigned char *p = buf;

        printf("Hex dump\n");

        for (n = 0; n < len; n++) {
                printf("%02x", p[n]);

                if ((n + 1) % 2 == 0)
                        printf(" ");
                if ((n + 1) % 32 == 0)
                        printf("\n");
        }
        printf("\n\n");
}


#endif /* _TLP_TEST_UTIL_H_ */
