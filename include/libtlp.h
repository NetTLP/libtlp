/* libtlp.h */

#ifndef _LIBTLP_H_
#define _LIBTLP_H_

#include <stdint.h>
#include <netinet/in.h>

#include <tlp.h>

/*
 * NetTLP specific header
 */
struct nettlp_hdr {
	uint16_t	seq;
	uint32_t	tstamp;
} __attribute__((packed));

/*
 * structure describing nettlp context for applications
 */
struct nettlp {

	/* configuration */
	int remote_port;
	int local_port;
	struct in_addr remote_addr;
	struct in_addr local_addr;
	uint16_t requester;
	uint8_t tag;

	/* variable */
	int sockfd;
};


/*
 * nettlp_init(), initialize nettlp, actually, create socket.
 * Fill the struct nettlp, configuration valies, and call this function.
 */
int nettlp_init(struct nettlp *nt);

/*
 * Direct Memory Access API
 *
 * dma_read() and dma_write()
 *
 * @nt: struct nettlp, must be initalized in advance.
 * @addr: address of DMA destination.
 * @buf: buffer to be written to or read from remote.
 * @count: number of bytes to be written or read.
 * returns number of bytes transferred (as payload)
 */
ssize_t dma_read(struct nettlp *nt, uintptr_t addr, void *buf, size_t count);
ssize_t dma_write(struct nettlp *nt, uintptr_t addr, void *buf, size_t count);
		  
		  
/*
 * Callback API for psuedo memory process
 */
struct nettlp_cb {
	int (*mrd)(struct nettlp *nt, struct tlp_mr_hdr *mh, void *arg);
	int (*mwr)(struct nettlp *nt, struct tlp_mr_hdr *mh,
		   void *m, size_t count, void *arg);
	int (*cpl)(struct nettlp *nt, struct tlp_cpl_hdr *ch, void *arg);
	int (*cpld)(struct nettlp *nt, struct tlp_cpl_hdr *ch,
		    void *m, size_t count, void *arg);
};

int nettlp_run_cb(struct nettlp *nt, struct nettlp_cb *cb, void *arg);


#endif /* _LIBTLP_H_ */
