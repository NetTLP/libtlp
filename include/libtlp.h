/* libtlp.h */

#ifndef _LIBTLP_H_
#define _LIBTLP_H_

#include <stdint.h>
#include <netinet/in.h>

#include <tlp.h>


#define NETTLP_PORT_BASE	12288	/* actual port number is
					 * NETTLP_PORT_BASE + (tag & 0x0F) */

/*
 * NetTLP specific header
 */
struct nettlp_hdr {
	uint16_t	seq;
	uint32_t	tstamp;
} __attribute__((packed));


/*
 * structure describing nettlp context
 */
struct nettlp {

	/* configuration */
	struct in_addr remote_addr;
	struct in_addr local_addr;
	uint16_t requester;
	uint8_t tag;

	/* variable */
	int sockfd;
	uint16_t port;
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
 * dma_(read|write)_aligned()
 *
 * These variants aligns large memory request into @mrrs
 * (MaxReadReqestSize) or @mps (MaxPayloadSize)
 *
 */
ssize_t dma_read_aligned(struct nettlp *nt, uintptr_t addr, void *buf,
			 size_t count, size_t mrrs);
ssize_t dma_write_aligned(struct nettlp *nt, uintptr_t addr, void *buf,
			  size_t count, size_t mps);

		  
/*
 * Callback API for psuedo memory process
 *
 * @nt: struct nettlp that the callback is registered
 * @mh: Memory Request TLP header
 * @arg: argument passed throught nettlp_run_cb()
 *
 * @m: actual data of MWr or CplD
 * @count: length of the data in @m
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
void nettlp_stop_cb(void);


#endif /* _LIBTLP_H_ */
