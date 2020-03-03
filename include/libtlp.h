/* libtlp.h */

#ifndef _LIBTLP_H_
#define _LIBTLP_H_

#include <stdint.h>
#include <netinet/in.h>

#include <tlp.h>


#define NETTLP_MSG_PORT		0x2FFF	/* 12287, Port for messaging API */

#define NETTLP_LIBTLP_PORT_BASE		0x3000
#define NETTLP_ADAPTER_PORT_BASE	0x4000
/* NETTLP_PORT_BASE: Base UDP port numbers for NetTLP
 * encapsulation. The detail is described below (enum
 * dma_direction).
 */


/*
 * NetTLP specific header
 */
struct nettlp_hdr {
	uint16_t	seq;
	uint32_t	tstamp;
} __attribute__((packed));



enum dma_direction {
	DMA_ISSUED_BY_LIBTLP = 0,
	DMA_ISSUED_BY_ADAPTER = 1,
};
/* enum dma_reiction is used for struct nettlp.dir. This value
 * indicates directions of DMAs through the associating struct
 * nettlp. It is similar ot enum dma_data_direction on Linux kernel,
 * but they are certainly different things. dma_data_direction in
 * Linux kernel focuses on directions of DATA transferred by DMA,
 * thus, for exmaple, DMA_TO_DEVICE indicates DMA Read from a device
 * that moves data from CPU TO DEVICE. On the other hand,
 * dma_direction in NetTLP focuses on directions of PCIe Transactions
 * (not data). For example, DMA_ISSUED_BY_LIBTLP indicates DMA Read
 * and DMA Write issued from LibTLP to CPU on the remote host through
 * NetTLP adapter, which move data in the both directions: from CPU TO
 * DEVICE (DMA Read by LibTLP) and DEVICE TO CPU (DMA Write by
 * LibTLP).
 *
 * dma_direction changes UDP port numbers for encapsulated TLPs.
 *
 * - DMA_ISSUED_BY_LIBTLP uses (0x3000 + TLP_tag) as UDP port.
 * - DMA_ISSUED_BY_ADAPTER uses (0x4000 + TLP_tag[3:0]) as UDP port.
 *
 * As a result, PCIe transactions from LIbTLP and PCIe transactions
 * from CPU/Root Complex on the adapter host can be distinguished by
 * UDP port numbers (0x3000 or 0x4000). It enables that software
 * devices can handle both directions on different UDP sockets, CPU
 * cores, and NIC queueus.
 */


/*
 * structure describing nettlp context
 */
struct nettlp {

	/* configuration */
	struct in_addr remote_addr;	/* Remote NetTLP adapter addr */
	struct in_addr local_addr;	/* Local addr connected to adapter */
	uint16_t requester;		/* PCI requester ID */
	uint8_t tag;			/* PCI tag value */
	enum dma_direction 	dir;	/* Direction */

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
 * @nt: array of struct nettlp that the callback is registered
 * @nnts: number of struct nettlp
 * @mh: Memory Request TLP header
 * @arg: argument passed throught nettlp_run_cb()
 *
 * @m: actual data of MWr or CplD
 * @count: length of the data in @m
 *
 * multiple struct nettlp contexts are handled by a single thread with poll
 */
struct nettlp_cb {

	uintptr_t start;
	uintptr_t end;

	int (*mrd)(struct nettlp *nt, struct tlp_mr_hdr *mh, void *arg);
	int (*mwr)(struct nettlp *nt, struct tlp_mr_hdr *mh,
		   void *m, size_t count, void *arg);
	int (*cpl)(struct nettlp *nt, struct tlp_cpl_hdr *ch, void *arg);
	int (*cpld)(struct nettlp *nt, struct tlp_cpl_hdr *ch,
		    void *m, size_t count, void *arg);
	int (*other)(struct nettlp *nt, struct tlp_hdr *tlp, void *arg);
};
/* *other is called when TLP type is not MRd|MWr|Cpl|CplD */


#define NETTLP_CB_MAX_NTS	16

int nettlp_run_cb(struct nettlp **nt, int nnts,
		  struct nettlp_cb *cb, void *arg);
void nettlp_stop_cb(void);

/*
 * Messaging API for NetTLP driver.
 *
 * Currently, this API enables libtlp applications to obtain NetTLP
 * hardware information, such as BAR4 start address and MSIX talbe
 * entries.
 *
 * Note: the message API creates udp socket every exectuon.
 */
#define	NETTLP_MSG_GET_BAR4_ADDR	1
#define NETTLP_MSG_GET_DEV_ID		2
#define NETTLP_MSG_GET_MSIX_TABLE	3

#define NETTLP_MAX_VEC	16	/* number of current MSIX vectors of NetTLP */

/*
 * nettlp_msg_get_bar4_start()
 *
 * @addr: remote host address in which NetTLP nic is installed.
 * return value: if success, it returns BAR4 start address in MMIO-space.
 * Otherwise, 0 is returned.
 */
uintptr_t nettlp_msg_get_bar4_start(struct in_addr addr);


/*
 * nettlp_msg_get_dev_id()
 *
 * @addr: remote host address in which NetTLP nic is installed.
 * return value: if success, it returns 16bit device id that can be
 * used for requester/completer id.
 */
uint16_t nettlp_msg_get_dev_id(struct in_addr addr);


/*
 * nettlp_msg_get_msix_table()
 *
 * @addr: remote host address in which NetTLP nic is installed.
 * @msix: array of nettlp_msix structures.
 * @msix_count: number of nettlp_msix structures in on @msix.
 * return value: if success, it returns 0 and MSIX tablues values are
 * written into @msix. Otherwise, -1 is returned and errno is set.
 *
 */

struct nettlp_msix {
        uint64_t addr;
        uint32_t data;
} __attribute__((__packed__));

int nettlp_msg_get_msix_table(struct in_addr addr, struct nettlp_msix *msix,
			      int msix_count);



/*
 * PCIe Configuration API.
 *
 * Since v0.22, the NetTLP adapter supports manipulating PCIe
 * configuration registers from libtlp.
 */

#define NETTLP_PCIE_CFG_PORT	0x4001

struct nettlp_pcie_cfg {

	/* connection endpoints for communicating NetTLP adapter */
	struct in_addr remote_addr;
	struct in_addr local_addr;

	/* private variable */
	int sockfd;
};

/*
 * nettlp_pcie_cfg_init() just creates UDP socket and save it on the struct
 * nettlp_pcie_cfg.
 */
int nettlp_pcie_cfg_init(struct nettlp_pcie_cfg *ntpc);


/*
 * nettlp_pcie_cfg_read() and nettlp_pcie_cfg_write()
 *
 * read and write PCIe configuration space of NetTLP adapter.
 *
 * @ntpc: struct nettlp_pcie_cfg, must be initialized in advance.
 * @addr: target address on PCIe configuration space of the NetTLP adapter
 * @buf: buffer to bytes to be written or read.
 * @count: number of bytes to be written or read.
 * returns number of bytes written or read.
 */
ssize_t nettlp_pcie_cfg_read(struct nettlp_pcie_cfg *ntpc, uint16_t addr,
			     void *buf, size_t count);
ssize_t nettlp_pcie_cfg_write(struct nettlp_pcie_cfg *ntpc, uint16_t addr,
			      void *buf, size_t cout);


#endif /* _LIBTLP_H_ */
