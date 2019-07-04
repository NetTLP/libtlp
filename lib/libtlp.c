/*
 * libtlp.c
 */
#include <stdio.h>	/* for debug */
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <poll.h>

#include <libtlp.h>
#include <tlp.h>

#define LIBTLP_CPL_TIMEOUT	500	/* msec */



int nettlp_init(struct nettlp *nt)
{
	int fd, ret;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	/* bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = nt->local_addr;
	saddr.sin_port = htons(nt->local_port);
	ret = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		return ret;
	
	/* connect to remote address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = nt->remote_addr;
	saddr.sin_port = htons(nt->remote_port);
	ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		return ret;

	nt->sockfd = fd;
	return 0;
}

static ssize_t libtlp_read_cpld(struct nettlp *nt, void *buf,
				size_t count)
{
	int ret = 0;
	ssize_t received;
	struct pollfd x[1];
	struct iovec iov[3];
	struct nettlp_hdr nh;
	struct tlp_cpl_hdr ch;

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &ch;
	iov[1].iov_len = sizeof(ch);

	x[0].fd = nt->sockfd;
	x[0].events = POLLIN;

	received = 0;

	while (1) {

		ret = poll(x, 1, LIBTLP_CPL_TIMEOUT);
		if (ret < 0)
			goto err_out;

		if (ret == 0)
			goto out;

		if (!x[0].revents & POLLIN)
			goto err_out;

		iov[2].iov_base = buf + received;
		iov[2].iov_len = count - received;
		ret = readv(nt->sockfd, iov, 3);
		if (tlp_cpl_status(ch.stcnt) != TLP_CPL_STATUS_SC) {
			switch (tlp_cpl_status(ch.stcnt)) {
			case TLP_CPL_STATUS_UR:
				errno = EOPNOTSUPP;
				ret = -1;
				goto err_out;
			case TLP_CPL_STATUS_CRS:
				errno = EINVAL;
				ret = -1;
				goto err_out;
			case TLP_CPL_STATUS_CA:
				errno = ECONNABORTED;
				ret = -1;
				goto err_out;
			}
		}
		
		
		/*
		 * XXX: should check remaining buffer space
		 */

		if (tlp_length(ch.tlp.falen) ==
		    ((ch.lowaddr & 0x3) + tlp_cpl_bcnt(ch.stcnt) + 3) >> 2) {

			printf("finished!\n");

			/* last CplD.
			 * see http://xillybus.com/tutorials/
			 * pci-express-tlp-pcie-primer-tutorial-guide-1
			 */
			received += tlp_cpl_bcnt(ch.stcnt);

			/* XXX: this code slightly causes buffer overflow */
			if (ch.lowaddr & 0x3) {
				memmove(iov[2].iov_base,
					iov[2].iov_base + (ch.lowaddr & 0x3),
					tlp_cpl_bcnt(ch.stcnt));
			}

			break;
		} else {
			received += tlp_length(ch.tlp.falen) << 2;
			printf("received = %lu\n", received);
		}
	}

out:
	return received;

err_out:
	return ret;
}


ssize_t dma_read(struct nettlp *nt, uintptr_t addr, void *buf, size_t count)
{
	int ret;
	struct iovec iov[3];
	struct nettlp_hdr nh;
	struct tlp_mr_hdr mh;
	uint64_t dst_addr64;
	uint32_t dst_addr32;

	memset(&nh, 0, sizeof(nh));
	memset(&mh, 0, sizeof(mh));

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &mh;
	iov[1].iov_len = sizeof(mh);

	/* build memory read request  */
	tlp_set_type(mh.tlp.fmt_type, TLP_TYPE_MRd);
	if (addr < INT32_MAX) {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_3DW, TLP_FMT_WO_DATA);
		dst_addr32 = htobe32(addr & 0xFFFFFFFC);
		iov[2].iov_base = &dst_addr32;
		iov[2].iov_len = sizeof(dst_addr32);
	} else {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_4DW, TLP_FMT_WO_DATA);
		dst_addr64 = htobe64(addr & 0xFFFFFFFFFFFFFFFC);
		iov[2].iov_base = &dst_addr64;
		iov[2].iov_len = sizeof(dst_addr64);
	}
	mh.requester = ntohs(nt->requester);
	mh.tag = nt->tag;
	mh.lstdw = tlp_calculate_lstdw(addr, count);
	mh.fstdw = tlp_calculate_fstdw(addr, count);
	tlp_set_length(mh.tlp.falen, tlp_calculate_length(addr, count));
	

	ret = writev(nt->sockfd, iov, 3);
	if (ret < 0)
		return ret;

	return libtlp_read_cpld(nt, buf, count);
}

ssize_t dma_write(struct nettlp *nt, uintptr_t addr, void *buf, size_t count)
{
	int ret, n;
	char pad[4] = { 0, 0, 0, 0 };
	struct iovec iov[6];
	struct nettlp_hdr nh;
	struct tlp_mr_hdr mh;
	uint64_t dst_addr64;
	uint32_t dst_addr32;

	memset(&nh, 0, sizeof(nh));
	memset(&mh, 0, sizeof(mh));

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &mh;
	iov[1].iov_len = sizeof(mh);
	iov[3].iov_base = pad;
	iov[3].iov_len = 0;	/* if needed, increment for padding */
	iov[4].iov_base = buf;
	iov[4].iov_len = count;
	iov[5].iov_base = pad;
	iov[5].iov_len = 0;	/* if needed, increment for padding */


	/* build memory write request */
	tlp_set_type(mh.tlp.fmt_type, TLP_TYPE_MWr);
	if (addr < INT32_MAX) {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_3DW, TLP_FMT_W_DATA);
		dst_addr32 = htobe32(addr & 0xFFFFFFFC);
		iov[2].iov_base = &dst_addr32;
		iov[2].iov_len = sizeof(dst_addr32);
	} else {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_4DW, TLP_FMT_W_DATA);
		dst_addr64 = htobe64(addr & 0xFFFFFFFFFFFFFFF7);
		iov[2].iov_base = &dst_addr64;
		iov[2].iov_len = sizeof(dst_addr64);
	}
	mh.requester = ntohs(nt->requester);
	mh.tag = nt->tag;
	mh.lstdw = tlp_calculate_lstdw(addr, count);
	mh.fstdw = tlp_calculate_fstdw(addr, count);
	tlp_set_length(mh.tlp.falen, tlp_calculate_length(addr, count));

	/* XXX:
	 * 
	 * 1st DW BE is used and not 0xF, move the buffer, if 1st DW
	 * is xx10, x100, or 1000. It needs padding.
	 */
	if (mh.fstdw && mh.fstdw != 0xF) {
		printf("start padding, fstdw is %x\n", mh.fstdw);
		for (n = 0; n < 3; n++) {
			if ((mh.fstdw & (0x1 << n)) == 0) {
				/* this bit is not used. padding! */
				iov[3].iov_len++;
			}
		}
	}

	if (mh.lstdw && mh.lstdw != 0xF) {
		printf("start padding, lstdw is %x\n", mh.lstdw);
		for (n = 0; n < 3; n++) {
			if ((mh.lstdw & (0x8 >> n)) == 0) {
				/* this bit is not used, padding! */
				iov[5].iov_len++;
			}
		}
	}


	ret = writev(nt->sockfd, iov, 6);
	if (ret < 0)
		return ret;

	if (ret < (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len)) {
		/* failed to write the whole packet */
		return -2;
	}

	printf("0 %ld, 1 %ld, 2 %ld, 3 %ld, 4 %ld, 5 %ld, ret %d\n",
	       iov[0].iov_len, iov[1].iov_len,
	       iov[2].iov_len, iov[3].iov_len,
	       iov[4].iov_len, iov[5].iov_len, ret);
	       

	return ret - (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len
		      + iov[3].iov_len + iov[5].iov_len);
}
