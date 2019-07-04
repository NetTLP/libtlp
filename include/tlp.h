/*
 * tlp.h
 */

#ifndef _TLP_H_
#define _TLP_H_

#include <stdint.h>

/* 
 * Common Header
 * 
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 */

struct tlp_hdr {
	uint8_t		fmt_type;	/* Formant and Type */
	uint8_t		tclass;		/* Traffic Class */
	uint16_t	falen;		/* Flag, Attr, Reseved, and Length */
} __attribute__((packed));



/* TLP Format */
#define TLP_FMT_DW_MASK		0x20
#define TLP_FMT_3DW		0x00
#define TLP_FMT_4DW		0x20

#define tlp_fmt_dw(ft) ((ft) & TLP_FMT_DW_MASK)
#define tlp_is_3dw(ft) (tlp_fmt_dw(ft) == TLP_FMT_3DW)
#define tlp_is_4dw(ft) (tlp_fmt_dw(ft) == TLP_FMT_4DW)

#define TLP_FMT_DATA_MASK	0x40
#define TLP_FMT_WO_DATA		0x00
#define TLP_FMT_W_DATA		0x40

#define tlp_fmt_data(ft) ((ft) & TLP_FMT_DATA_MASK)
#define tlp_is_wo_data(ft) (tlp_fmt_data(ft) == TLP_FMT_WO_DATA)
#define tlp_is_w_data(ft) (tlp_fmt_data(ft) == TLP_FMT_W_DATA)

#define tlp_set_fmt(ft, dw, wd) \
		(ft) |= ((dw) & TLP_FMT_DW_MASK) |	\
			((wd) & TLP_FMT_DATA_MASK)


/* TLP Type */
#define TLP_TYPE_MASK		0x1F
#define TLP_TYPE_MRd		0x00
#define TLP_TYPE_MRdLk		0x01
#define TLP_TYPE_MWr		0x00
#define TLP_TYPE_Cpl		0x0A

#define tlp_type(ft) ((ft) & TLP_TYPE_MASK)
#define tlp_is_mrd(ft) (tlp_type(ft) == TLP_TYPE_MRd && tlp_is_wo_data(ft))
#define tlp_is_mwr(ft) (tlp_type(ft) == TLP_TYPE_MWr && tlp_is_w_data(ft))
#define tlp_is_cpl(ft) (tlp_type(ft) == TLP_TYPE_Cpl)
#define tlp_set_type(ft, v) ft = ((ft & ~TLP_TYPE_MASK) | (v & TLP_TYPE_MASK))


/* Traffic class */
#define TLP_TCLASS_MASK		0x70
#define tlp_tclass(tc) ((tc & TLP_TCLASS_MASK) >> 4)
#define tlp_set_tclass(tc, v) (tc) = (((v) << 4) & TLP_TCLASS_MASK)
		

/* TLP Flags */
#define TLP_FLAG_MASK		0xC000
#define tlp_flag(fl) (ntohs(fl) & TLP_FLAG_MASK)

#define TLP_FLAG_DIGEST_MASK	0x8000
#define tlp_flag_digest(fl) (tlp_flag(fl) & TLP_FLAG_DIGEST_MASK)
#define tlp_flag_set_digest(fl) (fl |= htons(TLP_FLAG_DIGEST_MASK))
#define tlp_flag_unset_digest(fl) (fl &= ~htons(TLP_FLAG_DIGEST_MASK))

#define TLP_FLAG_EP_MASK	0x4000
#define tlp_flag_ep(fl) (tlp_flag(fl) & TLP_FLAG_EP_MASK)
#define tlp_flag_set_ep(fl) (fl |= htons(TLP_FLAG_EP_MASK))
#define tlp_flag_unset_ep(fl) (fl &= ~htons(TLP_FLAG_EP_MASK))


/* TLP Attrs */
#define TLP_ATTR_MASK		0x3000
#define tlp_attr(fl) (ntohs(fl) & TLP_ATTR_MASK)

#define TLP_ATTR_RELAX_MASK	0x2000
#define tlp_attr_relax(fl) (tlp_attr(fl) & TLP_ATTR_RELAX_MASK)
#define tlp_attr_set_relax(fl) (fl |= htons(TLP_ATTR_RELAX_MASK))
#define tlp_attr_unset_relax(fl) (fl &= ~htons(TLP_ATTR_RELAX_MASK))

#define TLP_ATTR_NOSNP_MASK	0x1000
#define tlp_attr_nosnp(fl) (tlp_attr(fl) & TLP_ATTR_NOSNP_MASK)
#define tlp_attr_set_nosnp(fl) (fl |= htons(TLP_ATTR_NOSNP_MASK))
#define tlp_attr_unset_nosnp(fl) (fl &= ~htons(TLP_ATTR_NOSNP_MASK))


/* TLP Length */
#define TLP_LENGTH_MASK		0x03FF
#define tlp_length(fl) (ntohs(fl) & TLP_LENGTH_MASK)
#define tlp_set_length(fl, v) (fl = htons((ntohs(fl) & ~TLP_LENGTH_MASK) | v))



/*
 * Memory Request Header
 *
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 * |         Requeseter ID         |      Tag      | LastDW| 1stDW |
 * +---------------+---------------+---------------+---------------+
 * |                            Address                        | R |
 * +---------------+---------------+---------------+---------------+
 * 
 * or, 64bit address (4DW header)
 * +---------------+---------------+---------------+---------------+
 * |                            Address                            |
 * +---------------+---------------+---------------+---------------+
 * |                            Address                        | R |
 * +---------------+---------------+---------------+---------------+
 */

struct tlp_mr_hdr {
	struct tlp_hdr tlp;

	uint16_t requester;
	uint8_t	tag;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t fstdw : 4;
	uint8_t lstdw : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t lstdw : 4;
	uint8_t fstdw : 4;
#else
# error "Please fix <bits/endian.h>"
#endif
	
} __attribute__((packed));


#define tlp_id_to_bus(id) (ntohs(id) >> 8)
#define tlp_id_to_device(id) (ntohs(id) & 0x00FF)

/* calculate Last DW BE, 1st DW BE, and 4WD length.
 * @addr: actual start DMA address (not 4WD-aligned)
 * @cnt: number of bytes to be DMAed (not 4WD-aligned)
 *
 * tlp_calculate_lstdw() returns 4bit Last DW BE
 * tlp_calculate_fstdw() returns 4bit 1st DW BE
 * tlp_calculate_length() returns 4DW length:
 */
#if 0
#define tlp_calculate_lstdw(addr, cnt)			\
	((addr + cnt) & 0x3 ?				\
	 (~(0xF << ((addr + cnt) & 0x3)) & 0xF) : 0xF)

#define tlp_calculate_fstdw(addr)	((0xF << (addr & 0x3)) & 0xF)
#endif


static int tlp_calculate_lstdw(uintptr_t addr, size_t count)
{
	uintptr_t end, end_start, start;

	start = (addr >> 2) << 2;
	end = addr + count;
	if ((end & 0x3) == 0)
		end_start = end - 4;
	else
		end_start = (end >> 2) << 2;

	/* corner case. count is smaller than 8*/
	if (end_start <= start)
		end_start = addr + 4;
	if (end < end_start)
		return 0;

	return ~(0xF << (end - end_start)) & 0xF;
}

static int tlp_calculate_fstdw(uintptr_t addr, size_t count)
{
	uint8_t be = 0xF;

	if (count < 4)
		be = ~(0xF << count) & 0xF;

	return (be << (addr & 0x3)) & 0xF;
}

static int tlp_calculate_length(uintptr_t addr, size_t count)
{
	size_t len = 0;
	uintptr_t start, end;

	start = addr & 0xFFFFFFFFFFFFFFFc;
	end = addr + count;

	len = (end - start) >> 2;

	if ((end - start) & 0x3)
		len++;

	return len;
}



/*
 * = Completion Header
 *
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 * |          Completer ID         |CplSt|B|      Byte Count       |
 * +---------------+---------------+---------------+---------------+ 
 * |          Requester ID         |      Tag      |R| Lower Addr  |
 * +---------------+---------------+---------------+---------------+ 
 */

struct tlp_cpl_hdr {
	struct tlp_hdr tlp;

	uint16_t completer;
	uint16_t stcnt;	/* status and count */

	uint16_t requester;
	uint8_t tag;
	uint8_t lowaddr;
} __attribute__((packed));


#define TLP_CPL_STATUS_MASK	0xE000
#define tlp_cpl_status(sc) ((ntohs(sc)) & TLP_CPL_STATUS_MASK)

#define TLP_CPL_STATUS_SC	0x0000	/* Successful Completion */
#define TLP_CPL_STATUS_UR	0x2000	/* Unsupported Request */
#define TLP_CPL_STATUS_CRS	0x4000	/* Configratuon Request Retry Status */
#define TLP_CPL_STATUS_CA	0x8000	/* Completer Abort */
#define tlp_set_cpl_status(sc, v) \
	(sc = htons((ntohs(sc) &= ~TLP_CPL_STATUS_MASK) | v))


#define TLP_CPL_BCNT_MASK	0x0FFF
#define tlp_cpl_bcnt(sc) (ntohs(sc) & TLP_CPL_BCNT_MASK)
#define tlp_set_cpl_bcnt(sc, v) \
	(sc = htons((ntohs(sc) &= ~TLP_BCNT_MASK) | v))

#endif	/* _TLP_H_ */
