#include "picotest/picotest.h"

#include <libtlp.h>

static void
calculate_fstdw_lstdw(uintptr_t addr, size_t count, int *result_fst, int *result_lst)
{
	*result_fst = tlp_calculate_fstdw(addr, count);
	*result_lst = tlp_calculate_lstdw(addr, count);
	//note("result_fst=0x%x, result_lst=0x%x", *result_fst, *result_lst);
}

static void
test_tlp_calculate_fstdw_lstdw(void)
{
	int result_fst, result_lst;

	// zero-length read and write
	calculate_fstdw_lstdw(0x0, 0, &result_fst, &result_lst);
	ok(result_fst == 0 && result_lst == 0);

	calculate_fstdw_lstdw(0x0, 4093, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x1);

	calculate_fstdw_lstdw(0x0, 4094, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x3);

	calculate_fstdw_lstdw(0x0, 4095, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x7);

	calculate_fstdw_lstdw(0x0, 4096, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0xf);

	// zero-length read and write
	calculate_fstdw_lstdw(0xa0000003, 0, &result_fst, &result_lst);
	ok(result_fst == 0x0 && result_lst == 0x0);

	calculate_fstdw_lstdw(0xa0000000, 1, &result_fst, &result_lst);
	ok(result_fst == 0x1 && result_lst == 0x0);

	calculate_fstdw_lstdw(0xa0000000, 2, &result_fst, &result_lst);
	ok(result_fst == 0x3 && result_lst == 0x0);

	calculate_fstdw_lstdw(0xa0000000, 3, &result_fst, &result_lst);
	ok(result_fst == 0x7 && result_lst == 0x0);

	calculate_fstdw_lstdw(0xa0000000, 4, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x0);

	calculate_fstdw_lstdw(0xa0000000, 5, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x1);

	calculate_fstdw_lstdw(0xa0000000, 6, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x3);

	calculate_fstdw_lstdw(0xa0000000, 7, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0x7);

	calculate_fstdw_lstdw(0xa0000000, 8, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0xf);

	calculate_fstdw_lstdw(0xa0000000, 16, &result_fst, &result_lst);
	ok(result_fst == 0xf && result_lst == 0xf);

	calculate_fstdw_lstdw(0x00000003, 9, &result_fst, &result_lst);
	ok(result_fst == 0x8 && result_lst == 0xf);

	calculate_fstdw_lstdw(0x00000003, 10, &result_fst, &result_lst);
	ok(result_fst == 0x8 && result_lst == 0x1);

	calculate_fstdw_lstdw(0x00000003, 11, &result_fst, &result_lst);
	ok(result_fst == 0x8 && result_lst == 0x3);

	calculate_fstdw_lstdw(0x00000003, 12, &result_fst, &result_lst);
	ok(result_fst == 0x8 && result_lst == 0x7);

	calculate_fstdw_lstdw(0x00000003, 13, &result_fst, &result_lst);
	ok(result_fst == 0x8 && result_lst == 0xf);
}

int
main(int argc, char **argv)
{
	subtest("tlp_calculate_fstdw_lstdw",
			test_tlp_calculate_fstdw_lstdw);

	return done_testing();
}

