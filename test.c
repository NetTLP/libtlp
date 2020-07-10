#include "picotest/picotest.h"

#include <libtlp.h>

static void
test_unit1(void)
{
	int a, b;

	a = 10;
	b = 10;

	note("hoge");

	ok(a == b);
}

static void
test_unit2(void)
{
	int a, b;

	a = 10;
	b = 11;

	note("moge");

	ok(a == b);
}

int
main(int argc, char **argv)
{
	subtest("unittest1", test_unit1);
	subtest("unittest2", test_unit2);

	return done_testing();
}


