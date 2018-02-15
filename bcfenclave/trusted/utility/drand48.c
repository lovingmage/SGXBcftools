/// @file drand48.c
/*
	Source: http://web.mit.edu/cgs/src/math/drand48/drand48.c
*/

//-------------< Implementation of drand48()>--------------
#include "drand48.h"

static unsigned x[3] = { X0, X1, X2 }, a[3] = { A0, A1, A2 }, c = C;

#if HAVEFP
double drand48()
{
	double ret = 0.0;
	static double two16m = 1.0 / (1L << NUM);
	next();
	ret = two16m * (two16m * (two16m * x[0] + x[1]) + x[2]);
	return ret;
}
#endif

//-------------< next operation implemetation >-----------
static void next()
{
	unsigned p[2], q[2], r[2], carry0, carry1;

	MUL(a[0], x[0], p);
	ADDEQU(p[0], c, carry0);
	ADDEQU(p[1], carry0, carry1);
	MUL(a[0], x[1], q);
	ADDEQU(p[1], q[0], carry0);
	MUL(a[1], x[0], r);
	x[2] = LOW(carry0 + carry1 + CARRY(p[1], r[0]) + q[1] + r[1] +
		a[0] * x[2] + a[1] * x[1] + a[2] * x[0]);
	x[1] = LOW(p[1] + r[0]);
	x[0] = LOW(p[0]);
}

//-------------------< Test Stub >-------------------------
#ifdef TEST_DRAND48
#include <stdio.h>

main()
{
	int i;

	for (i = 0; i < 80; i++) {
		printf("%4d ", (int)(4096 * drand48()));
		printf("%.4X%.4X%.4X\n", x[2], x[1], x[0]);
	}
}
#endif
