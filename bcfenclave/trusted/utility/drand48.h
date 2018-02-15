/// @file drand48.h
/// drand48() implementation
/*

 *	drand48, etc. pseudo-random number generator
 *	This implementation assumes unsigned short integers of at least
 *	16 bits, long integers of at least 32 bits, and ignores
 *	overflows on adding or multiplying two unsigned integers.
 *	Two's-complement representation is assumed in a few places.
 *
 *
    Source: http://web.mit.edu/cgs/src/math/drand48/drand48.c
*/

#ifndef SGX_DRAND48
#define SGX_DRAND48

#define DRIVER
#ifndef HAVEFP
#define HAVEFP 1
#endif
#define NUM	16
#define MASK	((unsigned)(1 << (NUM - 1)) + (1 << (NUM - 1)) - 1)
#define LOW(x)	((unsigned)(x) & MASK)
#define HIGH(x)	LOW((x) >> NUM)
#define MUL(x, y, z)	{ long l = (long)(x) * (long)(y); \
		(z)[0] = LOW(l); (z)[1] = HIGH(l); }
#define CARRY(x, y)	((long)(x) + (long)(y) > MASK)
#define ADDEQU(x, y, z)	(z = CARRY(x, (y)), x = LOW(x + (y)))
#define X0	0x330E
#define X1	0xABCD
#define X2	0x1234
#define A0	0xE66D
#define A1	0xDEEC
#define A2	0x5
#define C	0xB
#define HI_BIT	(1L << (2 * NUM - 1))

//---< limitted global variables for drand48 algorithm >-----------
//static unsigned short lastx[3];

//--< drand48() interface >--
double drand48();
//----< next() interface >--
static void next();

#endif