#ifndef _BCFENCLAVE_H_
#define _BCFENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

//The following three specifies the fprintf operation flags.
#define stdin  0
#define stdout 1
#define stderr 2

// This is the marco to replace exit using return
#define exit(a) return a

#define M_LN2	0.69314718055994530942
#define M_LN10   2.30258509299404568402

# define SEEK_SET	0	/* Seek from beginning of file.  */
# define SEEK_CUR	1	/* Seek from current position.  */
# define SEEK_END	2	/* Seek from end of file.  */
# ifdef __USE_GNU
#  define SEEK_DATA	3	/* Seek to next data.  */
#  define SEEK_HOLE	4	/* Seek to next hole.  */
#endif

#if defined(__cplusplus)
extern "C" {
#endif


//double drand48();
void error(const char *fmt, ...);
void printf(const char *fmt, ...);
void fprintf(int file, const char* format, ...);
char *strdup(const char *s);

#if defined(__cplusplus)
}
#endif

#endif /* !_BCFENCLAVE_H_ */
