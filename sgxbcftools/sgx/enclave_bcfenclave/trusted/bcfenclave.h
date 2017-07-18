#ifndef _BCFENCLAVE_H_
#define _BCFENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

double drand48();
void printf(const char *fmt, ...);
char *strdup(const char *s);

#if defined(__cplusplus)
}
#endif

#endif /* !_BCFENCLAVE_H_ */
