#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "logistic.h"
#include "logistic_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_logistic_sample(buf);
}

int ecall_logistic_sample()
{
  printf("IN LOGISTIC\n");
  return 0;
}

