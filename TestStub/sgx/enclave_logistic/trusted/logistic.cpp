#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "logistic.h"
#include "logistic_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

int open(const char* filename, int mode) {
    int ret;
    
    if (ocall_open(&ret, filename, mode) != SGX_SUCCESS) return -1;
    return ret;
}

int read(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_read(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

int write(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_write(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

int close(int file) {
	int ret;
    ocall_close(&ret, file);
    return ret;
}

int fsync(int file)
{
	int ret;
	ocall_fsync(&ret, file);
	return ret;
}

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

