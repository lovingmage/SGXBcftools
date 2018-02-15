#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../../htslib-1.5/htslib/hts.h"
#include "../../htslib-1.5/version.h"
#include "../../bcftools.h"

#include "bcfenclave.h"
#include "bcfenclave_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */


void fprintf(int file, const char* fmt, ...) {
#define BUF_SIZE 1024
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    ocall_bcfenclave_sample(buf);
}

/*
double drand48(void){
    double ret;
	ocall_drand48(&ret);
	return ret;
}
*/

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_bcfenclave_sample(buf);
}

void error(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_bcfenclave_sample(buf);
}

//---------------< Ecall To Make Actual Variant Calls >-----------------------------------
int ecall_bcfenclave_sample(char* refname, char* reffile, char* genomefile, char* outfile)
{
  printf("IN MPILEUP\n");
  int argc = 8;
  char* argv[] = {"bcftools",
                    "mpileup",
                    "-Ov",
                    "-f",             // Default paramater
                    reffile, // reference file
                    genomefile,   // Input Sam file used for variant call
                    "-o",             // Default paramater
                    outfile    // Output File
                    };

  //bam_mpileup(argc - 1, argv + 1, "mpileup.ref.fa", "mpileup.ref.fa", "mpileup1.sam", "mpileup1.tmp") ;  
  bam_mpileup(argc - 1, argv + 1);  
  
  return 0;

}


int ecall_bcfenclave_ccall(char* mlpfile, char* callfile)
{
    printf("IN VCFCALL\n");
    int argc = 6;
    char* argv[] = {"bcftools", 
                  "call", 
                  "-mv",             // Default paramater
                  mlpfile,  // Input Sam file used for variant cal   // Output File
                  "-o",
                  callfile};  

    main_vcfcall(argc - 1, argv + 1);

  return 0;
}
