#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "htslib/hts.h"
#include "version.h"
#include "bcftools.h"

#include "bcfenclave.h"
#include "bcfenclave_t.h"  /* print_string */

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
    ocall_bcfenclave_sample(buf);
}

char *sgxstrdup(const char *s)
{
    size_t len = strlen(s) + 1;
    void  *mem = malloc(len);

    if (mem == NULL)
        return mem;

    return memcpy(mem, s, len);
}

//---------------< Ecall To Make Actual Variant Calls >-----------------------------------
int ecall_bcfenclave_sample(char* refname, char* reffile, char* genomefile, char* outfile)
{
  printf("IN BCFENCLAVE\n");
  int argc = 7;
  char* argv[] = {"bcftools",
                    "mpileup",
                    "-f",             // Default paramater
                    "mpileup.ref.fa", // reference file
                    "mpileup1.sam",   // Input Sam file used for variant call
                    "-o",             // Default paramater
                    "mpileup1.tmp"    // Output File
                    };

  //bam_mpileup(argc - 1, argv + 1, "mpileup.ref.fa", "mpileup.ref.fa", "mpileup1.sam", "mpileup1.tmp") ;  
  bam_mpileup(argc - 1, argv + 1, refname, reffile, genomefile, outfile) ;  


  
  return 0;

}

