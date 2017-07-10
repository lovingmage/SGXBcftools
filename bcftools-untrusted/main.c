/*  main.c -- main bcftools command front-end.

    Copyright (C) 2012-2016 Genome Research Ltd.

    Author: Chenghong Wang <cwang132@syr.edu>

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "htslib/hts.h"
#include "version.h"
#include "bcftools.h"


int bam_mpileup(int argc, char *argv[], char* refname, char* reffile, char* genomefile, char* outfile);

typedef struct
{
    int (*func)(int, char*[]);
    const char *alias, *help;
}
cmd_t;

char *bcftools_version(void)
{
    return BCFTOOLS_VERSION;
}

//-------------------< Test Stub >----------------------------------------------
#define SGX_DEBUG_VERSION
#ifdef SGX_DEBUG_VERSION
int main()
{
  int argc = 7;
  char* argv[] = {"bcftools", 
                  "mpileup", 
                  "-f",             // Default paramater
                  "mpileup.ref.fa", // reference file
                  "mpileup1.sam",   // Input Sam file used for variant call
                  "-o",             // Default paramater
                  "mpileup1.vcf"    // Output File
                  };  

  bam_mpileup(argc - 1, argv + 1, "mpileup.ref.fa", "mpileup.ref.fa", "mpileup1.sam", "mpileup1.tmp") ;  

  char* argvx[] = {"bcftools", 
                  "call", 
                  "-mv",             // Default paramater
                  "mpileup1.tmp"   // Input Sam file used for variant cal   // Output File
                  };  

  main_vcfcall(3, argvx + 1, "mpileup1.tmp");
  return 0;
}
#endif