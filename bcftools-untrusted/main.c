///////////////////////////////////////////////////////////////////////
// main.c - main teststubs for light bcftools                        //
// ver 3.5                                                           //
// Language:    C, C++ Linux                                         //
// Application: The upfront interfaces for making variant calls      //
// Author:      Chenghong Wang, Research Engineer, Centromere Inc.   //
//              cwang@centromereinc.com                              //
///////////////////////////////////////////////////////////////////////
/*
* Package Operations:
* -------------------
* This package provides a public SemiExp class that collects and makes
* available sequences of tokens.  SemiExp uses the services of a Toker
* class to acquire tokens.  Each call to SemiExp::get() returns a 
* sequence of tokens that ends in {, }, ;, and '\n' if the line begins
* with #.  There are three additiona termination conditions: a sequence
* of tokens that ends with : and the immediately preceding token is
* public, protected, or private.
*
* Each semiexpression returns just the right tokens to analyze one
* C++ grammatical construct, e.g., class definition, function definition,
* declaration, etc.
* 
* Build Process:
* --------------
* Required Files: 
*   SemiExpression.h, SemiExpression.cpp, Tokenizer.h, Tokenizer.cpp, 
*   Utilities.h, Utilities.cpp
* 
* Build Command: devenv Project1.sln /rebuild debug
*
* Maintenance History:
* --------------------
* ver 3.5 : 15 Feb 2016
* - modifications to implement ITokCollection:
*   - added member functions: const indexer, push_back, remove(tok), 
*     toLower, isComment, clear
*   - changed trim to trimFront
* ver 3.4 : 06 Feb 2016
* - added some additional comments
* ver 3.3 : 03 Feb 2016
* - completed addition of terminators
* - added trim() and remove()
* ver 3.2 : 02 Feb 2016
* - declared SemiExp copy constructor and assignment operator = delete
* - added default argument for Toker pointer to nullptr so SemiExp
*   can be used like a container of tokens.
* - if pToker is nullptr then get() will throw logic_error exception
* ver 3.1 : 30 Jan 2016
* - changed namespace to Scanner
* - fixed bug in termination due to continually trying to read
*   past end of stream if last tokens didn't have a semiExp termination
*   character
* ver 3.0 : 29 Jan 2016
* - built in help session, Friday afternoon
*
* Planned Additions and Changes:
* ------------------------------
* - change the ITokCollection interface to match what is needed for the
*   parser, and make SemiExp implement that interface
* - add public :, protected :, private : as terminators
* - move creation of tokenizer into semiExp constructor so
*   client doesn't have to write that code
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "htslib/hts.h"
#include "version.h"
#include "bcftools.h"

//-------------------< function call for making mpileup >-----------------------
int bam_mpileup(int argc, char *argv[], char* refname, char* reffile, char* genomefile, char* outfile);

typedef struct
{
    int (*func)(int, char*[]);
    const char *alias, *help;
}
cmd_t;

//-------------------< Return The Version of BCFTOOLS >------------------------
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
  // The parameters are not using in the new version again
  char* argv[] = {"bcftools", 
                  "mpileup", 
                  "-f",             // Default paramater
                  "mpileup.ref.fa", // reference file
                  "mpileup1.sam",   // Input Sam file used for variant call
                  "-o",             // Default paramater
                  "mpileup1.tmp"    // Output File
                  };  

  //bam_mpileup(argc - 1, argv + 1, "/home/cwang/Desktop/dataset/Homo_sapiens.GRCh38.dna.chromosome.11.fa", "/home/cwang/Desktop/dataset/Homo_sapiens.GRCh38.dna.chromosome.11.fa", "/home/cwang/Desktop/dataset/HG01537.chrom11.ILLUMINA.bwa.IBS.low_coverage.20130415.sam", "/home/cwang/Desktop/dataset/HG01537.chrom11.ILLUMINA.bwa.IBS.low_coverage.20130415.untrust.mlp") ;  
 //bam_mpileup(argc, argv+1);
 // The parameters are not using in the new version again
  char* argvx[] = {"bcftools", 
                  "call", 
                  "-mv",             // Default paramater
                  "mpileup1.tmp"   // Input Sam file used for variant cal   // Output File
                  };  

  main_vcfcall(3, argvx + 1, "/home/cwang/Desktop/dataset/NA12234.chrom20.ILLUMINA.bwa.CEU.low_coverage.20130415.origin.mlp");
  return 0;
}
#endif