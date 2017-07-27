/*  vcfcall.c -- SNP/indel variant calling from VCF/BCF.

    Copyright (C) 2013-2016 Genome Research Ltd.

    Author: Petr Danecek <pd3@sanger.ac.uk>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.  */

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <math.h>
#include "htslib/vcf.h"
#include <time.h>
#include <stdarg.h>
#include "htslib/kfunc.h"
#include "htslib/synced_bcf_reader.h"
#include "htslib/khash_str2int.h"
#include <ctype.h>
#include "bcftools.h"
#include "call.h"
#include "ploidy.h"
#include "gvcf.h"

void printf(const char *format, ...);

#ifdef _WIN32
#define srand48(x) srand(x)
#define lrand48() rand()
#endif

#define CF_NO_GENO      1
#define CF_INS_MISSED   (1<<1)
#define CF_CCALL        (1<<2)
//                      (1<<3)
//                      (1<<4)
//                      (1<<5)
#define CF_ACGT_ONLY    (1<<6)
#define CF_QCALL        (1<<7)
#define CF_ADJLD        (1<<8)
#define CF_NO_INDEL     (1<<9)
#define CF_ANNO_MAX     (1<<10)
#define CF_MCALL        (1<<11)
#define CF_PAIRCALL     (1<<12)
#define CF_QCNT         (1<<13)
#define CF_INDEL_ONLY   (1<<14)

typedef struct
{
    int flag;   // combination of CF_* flags above
    int output_type, n_threads, record_cmd_line;
    htsFile *bcf_in, *out_fh;
    char *bcf_fname, *output_fname;
    char **samples;             // for subsampling and ploidy
    int nsamples, *samples_map; // mapping from output sample names to original VCF
    char *regions, *targets;    // regions to process
    int regions_is_file, targets_is_file;

    char *samples_fname;
    int samples_is_file;
    int *sample2sex;    // mapping for ploidy. If negative, interpreted as -1*ploidy
    int *sex2ploidy, *sex2ploidy_prev, nsex;
    ploidy_t *ploidy;
    gvcf_t *gvcf;

    bcf1_t *missed_line;
    call_t aux;     // parameters and temporary data

    int argc;
    char **argv;

    //  int flag, prior_type, n1, n_sub, *sublist, n_perm;
    //  uint32_t *trio_aux;
    //  char *prior_file, **subsam;
    //  uint8_t *ploidy;
    //  double theta, pref, indel_frac, min_smpl_frac, min_lrt;
    // Permutation tests
    //  int n_perm, *seeds;
    //  double min_perm_p;
    //  void *bed;
}
args_t;

static char **add_sample(void *name2idx, char **lines, int *nlines, int *mlines, char *name, char sex, int *ith)
{
    int ret = khash_str2int_get(name2idx, name, ith);
    if ( ret==0 ) return lines;

    hts_expand(char*,(*nlines+1),*mlines,lines);
    int len = strlen(name);
    lines[*nlines] = (char*) malloc(len+3);
    memcpy(lines[*nlines],name,len);
    lines[*nlines][len]   = ' ';
    lines[*nlines][len+1] = sex;
    lines[*nlines][len+2] = 0;
    *ith = *nlines;
    (*nlines)++;
    khash_str2int_set(name2idx, strdup(name), *ith);
    return lines;
}

typedef struct
{
    const char *alias, *about, *ploidy;
}
ploidy_predef_t;


// only 5 columns are required and the first is ignored:
//  ignored,sample,father(or 0),mother(or 0),sex(1=M,2=F)
static char **parse_ped_samples(call_t *call, char **vals, int nvals, int *nsmpl)
{
    int i, j, mlines = 0, nlines = 0;
    kstring_t str = {0,0,0}, fam_str = {0,0,0};
    void *name2idx = khash_str2int_init();
    char **lines = NULL;
    for (i=0; i<nvals; i++)
    {
        str.l = 0;
        kputs(vals[i], &str);
        char *col_ends[5], *tmp = str.s;
        j = 0;
        while ( *tmp && j<5 )
        {
            if ( isspace(*tmp) )
            {
                *tmp = 0;
                ++tmp;
                while ( isspace(*tmp) ) tmp++;  // allow multiple spaces
                col_ends[j] = tmp-1;
                j++;
                continue;
            }
            tmp++;
        }
        if ( j!=5 ) break;

        char sex = col_ends[3][1]=='1' ? 'M' : 'F';
        lines = add_sample(name2idx, lines, &nlines, &mlines, col_ends[0]+1, sex, &j);
        if ( strcmp(col_ends[1]+1,"0") && strcmp(col_ends[2]+1,"0") )   // father and mother
        {
            call->nfams++;
            hts_expand(family_t, call->nfams, call->mfams, call->fams);
            family_t *fam = &call->fams[call->nfams-1];
            fam_str.l = 0;
            ksprintf(&fam_str,"father=%s, mother=%s, child=%s", col_ends[1]+1,col_ends[2]+1,col_ends[0]+1);
            fam->name = strdup(fam_str.s);

            if ( !khash_str2int_has_key(name2idx, col_ends[1]+1) )
                lines = add_sample(name2idx, lines, &nlines, &mlines, col_ends[1]+1, 'M', &fam->sample[FATHER]);
            if ( !khash_str2int_has_key(name2idx, col_ends[2]+1) )
                lines = add_sample(name2idx, lines, &nlines, &mlines, col_ends[2]+1, 'F', &fam->sample[MOTHER]);

            khash_str2int_get(name2idx, col_ends[0]+1, &fam->sample[CHILD]);
            khash_str2int_get(name2idx, col_ends[1]+1, &fam->sample[FATHER]);
            khash_str2int_get(name2idx, col_ends[2]+1, &fam->sample[MOTHER]);
        }
    }
    free(str.s);
    free(fam_str.s);
    khash_str2int_destroy_free(name2idx);

    if ( i!=nvals ) // not a ped file
    {
        if ( i>0 ) printf("Could not parse samples, not a PED format.\n");
        return NULL;
    }
    *nsmpl = nlines;
    return lines;
}


/*
 *  Reads sample names and their ploidy (optional) from a file.
 *  Alternatively, if no such file exists, the file name is interpreted
 *  as a comma-separated list of samples. When ploidy is not present,
 *  the default ploidy 2 is assumed.
 */
static void set_samples(args_t *args, const char *fn, int is_file)
{
    int i, nlines;
    char **lines = hts_readlist(fn, is_file, &nlines);
    if ( !lines ) printf("Could not read the file: %s\n", fn);

    int nsmpls;
    char **smpls = parse_ped_samples(&args->aux, lines, nlines, &nsmpls);
    if ( smpls )
    {
        for (i=0; i<nlines; i++) free(lines[i]);
        free(lines);
        lines = smpls;
        nlines = nsmpls;
    }

    args->samples_map = (int*) malloc(sizeof(int)*bcf_hdr_nsamples(args->aux.hdr)); // for subsetting
    args->sample2sex  = (int*) malloc(sizeof(int)*bcf_hdr_nsamples(args->aux.hdr));
    int dflt_sex_id = ploidy_nsex(args->ploidy) - 1;
    for (i=0; i<bcf_hdr_nsamples(args->aux.hdr); i++) args->sample2sex[i] = dflt_sex_id;

    int *old2new = (int*) malloc(sizeof(int)*bcf_hdr_nsamples(args->aux.hdr));
    for (i=0; i<bcf_hdr_nsamples(args->aux.hdr); i++) old2new[i] = -1;

    int nsmpl = 0, map_needed = 0;
    for (i=0; i<nlines; i++)
    {
        char *ss = lines[i];
        while ( *ss && isspace(*ss) ) ss++;
        if ( !*ss ) printf("Could not parse: %s\n", lines[i]);
        if ( *ss=='#' ) continue;
        char *se = ss;
        while ( *se && !isspace(*se) ) se++;
        char x = *se, *xptr = se; *se = 0;

        int ismpl = bcf_hdr_id2int(args->aux.hdr, BCF_DT_SAMPLE, ss);
        if ( ismpl < 0 ) { printf( "Warning: No such sample in the VCF: %s\n",ss); continue; }
        if ( old2new[ismpl] != -1 ) { printf( "Warning: The sample is listed multiple times: %s\n",ss); continue; }

        ss = se+1;
        while ( *ss && isspace(*ss) ) ss++;
        if ( !*ss ) ss = "2";   // default ploidy
        se = ss;
        while ( *se && !isspace(*se) ) se++;
        if ( se==ss ) { *xptr = x; printf("Could not parse: \"%s\"\n", lines[i]); }

        if ( ss[1]==0 && (ss[0]=='0' || ss[0]=='1' || ss[0]=='2') )
            args->sample2sex[nsmpl] = -1*(ss[0]-'0');
        else
            args->sample2sex[nsmpl] = ploidy_add_sex(args->ploidy, ss);

        if ( ismpl!=nsmpl ) map_needed = 1;
        args->samples_map[nsmpl] = ismpl;
        old2new[ismpl] = nsmpl;
        nsmpl++;
    }

    for (i=0; i<args->aux.nfams; i++)
    {
        int j, nmiss = 0;
        family_t *fam = &args->aux.fams[i];
        for (j=0; j<3; j++)
        {
            fam->sample[i] = old2new[fam->sample[i]];
            if ( fam->sample[i]<0 ) nmiss++;
        }
        assert( nmiss==0 || nmiss==3 );
    }
    free(old2new);

    if ( !map_needed ) { free(args->samples_map); args->samples_map = NULL; }

    args->nsamples = nsmpl;
    args->samples = lines;
}

static void init_missed_line(args_t *args)
{
    int i;
    for (i=0; i<bcf_hdr_nsamples(args->aux.hdr); i++)
    {
        args->aux.gts[i*2]   = bcf_gt_missing;
        args->aux.gts[i*2+1] = bcf_int32_vector_end;
    }
    args->missed_line = bcf_init1();
    bcf_update_genotypes(args->aux.hdr, args->missed_line, args->aux.gts, 2*bcf_hdr_nsamples(args->aux.hdr));
    bcf_float_set_missing(args->missed_line->qual);
}

static void print_missed_line(bcf_sr_regions_t *regs, void *data)
{
    args_t *args = (args_t*) data;
    call_t *call = &args->aux;
    bcf1_t *missed = args->missed_line;

    char *ss = regs->line.s;
    int i = 0;
    while ( i<args->aux.srs->targets_als-1 && *ss )
    {
        if ( *ss=='\t' ) i++;
        ss++;
    }
    if ( !*ss ) printf("Could not parse: [%s] (%d)\n", regs->line.s,args->aux.srs->targets_als);

    missed->rid  = bcf_hdr_name2id(call->hdr,regs->seq_names[regs->prev_seq]);
    missed->pos  = regs->start;
    bcf_update_alleles_str(call->hdr, missed,ss);

    bcf_write1(args->out_fh, call->hdr, missed);
}

static void init_data(args_t *args)
{
    args->aux.srs = bcf_sr_init();

    // Open files for input and output, initialize structures
    if ( args->targets )
    {
        if ( bcf_sr_set_targets(args->aux.srs, args->targets, args->targets_is_file, args->aux.flag&CALL_CONSTR_ALLELES ? 3 : 0)<0 )
            printf("Failed to read the targets: %s\n", args->targets);

        if ( args->aux.flag&CALL_CONSTR_ALLELES && args->flag&CF_INS_MISSED )
        {
            args->aux.srs->targets->missed_reg_handler = print_missed_line;
            args->aux.srs->targets->missed_reg_data = args;
        }
    }
    if ( args->regions )
    {
        if ( bcf_sr_set_regions(args->aux.srs, args->regions, args->regions_is_file)<0 )
            printf("Failed to read the regions: %s\n", args->regions);
    }

    if ( !bcf_sr_add_reader(args->aux.srs, args->bcf_fname) ) printf("Failed to open %s \n", args->bcf_fname );
    args->aux.hdr = bcf_sr_get_header(args->aux.srs,0);

    int i;
    if ( args->samples_fname )
    {
        set_samples(args, args->samples_fname, args->samples_is_file);
        if ( args->aux.flag&CALL_CONSTR_TRIO )
        {
            if ( 3*args->aux.nfams!=args->nsamples ) printf("Expected only trios in %s, sorry!\n", args->samples_fname);
            printf( "Detected %d samples in %d trio families\n", args->nsamples,args->aux.nfams);
        }
    }
    if ( args->ploidy  )
    {
        args->nsex = ploidy_nsex(args->ploidy);
        args->sex2ploidy = (int*) calloc(args->nsex,sizeof(int));
        args->sex2ploidy_prev = (int*) calloc(args->nsex,sizeof(int));
        if ( !args->nsamples )
        {
            args->nsamples = bcf_hdr_nsamples(args->aux.hdr);
            args->sample2sex = (int*) malloc(sizeof(int)*args->nsamples);
            for (i=0; i<args->nsamples; i++) args->sample2sex[i] = args->nsex - 1;
        }
    }
    if ( args->nsamples )
    {
        args->aux.ploidy = (uint8_t*) malloc(args->nsamples);
        for (i=0; i<args->nsamples; i++) args->aux.ploidy[i] = ploidy_max(args->ploidy);
        for (i=0; i<args->nsex; i++) args->sex2ploidy_prev[i] = ploidy_max(args->ploidy);
        for (i=0; i<args->nsamples; i++) 
            if ( args->sample2sex[i] >= args->nsex ) args->sample2sex[i] = args->nsex - 1;
    }

    if ( args->gvcf )
    {
        int id = bcf_hdr_id2int(args->aux.hdr,BCF_DT_ID,"DP");
        if ( id<0 || !bcf_hdr_idinfo_exists(args->aux.hdr,BCF_HL_FMT,id) ) printf("--gvcf output mode requires FORMAT/DP tag, which is not present in the input header\n");
        gvcf_update_header(args->gvcf, args->aux.hdr);
    }

    if ( args->samples_map )
    {
        args->aux.hdr = bcf_hdr_subset(bcf_sr_get_header(args->aux.srs,0), args->nsamples, args->samples, args->samples_map);
        if ( !args->aux.hdr ) printf("printf occurred while subsetting samples\n");
        for (i=0; i<args->nsamples; i++)
            if ( args->samples_map[i]<0 ) printf("No such sample: %s\n", args->samples[i]);
        if ( !bcf_hdr_nsamples(args->aux.hdr) ) printf("No matching sample found\n");
    }
    else
    {
        args->aux.hdr = bcf_hdr_dup(bcf_sr_get_header(args->aux.srs,0));
        if ( args->samples )
        {
            for (i=0; i<args->nsamples; i++)
                if ( bcf_hdr_id2int(args->aux.hdr,BCF_DT_SAMPLE,args->samples[i])<0 )
                    printf("No such sample: %s\n", args->samples[i]);
        }
    }

    args->out_fh = hts_open(args->output_fname, hts_bcf_wmode(args->output_type));
    if ( args->out_fh == NULL ) printf("Can't write to \"%s\" \n", args->output_fname);
    if ( args->flag & CF_QCALL )
        return;

    if ( args->flag & CF_MCALL )
        call_init(&args->aux);


    bcf_hdr_remove(args->aux.hdr, BCF_HL_INFO, "QS");
    bcf_hdr_remove(args->aux.hdr, BCF_HL_INFO, "I16");
    bcf_hdr_write(args->out_fh, args->aux.hdr);

    if ( args->flag&CF_INS_MISSED ) init_missed_line(args);
}

static void destroy_data(args_t *args)
{
    if ( args->flag & CF_MCALL ) call_destroy(&args->aux);
    else if ( args->flag & CF_QCALL ) qcall_destroy(&args->aux);
    int i;
    if ( args->samples )
    {
        for (i=0; i<args->nsamples; i++) free(args->samples[i]);
    }
    if ( args->aux.fams )
    {
        for (i=0; i<args->aux.nfams; i++) free(args->aux.fams[i].name);
        free(args->aux.fams);
    }
    if ( args->missed_line ) bcf_destroy(args->missed_line);
    ploidy_destroy(args->ploidy);
    free(args->sex2ploidy);
    free(args->sex2ploidy_prev);
    free(args->samples);
    free(args->samples_map);
    free(args->sample2sex);
    free(args->aux.ploidy);
    if ( args->gvcf ) gvcf_destroy(args->gvcf);
    bcf_hdr_destroy(args->aux.hdr);
    hts_close(args->out_fh);
    bcf_sr_destroy(args->aux.srs);
}

static void set_ploidy(args_t *args, bcf1_t *rec)
{
    ploidy_query(args->ploidy,(char*)bcf_seqname(args->aux.hdr,rec),rec->pos,args->sex2ploidy,NULL,NULL);

    int i;
    for (i=0; i<args->nsex; i++)
        if ( args->sex2ploidy[i]!=args->sex2ploidy_prev[i] ) break;

    if ( i==args->nsex ) return;    // ploidy same as previously

    for (i=0; i<args->nsamples; i++)
    {
        if ( args->sample2sex[i]<0 )
            args->aux.ploidy[i] = -1*args->sample2sex[i];
        else
            args->aux.ploidy[i] = args->sex2ploidy[args->sample2sex[i]];
    }
    int *tmp = args->sex2ploidy; args->sex2ploidy = args->sex2ploidy_prev; args->sex2ploidy_prev = tmp;
}

int main_vcfcall(int argc, char *argv[], char* mpileupFilename, char* callfile)
{
    args_t args;
    memset(&args, 0, sizeof(args_t));
    args.argc = argc; args.argv = argv;
    args.aux.prior_type = -1;
    args.aux.indel_frac = -1;
    args.aux.theta      = 1.1e-3;
    args.aux.pref       = 0.5;
    args.aux.min_perm_p = 0.01;
    args.aux.min_lrt    = 1;
    args.flag           = CF_ACGT_ONLY;
    args.output_fname   = "-";
    args.output_type    = FT_VCF;
    args.n_threads = 0;
    args.record_cmd_line = 1;
    args.aux.trio_Pm_SNPs = 1 - 1e-8;
    args.aux.trio_Pm_ins  = args.aux.trio_Pm_del  = 1 - 1e-9;
    args.aux.flag |= CALL_VARONLY;
    args.flag |= CF_MCALL;
    args.output_fname = callfile;
    args.ploidy = ploidy_init_string("* * * 0 0\n* * * 1 1\n* * * 2 2\n",2);
    args.bcf_fname = mpileupFilename;

    if ( args.aux.n_perm && args.aux.ngrp1_samples<=0 ) printf("Expected -1 with -U\n");    // not sure about this, please fix
    if ( args.aux.flag & CALL_CONSTR_ALLELES )
    {
        if ( !args.targets ) printf("Expected -t or -T with \"-C alleles\"\n");
        if ( !(args.flag & CF_MCALL) ) printf("The \"-C alleles\" mode requires -m\n");
    }
    if ( args.flag & CF_INS_MISSED && !(args.aux.flag&CALL_CONSTR_ALLELES) ) printf("The -i option requires -C alleles\n");
    if ( args.aux.flag&CALL_VARONLY && args.gvcf ) printf("The two options cannot be combined: --variants-only and --gvcf\n");
    init_data(&args);

    while ( bcf_sr_next_line(args.aux.srs) )
    {
        bcf1_t *bcf_rec = args.aux.srs->readers[0].buffer[0];
        if ( args.samples_map ) bcf_subset(args.aux.hdr, bcf_rec, args.nsamples, args.samples_map);
        bcf_unpack(bcf_rec, BCF_UN_STR);

        // Skip unwanted sites
        int i, is_indel = bcf_is_snp(bcf_rec) ? 0 : 1;
        if ( (args.flag & CF_INDEL_ONLY) && !is_indel ) continue;
        if ( (args.flag & CF_NO_INDEL) && is_indel ) continue;
        if ( (args.flag & CF_ACGT_ONLY) && (bcf_rec->d.allele[0][0]=='N' || bcf_rec->d.allele[0][0]=='n') ) continue;   // REF[0] is 'N'

        // Which allele is symbolic? All SNPs should have it, but not indels
        args.aux.unseen = 0;
        for (i=1; i<bcf_rec->n_allele; i++)
        {
            if ( bcf_rec->d.allele[i][0]=='X' ) { args.aux.unseen = i; break; }  // old X
            if ( bcf_rec->d.allele[i][0]=='<' )
            {
                if ( bcf_rec->d.allele[i][1]=='X' && bcf_rec->d.allele[i][2]=='>' ) { args.aux.unseen = i; break; } // old <X>
                if ( bcf_rec->d.allele[i][1]=='*' && bcf_rec->d.allele[i][2]=='>' ) { args.aux.unseen = i; break; } // new <*>
            }
        }
        int is_ref = (bcf_rec->n_allele==1 || (bcf_rec->n_allele==2 && args.aux.unseen>0)) ? 1 : 0;

        if ( is_ref && args.aux.flag&CALL_VARONLY )
            continue;

        bcf_unpack(bcf_rec, BCF_UN_ALL);
        if ( args.nsex ) set_ploidy(&args, bcf_rec);

        // Various output modes: QCall output (todo)
        if ( args.flag & CF_QCALL )
        {
            qcall(&args.aux, bcf_rec);
            continue;
        }

        // Calling modes which output VCFs
        int ret = -2;
        if ( args.flag & CF_MCALL )
            ret = call(&args.aux, bcf_rec);
        if ( ret==-1 ) printf("Something is wrong\n");
        else if ( ret==-2 ) continue;   // skip the site

        // Normal output
        if ( (args.aux.flag & CALL_VARONLY) && ret==0 && !args.gvcf ) continue;     // not a variant
        if ( args.gvcf )
            bcf_rec = gvcf_write(args.gvcf, args.out_fh, args.aux.hdr, bcf_rec, ret==1?1:0);
        if ( bcf_rec )
            bcf_write1(args.out_fh, args.aux.hdr, bcf_rec);
    }
    if ( args.gvcf ) gvcf_write(args.gvcf, args.out_fh, args.aux.hdr, NULL, 0);
    if ( args.flag & CF_INS_MISSED ) bcf_sr_regions_flush(args.aux.srs->targets);
    destroy_data(&args);
    return 0;
}