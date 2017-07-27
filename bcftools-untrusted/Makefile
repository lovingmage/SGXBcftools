# Makefile for bcftools, utilities for Variant Call Format VCF/BCF files.
#
#   Copyright (C) 2012-2017 Genome Research Ltd.
#
#   Author: Petr Danecek <pd3@sanger.ac.uk>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

PROG=       bcftools
TEST_PROG=  test/test-rbuf test/test-regidx


all: $(PROG)

# Adjust $(HTSDIR) to point to your top-level htslib directory
HTSDIR = htslib-1.4
#include $(HTSDIR)/htslib.mk
#include $(HTSDIR)/htslib_static.mk
#HTSLIB = $(HTSDIR)/libhts.a
HTSLIB_static_LDFLAGS = 
HTSLIB_static_LIBS = -lz -lm
HTSLIB_LDFLAGS = $(HTSLIB_static_LDFLAGS)
HTSLIB_LIBS = $(HTSLIB_static_LIBS)

CC       = gcc
CPPFLAGS =
CFLAGS   = -g -Wall -Wc++-compat -O2
LDFLAGS  =
LIBS     =

ifeq "$(shell uname -s)" "Darwin"
DYNAMIC_FLAGS = -Wl,-export_dynamic
else
DYNAMIC_FLAGS = -rdynamic
endif

# TODO Use configure or htslib.pc to add -rdynamic/-ldl conditionally
ALL_CPPFLAGS = -I. $(HTSLIB_CPPFLAGS) $(CPPFLAGS)
ALL_LDFLAGS  = $(DYNAMIC_FLAGS) $(HTSLIB_LDFLAGS) $(LDFLAGS)
ALL_LIBS     = -lm -lz -ldl $(LIBS)

OBJS     = main.o \
           mcall.o vcmp.o \
           version.o \
           regidx.o \
           mpileup.o bam2bcf.o bam_sample.o bcf_sr_sort.o\
	bam2bcf_indel.o\
	kfunc.o \
	kstring.o \
	bgzf.o \
	errmod.o \
	faidx.o \
	hfile.o \
	hts.o \
	md5.o \
	sam.o \
	tbx.o \
	vcf.o \
	prob1.o \
	ploidy.o \
	gvcf.o \
	synced_bcf_reader.o \
	kmin.o \
	em.o \
	ccall.o \
	vcfcall.o \
	realn.o \
	probaln.o


EXTRA_CPPFLAGS = -I. -I$(HTSDIR) -DPLUGINPATH=\"$(pluginpath)\"
GSL_LIBS       =

# The polysomy command is not compiled by default because it brings dependency
# on libgsl. The command can be compiled wth `make USE_GPL=1`. See the INSTALL
# and LICENSE documents to understand license implications.
ifdef USE_GPL
    EXTRA_CPPFLAGS += -DUSE_GPL
    OBJS += polysomy.o peakfit.o
    GSL_LIBS = -lgsl -lcblas
endif

prefix      = /usr/local
exec_prefix = $(prefix)
bindir      = $(exec_prefix)/bin
libdir      = $(exec_prefix)/lib
libexecdir  = $(exec_prefix)/libexec
mandir      = $(prefix)/share/man
man1dir     = $(mandir)/man1

plugindir   = $(libexecdir)/bcftools
pluginpath  = $(plugindir)

MKDIR_P = mkdir -p
INSTALL = install -p
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA    = $(INSTALL) -m 644regidx-mp.o
INSTALL_DIR     = $(MKDIR_P) -m 755

MISC_PROGRAMS = plot-vcfstats vcfutils.pl plugins/color-chrs.pl

all:$(PROG)

# See htslib/Makefile
PACKAGE_VERSION = 1.4
ifneq "$(wildcard .git)" ""
PACKAGE_VERSION := $(shell git describe --always --dirty)
DOC_VERSION :=  $(shell git describe --always)+
DOC_DATE := $(shell date +'%Y-%m-%d %R %Z')
version.h: $(if $(wildcard version.h),$(if $(findstring "$(PACKAGE_VERSION)",$(shell cat version.h)),,force))
endif
version.h:
	echo '#define BCFTOOLS_VERSION "$(PACKAGE_VERSION)"' > $@


.SUFFIXES:.c .o
.PHONY:all clean clean-all clean-plugins distclean install lib tags test testclean force plugins docs

force:

.c.o:
	$(CC) $(CFLAGS) $(EXTRA_CPPFLAGS) $(ALL_CPPFLAGS) -c -o $@ $<



# Plugin rules
PLUGINC = $(foreach dir, plugins, $(wildcard $(dir)/*.c))
PLUGINS = $(PLUGINC:.c=.so)
PLUGINM = $(PLUGINC:.c=.mk)

ifeq "$(shell uname -s)" "Darwin"
$(PLUGINS): | bcftools
PLUGIN_FLAGS = -bundle -bundle_loader bcftools
else
PLUGIN_FLAGS = -fPIC -shared
endif

%.so: %.c version.h version.c
	$(CC) $(PLUGIN_FLAGS) $(CFLAGS) $(EXTRA_CPPFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ version.c $< $(LIBS)

-include $(PLUGINM)


htslib_bgzf_h = htslib/bgzf.h $(htslib_hts_defs_h)
htslib_faidx_h = htslib/faidx.h $(htslib_hts_defs_h)
htslib_hfile_h = htslib/hfile.h $(htslib_hts_defs_h)
htslib_hts_h = htslib/hts.h $(htslib_hts_defs_h)
htslib_hts_defs_h = htslib/hts_defs.h
htslib_hts_endian_h = htslib/hts_endian.h
htslib_kfunc_h = htslib/kfunc.h
htslib_khash_h = htslib/khash.h
htslib_khash_str2int_h = htslib/khash_str2int.h $(htslib_khash_h)
htslib_klist_h = htslib/klist.h
htslib_knetfile_h = htslib/knetfile.h
htslib_kseq_h = htslib/kseq.h
htslib_ksort_h = htslib/ksort.h
htslib_kstring_h = htslib/kstring.h
htslib_sam_h = htslib/sam.h $(htslib_hts_h)
htslib_tbx_h = htslib/tbx.h $(htslib_hts_h)
htslib_vcf_h = htslib/vcf.h $(htslib_hts_h) $(htslib_kstring_h) $(htslib_hts_defs_h) $(htslib_hts_endian_h)
hts_internal_h = hts_internal.h $(htslib_hts_h)
hfile_internal_h = hfile_internal.h $(htslib_hfile_h)
prob1_h = prob1.h $(htslib_vcf_h) $(call_h)
ploidy_h = ploidy.h regidx.h
htslib_synced_bcf_reader_h = htslib/synced_bcf_reader.h $(htslib_hts_h) $(htslib_vcf_h) $(htslib_tbx_h)
#Done, Check
bcftools_h = bcftools.h $(htslib_hts_defs_h) $(htslib_vcf_h)
call_h = call.h $(htslib_vcf_l_h) $(htslib_synced_bcf_reader_h) vcmp.h
bam2bcf_h = bam2bcf.h $(htslib_hts_h) $(htslib_vcf_l_h)
#Done, Check
bam_sample_h = bam_sample.h $(htslib_sam_h)

main.o: main.c $(htslib_hts_h) version.h $(bcftools_h)

mcall.o: mcall.c $(htslib_kfunc_h) $(call_h)
#Done
vcmp.o: vcmp.c $(htslib_hts_h) vcmp.h
#Done
regidx.o: regidx.c $(htslib_hts_h) $(htslib_kstring_h) $(htslib_kseq_h) $(htslib_khash_str2int_h) regidx.h
#Done
mpileup.o: mpileup.c $(htslib_sam_h) $(htslib_faidx_h) $(htslib_kstring_h) $(htslib_khash_str2int_h) regidx.h $(bcftools_h) $(call_h) $(bam2bcf_h) $(bam_sample_h)
#Done
bam_sample.o: $(bam_sample_h) $(htslib_hts_h) $(htslib_khash_str2int_h)
#Done, Check
version.o: version.h version.c
#Done
bgzf.o bgzf.pico: bgzf.c config.h $(htslib_hts_h) $(htslib_bgzf_h) $(htslib_hfile_h) $(htslib_khash_h)
#Done
errmod.o errmod.pico: errmod.c config.h $(htslib_hts_h) $(htslib_ksort_h)
#Done
kstring.o kstring.pico: kstring.c config.h $(htslib_kstring_h)
#Done
hfile.o hfile.pico: hfile.c config.h $(htslib_hfile_h) $(hfile_internal_h) $(hts_internal_h) $(htslib_khash_h)
#Done
hts.o hts.pico: hts.c config.h $(htslib_hts_h) $(htslib_bgzf_h) $(htslib_hfile_h) version.h $(hts_internal_h) $(htslib_khash_h) $(htslib_kseq_h) $(htslib_ksort_h) 
#Done
vcf.o vcf.pico: vcf.c config.h $(htslib_vcf_h) $(htslib_bgzf_h) $(htslib_tbx_h) $(htslib_hfile_h) $(hts_internal_h) $(htslib_khash_str2int_h) $(htslib_kstring_h) $(htslib_khash_h) $(htslib_kseq_h) $(htslib_hts_endian_h)
#Done, Check
sam.o sam.pico: sam.c config.h $(htslib_sam_h) $(htslib_bgzf_h) $(hts_internal_h) $(htslib_hfile_h) $(htslib_khash_h) $(htslib_kseq_h) $(htslib_kstring_h) $(htslib_hts_endian_h) 
#Done, Check
tbx.o tbx.pico: tbx.c config.h $(htslib_tbx_h) $(htslib_bgzf_h) $(hts_internal_h) $(htslib_khash_h)
#Done, Check
faidx.o faidx.pico: faidx.c config.h $(htslib_bgzf_h) $(htslib_faidx_h) $(htslib_hfile_h) $(htslib_khash_h) $(htslib_kstring_h) $(hts_internal_h)
#Done, Check
kfunc.o kfunc.pico: kfunc.c config.h $(htslib_kfunc_h)
#Done, Check
md5.o md5.pico: md5.c config.h $(htslib_hts_h) $(htslib_hts_endian_h)
#Done, Check
realn.o realn.pico: realn.c config.h $(htslib_hts_h) $(htslib_sam_h)
#Done, Check
probaln.o probaln.pico: probaln.c config.h $(htslib_hts_h)
#Done, Check
prob1.o: prob1.c $(prob1_h)
#Done, Check
ploidy.o: ploidy.c regidx.h $(htslib_khash_str2int_h) $(htslib_kseq_h) $(htslib_hts_h) $(bcftools_h) $(ploidy_h)
#Done, Check
gvcf.o: gvcf.c gvcf.h $(call_h)
#Done, Check
bcf_sr_sort.o bcf_sr_sort.pico: bcf_sr_sort.c config.h bcf_sr_sort.h $(htslib_kseq_h) $(htslib_khash_str2int_h)
#Done, Check
synced_bcf_reader.o synced_bcf_reader.pico: synced_bcf_reader.c config.h bcf_sr_sort.h $(htslib_synced_bcf_reader_h) $(htslib_kseq_h) $(htslib_khash_str2int_h) $(htslib_bgzf_h)
#Done, Check
ccall.o: ccall.c $(htslib_kfunc_h) $(call_h) kmin.h $(prob1_h)
#Done, Check
kmin.o: kmin.c kmin.h
#Done, Check
em.o: em.c $(htslib_vcf_h) kmin.h $(call_h)
#Done, Check
vcfcall.o: vcfcall.c $(htslib_vcf_h) $(htslib_kfunc_h) $(htslib_synced_bcf_reader_h) $(htslib_khash_str2int_h) $(bcftools_h) $(call_h) $(prob1_h) $(ploidy_h)
#Done, Check

bcftools: $(OBJS)
	$(CC) $(ALL_LDFLAGS) -o $@ $(OBJS) $(HTSLIB_LIBS) $(GSL_LIBS) $(ALL_LIBS)


# To avoid an install dependency on asciidoc, the make install target
# does not depend on doc/bcftools.1
# bcftools.1 is a generated file from the asciidoc bcftools.txt file.
# Since there is no make dependency, bcftools.1 can be out-of-date and
# make docs can be run to update if asciidoc is available
install: $(PROG)
	$(INSTALL_DIR) $(DESTDIR)$(bindir) $(DESTDIR)$(man1dir) $(DESTDIR)$(plugindir)
	$(INSTALL_PROGRAM) $(PROG) $(MISC_PROGRAMS) $(DESTDIR)$(bindir)
	$(INSTALL_DATA) doc/bcftools.1 $(DESTDIR)$(man1dir)
	$(INSTALL_PROGRAM) plugins/*.so $(DESTDIR)$(plugindir)

clean: testclean clean-plugins
	-rm -f gmon.out *.o *~ $(PROG) version.h plugins/*.so plugins/*.P
	-rm -rf *.dSYM plugins/*.dSYM test/*.dSYM

clean-plugins:
	-rm -f plugins/*.so plugins/*.P
	-rm -rf plugins/*.dSYM

testclean:
	-rm -f test/*.o test/*~ $(TEST_PROG)

distclean: clean
	-rm -f TAGS

clean-all: clean clean-htslib

tags:
	ctags -f TAGS *.[ch] plugins/*.[ch]
