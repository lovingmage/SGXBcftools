# SGXBcftools
SGXBCFtools implements utilities for variant calling (in conjunction with
SAMtools) and manipulating VCF and BCF files in a secure manner.  The program 
is intended to support secure variant calling computation based on original
Bcftools.

System Requirements
===================

SGXBCFtools depend on the zlib library <http://zlib.net>, the bzip2
library <http://bzip.org/> and liblzma <http://tukaani.org/xz/>.  Building
them requires development files to be installed on the build machine;
note that some Linux distributions package these separately from the library
itself (see below).

The bzip2 and liblzma dependencies can be removed if full CRAM support
is not needed - see HTSlib's INSTALL file for details.

Packages for dpkg-based Linux distributions (Debian / Ubuntu) are:

>  zlib1g-dev
>  libbz2-dev
>  liblzma-dev

Packages for rpm or yum-based Linux distributions (RedHat / Fedora / CentOS)
are:

>  zlib-devel
>  bzip2-devel
>  xz-devel

To build SGXBCFtools, you will need:

>    GNU make
>    C compiler (e.g. gcc or clang)

In addition, building the configure script requires:

>    autoheader
>    autoconf

Running the configure script uses awk, along with a number of
standard UNIX tools (cat, cp, grep, mv, rm, sed, among others).  Almost
all installations will have these already.

Running the test harness (make test) uses:

>    bash
>    perl

Building Configure
==================

This step is only needed if configure.ac has been changed, or if configure
does not exist (for example, when building from a git clone).  The
configure script and config.h.in can be built by running:

>    autoheader
>    autoconf

If you have a full GNU autotools install, you can alternatively run:

>    autoreconf

Warnings like "AC_CONFIG_SUBDIRS: you should use literals" can be ignored
or supressed using 'autoconf -Wno-syntax'.


Compilation
===========

'cd' to the bcftools directory containing the package's source and type:

>    ./configure
>    make

This SGXBCFtools release contains a modified version of HTSlib which will be 
used to build SGXBCFtools.  If you already have a system-installed HTSlib or another HTSlib
please reinstall these related packages and use the secure version of modified HTSlib shipped 
with this package.

if you would like to use the original version of BCFtools please type:

>    ./congiure 
>    make Build_Mode=ORIGIN_BUILD

Execution and Test
==========

After make, the binary sample will be generated within folder ./bcfenclave
The command line for executing binary is:
>    ./sample [reference file] [sam file] [output mpi file name] [output vcf file name]

Or use can use the python script *sample_test.py* within the same folder to run tests

