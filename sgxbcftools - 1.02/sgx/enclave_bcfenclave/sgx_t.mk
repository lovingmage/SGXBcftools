######## Intel(R) SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -Wall -Wc++-compat
else
        SGX_COMMON_CFLAGS += -O2 -Wall -Wc++-compat 
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Bcfenclave_C_Files := trusted/bcfenclave.c \
					trusted/kfunc.c \
					trusted/errmod.c\
					trusted/kstring.c\
					trusted/md5.c\
					trusted/hfile.c\
					trusted/bgzf.c\
					trusted/version.c\
					trusted/hts.c\
					trusted/tbx.c\
					trusted/sam.c\
					trusted/bam_sample.c\
					trusted/vcmp.c\
					trusted/regidx.c\
					trusted/faidx.c\
					trusted/vcf.c\
					trusted/mcall.c\
					trusted/bam2bcf.c\
					trusted/mpileup.c\
					trusted/iocrypto.c\
					trusted/probaln.c\
					trusted/realn.c\
					trusted/kmin.c\
					trusted/prob1.c\
					trusted/ploidy.c\
					trusted/gvcf.c\
					trusted/synced_bcf_reader.c\
					trusted/bcf_sr_sort.c\
					trusted/em.c\
					trusted/ccall.c\
					trusted/vcfcall.c

Bcfenclave_Include_Paths := -IInclude -Itrusted -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Bcfenclave_Include_Paths) -fno-builtin-printf -I.
Bcfenclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)

Bcfenclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/bcfenclave.lds\

Bcfenclave_C_Objects := $(Bcfenclave_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: bcfenclave.so
	@echo "Build enclave bcfenclave.so [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the bcfenclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo
else
all: bcfenclave.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## bcfenclave Objects ########

trusted/bcfenclave_t.c: $(SGX_EDGER8R) ./trusted/bcfenclave.edl
	@cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/bcfenclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

trusted/bcfenclave_t.o: ./trusted/bcfenclave_t.c
	@$(CC) $(Bcfenclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/%.o: trusted/%.c
	@$(CC) $(Bcfenclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

bcfenclave.so: trusted/bcfenclave_t.o $(Bcfenclave_C_Objects)
	@$(CXX) $^ -o $@ $(Bcfenclave_Link_Flags)
	@echo "LINK =>  $@"

bcfenclave.signed.so: bcfenclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/bcfenclave_private.pem -enclave bcfenclave.so -out $@ -config trusted/bcfenclave.config.xml
	@echo "SIGN =>  $@"
clean:
	@rm -f bcfenclave.* trusted/bcfenclave_t.*  $(Bcfenclave_C_Objects)
