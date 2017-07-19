import os
import sys

#This is to create the command string.
string_command = "diff bcftools-untrusted/" + sys.argv[1] + " sgxbcftools/sgx/enclave_bcfenclave/trusted/" + sys.argv[1]
os.system(string_command)
