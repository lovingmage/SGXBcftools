import os
import sys
import re
import errno
from datetime import datetime

data_path = "/home/centromere/1KGenome/phase3/data/"
ref_path = "/home/centromere/1KGenome/technical/reference/phase2_reference_assembly_sequence/"
output_path = os.getcwd()

#
#    The command line for executing binary is:
#    ./sample [reference file] [sam file] [output mpi file name] [output vcf file name]
#
def execute_test(keepIntermediate):

    test_files = {
                  "NA12234.chrom20.ILLUMINA.bwa.CEU.low_coverage.20130415" : "20.fa",
                  "HG00096.chrom11.ILLUMINA.bwa.GBR.low_coverage.20120522" : "11.fa",
                  "HG00096.chrom20.ILLUMINA.bwa.GBR.low_coverage.20120522" : "20.fa",
                  "HG02600.chrom20.ILLUMINA.bwa.PJL.low_coverage.20121211" : "20.fa"}

    for i in test_files.keys():
        test_file_path = data_path + i.split(".")[0] + "/alignment/"
        curr_sam = test_file_path + i + ".sam"
        curr_ref = ref_path + test_files[i]
        curr_mlp = output_path + '/' + i + ".sgx.mlp"
        curr_vcf = output_path + '/' + i + ".sgx.call.vcf"
        curr_diff = output_path + '/' + i + ".diff"
        curr_time = output_path + '/' + i + ".time"

        #str_command_sgx = "./sample " + curr_ref + " " + curr_sam + " " + curr_mlp + " " + curr_vcf + " >> " + curr_time
        str_mlp_command_sgx = "./sample mpileup " + curr_ref + " " + curr_sam + " " + curr_mlp + " >> " + curr_time
        str_call_command_sgx = "./sample call " + curr_mlp + " " + curr_vcf + " >> " + curr_time
        real_vcf = test_file_path + i + "_bcftools_relv1.5.vcf"
        str_diff = "diff " + curr_vcf + " " + real_vcf + " >> " + curr_diff
        #print str_command_sgx
        #print str_diff
        os.system(str_mlp_command_sgx)
        os.system(str_call_command_sgx)
        os.system(str_diff)

        if (keepIntermediate is False):
            # remove intermediate files
            try:
                os.remove(curr_mlp)
            except OSError:
                print("Warning: Failed to remove ", curr_mlp)

# By default, we do not want to keep any intermediate data after the test is done.
keepIntermediate = False

# accept user preferred output path if any
if (2 <= len(sys.argv)):
    print "user specified a different output path, re-directing all outputs to ", str(sys.argv[1])
    if (os.path.isdir(str(sys.argv[1]))):
        output_path = str(sys.argv[1]) + '/'
 
        # Keep intermediate data files only when the user explicitly specifies an output location
        keepIntermediate = True
    else:
        # I choose to error out instead of creating new folder
        print str(sys.argv[1]), ' does not exist. Please correct and re-run.'
        sys.exit(-1)

# turn it into abs path for further scanning
output_path = os.path.abspath(output_path)

# I might need a lot space for intermediate/final data, so try to void working in Dropbox
if re.match(r'.*/dropbox.*', output_path, re.IGNORECASE):
    print 'WARNING: it seems that you are to output to a Dropbox folder (' + output_path + \
          '). This test might consume lots of space. Make sure you are aware of the consequence.\n'

    newOutputPath = raw_input('Press Enter to continue with current output path, otherwise provide a new output path: ')

    # handle possible ~
    newOutputPath = os.path.expanduser(newOutputPath)

    if newOutputPath:
        if (os.path.isdir(newOutputPath)):
            output_path = newOutputPath + '/'
        else:
            # I choose to error out instead of creating new folder
            print newOutputPath, ' does not exist. Please correct and re-run.'
            sys.exit(-1)

# write all data out of this execution into a timestamped new folder
output_path = os.path.join(output_path, os.path.basename(__file__)+'_'+datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
try:
    os.makedirs(output_path)
except OSError as e:
    if e.errno != errno.EEXIST:
        raise  # silent when existed, otherwise raise

execute_test(keepIntermediate)
