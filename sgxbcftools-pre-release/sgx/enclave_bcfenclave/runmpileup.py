import os
import sys

input_file = {
        "mpileup":["mpileup.ref.fa", "mpileup1.sam", "mpileup1.vcf"], 
        "HG01537.chrom11.ILLUMINA.bwa.IBS.low_coverage.20130415": ["Homo_sapiens.GRCh38.dna.chromosome.11.fa", "HG01537.chrom11.ILLUMINA.bwa.IBS.low_coverage.20130415.sam"],
        "NA12234.chrom20.ILLUMINA.bwa.CEU.low_coverage.20130415": ["chr20.fa", "NA12234.chrom20.ILLUMINA.bwa.CEU.low_coverage.20130415.sam"],
        "HG00096.wgs.ILLUMINA.bwa.GBR.high_cov_pcr_free.20140203": ["chr20.fa","HG00096.wgs.ILLUMINA.bwa.GBR.high_cov_pcr_free.20140203.sam"]
        }

#--------------< this function is used for generate the testing command >-----
def execute_mpileuptest(testFile):
    input_file_list = input_file[testFile]
    ref_file = input_file_list[0]
    sam_file = input_file_list[1]
    out_file = sam_file + ".tmp.mlp"
    str_command = "./sample" + " " + ref_file + " " + sam_file + " " + out_file

    return str_command, out_file

def generate_difftest(test_file, out_file):
    input_file_list = input_file[test_file]
    ground_truth = input_file_list[2]
    command  = "diff " + ground_truth + " " + out_file

    return command
    


if __name__ == '__main__':
    command, out_file = execute_mpileuptest(sys.argv[1])
    print "\n=======================<< Start Running Test >>========================\n"
    print_str = "[+] Executing Test Command " + command
    print print_str
    print '\n'

    #print "Generating Output File As: " out_file
    os.system(command)
    diff_command = generate_difftest(sys.argv[1], out_file)
    #print diff_command
    print '\n'
    print "[*] Printing Difference Test Result..."
    os.system(diff_command)
