import os

def execute_test():
    test_file_path = "/home/cwang/Desktop/dataset/"
    test_diff_result_path = "/home/cwang/Desktop/dataset/diff/"
    test_time_result_path = "/home/cwang/Desktop/dataset/time/"
    
    test_files = {"HG00096.chrom11.ILLUMINA.bwa.GBR.low_coverage.20120522" : "Homo_sapiens.GRCh38.dna.chromosome.11.fa",
                  "HG00096.chrom20.ILLUMINA.bwa.GBR.low_coverage.20120522" : "chr20.fa",
                  "HG01537.chrom11.ILLUMINA.bwa.IBS.low_coverage.20130415" : "Homo_sapiens.GRCh38.dna.chromosome.11.fa",
                  "HG02600.chrom20.ILLUMINA.bwa.PJL.low_coverage.20121211" : "chr20.fa",
                  "mpileup1" : "mpileup.ref.fa"}
    
    for i in test_files.keys():
        curr_sam = test_file_path + test_files[i] + ".sam"
        curr_ref = test_file_path + test_files[i]
        curr_mlp = test_file_path + i + ".sgx.mlp"
        curr_vcf = test_file_path + i + ".sgx.call.vcf"
        curr_diff = test_diff_result_path + i + ".diff"
        curr_time = test_time_result_path + i + ".time"
        
        str_command_sgx = "./sample" + " " + curr_ref + " " + curr_sam + " " + curr_mlp + " " + curr_vcf
        
execute_test()