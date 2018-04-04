

#cd Desktop/sgxbcftools-complete/

./configure 
make
cd bcfenclave/
source /opt/intel/sgxsdk/environment
./sample ~/Desktop/1KGenome/reference/11.fa ~/Desktop/1KGenome/data/HG00096.chrom11.ILLUMINA.bwa.GBR.low_coverage.20120522.sam ~/Desktop/1KGenome/tmp.mlp ~/Desktop/1KGenome/vcf/HG00096.chrom11.ILLUMINA.bwa.GBR.low_coverage.20120522.sgx.vcf

cd ..
