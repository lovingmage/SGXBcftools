#!/bin/bash
START= $(date+%s)
./bcftools mpileup -f mpileup.ref.fa mpileup.1.bam >> mpileup.1.vcf
END= $(date +%s)
DIFF= $(( $END - $START ))
echo "It took $DIFF seconds for BAM Files"


SAMSTART=$(date+%s)
./bcftools mpileup -f mpileup.ref.fa mpileup.1.sam >> mpileup.1.vcf
SAMEND=$(date +%s)
DIFF=$(( $SAMEND - $SAMSTART ))
echo "It took $DIFF seconds"
