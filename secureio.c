#include <stdio.h>
#include "bcfenclave/trusted/bcfenclave.h"
#include "bcfenclave/trusted/bcfenclave_t.h"
#include "sgx_tprotected_fs.h"

void simSecureIO()
{
    SGX_FILE *fp;
    char c[] = "this is tutorialspoint";
    char buffer[100];
 
    /* Open file for both reading and writing */
    fp = sgx_fopen_auto_key("file.txt", "w+");
 
    /* Write data to the file */
    sgx_fwrite(c, strlen(c) + 1, 1, fp);
 
    /* Seek to the beginning of the file */
    sgx_fseek(fp, 0, SEEK_SET);
 
    /* Read and display data */
    sgx_fread(buffer, strlen(c)+1, 1, fp);
    printf("%s\n", buffer);
    sgx_fclose(fp);
    
    return;
}
