#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>
#include "sample.h"

#include "bcfenclave_u.h"



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid Intel(R) SGX device.",
        "Please make sure Intel(R) SGX module is enabled in the BIOS, and install Intel(R) SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "Intel(R) SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(BCFENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

/* OCall functions */
void ocall_bcfenclave_sample(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

int ocall_hfile_oflags(const char* mode)
{
	int rdwr = 0, flags = 0;
	    const char *s;
	    for (s = mode; *s; s++)
	        switch (*s) {
	        case 'r': rdwr = O_RDONLY;  break;
	        case 'w': rdwr = O_WRONLY; flags |= O_CREAT | O_TRUNC;  break;
	        case 'a': rdwr = O_WRONLY; flags |= O_CREAT | O_APPEND;  break;
	        case '+': rdwr = O_RDWR;  break;
	#ifdef O_CLOEXEC
	        case 'e': flags |= O_CLOEXEC;  break;
	#endif
	#ifdef O_EXCL
	        case 'x': flags |= O_EXCL;  break;
	#endif
	        default:  break;
	        }

	#ifdef O_BINARY
	    flags |= O_BINARY;
	#endif

	    return rdwr | flags;
}


int ocall_open(const char* filename, int mode) {
    return open(filename, mode, 0666);
}

int ocall_read(int file, void *buf, unsigned int size) {
    return read(file, buf, size);
}

int ocall_write(int file, void *buf, unsigned int size) {
    return write(file, buf, size);
}

int ocall_close(int file) {
    return close(file);
}

int ocall_fsync(int file){
	return fsync(file);
}

void print_ocall(char* message) {
  printf(message);
}

int ocall_readmem(void *file, void *buf, unsigned int size){
    return 1;
}

double ocall_drand48()
{
    //printf("Here we hit Drand48().\n");
    return drand48();
}
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Changing dir to where the executable is.*/
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]),absolutePath);
    printf("The working path is %s ", ptr);

    if( chdir(absolutePath) != 0)
    		abort();
            
    clock_t begin = clock();
    /* Initialize the enclave */
    if(initialize_enclave() < 0){

        return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int ecall_return = 0;

    clock_t end_enclave = clock();
    double time_spentin = (double)(end_enclave - begin) / CLOCKS_PER_SEC;
    printf("The Total Initialization Time is: %lf\n", time_spentin);

    ret = ecall_bcfenclave_sample(global_eid, &ecall_return, argv[1], argv[1], argv[2], argv[3]);

    if (ret != SGX_SUCCESS)
        abort();

    if (ecall_return == 0) {
        printf("[+] Application Mpileup ran with success\n");
    }
    else
    {
        printf("[+] Application Mpileup failed %d \n", ecall_return);
    }

    clock_t end_mp = clock();
    double time_spentmp = (double)(end_mp - end_enclave) / CLOCKS_PER_SEC;
    printf("The Total Initialization Time is: %lf\n", time_spentmp);

    ret = ecall_bcfenclave_ccall(global_eid, &ecall_return, argv[3], argv[4]);

    if (ret != SGX_SUCCESS)
        abort();

    if (ecall_return == 0) {
        printf("[+] Application VCFCALL ran with success\n");
    }
    else
    {
        printf("[+] Application VCFCALL failed %d \n", ecall_return);
    }

    clock_t end_call = clock();
    double time_spentcall = (double)(end_call - end_mp) / CLOCKS_PER_SEC;
    printf("The Total Initialization Time is: %lf\n", time_spentmp);

    sgx_destroy_enclave(global_eid);
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

    printf("The Total Running Time for the program is: %lf\n", time_spent);



    return ecall_return;
}

