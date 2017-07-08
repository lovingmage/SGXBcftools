#include <stdio.h>
#include <tchar.h>

#include "sgx_urts.h"
#include "sgx_lib.h"
#include "enclave_u.h"
#include "sgx_lib_u_util.h"

#define ENCLAVE_FILE _T("enclave.signed.dll")

#define TEST_APPLICATION
#ifdef TEST_APPLICATION
//--------------< Test Stub for Testing Secure I/O>-----------------
int main(int argc, char* argv[])
{
  sgx_enclave_id_t eid;
  int secret;
  uint8_t key[128] = {0};
  int sec[4096];

  // Launch the enclave
  if (launch_enclave(ENCLAVE_FILE, &eid) != SGX_SUCCESS) return -1;

  // Interact with the enclave
  set_key(eid, key);
  printf("Secret to seal by the enclave (-1 to reuse old secret): ");
  scanf("%d%*c", &secret);
  if (secret != -1) {
    add_secret(eid, secret);
  }
  print_secrets(eid);

  test_encryption(eid);


  dump_out(eid,sec);
  print_buffer(eid, sec);

  // Destroy the enclave
  if(destroy_enclave(eid) != SGX_SUCCESS) return -1;

  printf("Press any key to exit...");
  getchar();
  return 0;
}

#endif