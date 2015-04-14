/* Test program.
 *
 * Not used.
 */
#include "cryptlib.h"
#include <stdio.h>

#define PASSWORD "S3cR3tP@ssw0Rd!"
#define BUFSIZE 1024

int main(int argc, char **argv) {
  int status;
  int bytesCopied;
  int encryptedBytes;
  CRYPT_ENVELOPE cryptEnvelope;
  char buf[BUFSIZE];
  char encbuf[BUFSIZE];

  printf("Initializing cryptlib\n");
  status = cryptInit();
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error initializing cryptlib\n");
    return 1;
  }

  status = cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED, CRYPT_FORMAT_CRYPTLIB);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error creating envelope\n");
    return 1;
  }

  status = cryptSetAttribute(cryptEnvelope, CRYPT_OPTION_ENCR_ALGO, CRYPT_ALGO_3DES);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting encr. algo\n");
    return 1;
  }

  status = cryptSetAttributeString(cryptEnvelope, CRYPT_ENVINFO_PASSWORD, PASSWORD, sizeof(PASSWORD));
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting password\n");
    return 1;
  }

  status = cryptPushData(cryptEnvelope, "Hello world", 12, &bytesCopied);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error pushing data\n");
    return 1;
  }
  if (bytesCopied != 12) {
    fprintf(stderr, "Error pushing data\n");
    return 1;
  }

  status = cryptFlushData(cryptEnvelope);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error flushing data\n");
    return 1;
  }


  status = cryptPopData(cryptEnvelope, encbuf, BUFSIZE, &encryptedBytes);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error popping data\n");
    return 1;
  }
  fprintf(stderr, "encryption enveloping returned %d bytes of data\n", encryptedBytes);
/*  if (bytesCopied != 12) {*/
/*    printf("bytesCopied: %d\n", bytesCopied);*/
/*    fprintf(stderr, "Error popping data\n");*/
/*    return 1;*/
/*  }*/


  status = cryptDestroyEnvelope(cryptEnvelope);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error destroying envelope\n");
    return 1;
  }

  /* OK, try decrypting it */

  status = cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error creating envelope\n");
    return 1;
  }

  status = cryptPushData(cryptEnvelope, encbuf, encryptedBytes, &bytesCopied);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error pushing data (decrypt/status): %d\n", status);
    /* return 1; */
  }
  if (bytesCopied != encryptedBytes) {
    fprintf(stderr, "Error pushing data(decrypt/size)\n");
    return 1;
  }

  status = cryptSetAttributeString(cryptEnvelope, CRYPT_ENVINFO_PASSWORD, PASSWORD, sizeof(PASSWORD));
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting password (2): %d\n", status);
    return 1;
  }


  status = cryptFlushData(cryptEnvelope);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error flushing data\n");
    return 1;
  }

  status = cryptPopData(cryptEnvelope, buf, BUFSIZE, &bytesCopied);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error popping data\n");
    return 1;
  }

  printf("popped: %s", buf);
/*  if (bytesCopied != 12) {*/
/*    printf("bytesCopied: %d\n", bytesCopied);*/
/*    fprintf(stderr, "Error popping data\n");*/
/*    return 1;*/
/*  }*/


  status = cryptDestroyEnvelope(cryptEnvelope);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error destroying envelope\n");
    return 1;
  }

  printf("Deinitializing cryptlib\n");
  status = cryptEnd();
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error deinitializing cryptlib\n");
    return 1;
  }
  return 0;
}
