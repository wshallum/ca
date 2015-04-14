/* Test code to create CSR and self signed CA cert.
 * Not used.
 */
#include <stdio.h>
#include <stdlib.h>
#include "cryptlib.h"

#define KEY_FILENAME "private.key"
#define CSR_FILE "csr.req"
#define CACERT_FILE "ca.crt"
#define PASSWORD "S3cR3tP@ssw0Rd!"

void createCSR(CRYPT_CONTEXT);
void createCACert(CRYPT_CONTEXT);

int main(int argc, char **argv) {
  int status;
  CRYPT_CONTEXT cryptContext;
  CRYPT_KEYSET cryptKeyset;

  printf("Initializing cryptlib\n");
  status = cryptInit();
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error initializing cryptlib\n");
    return 1;
  }
  
  /* Create an RSA public/private key context, set a label for it, and
     generate a key into it */
  status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error creating crypt_context\n");
    return 1;
  }
  status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, "Private key", 11 );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting key label\n");
    return 1;
  }
  fprintf(stderr, "Generating RSA key\n");
  status = cryptGenerateKey( cryptContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error generating key\n");
    return 1;
  }
  fprintf(stderr, "done!\n");
  /* Save the generated public/private key pair to a keyset */
  status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, KEY_FILENAME, CRYPT_KEYOPT_CREATE );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error opening keyset\n");
    return 1;
  }
  status = cryptAddPrivateKey( cryptKeyset, cryptContext, PASSWORD );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error adding key to keyset\n");
    return 1;
  }
  status = cryptKeysetClose( cryptKeyset );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error closing keyset\n");
    return 1;
  }
  
  /* Create CSR */
  createCSR(cryptContext);
  
  /* Create CA cert */
  createCACert(cryptContext);
  
  
  /* Clean up */
  status = cryptDestroyContext( cryptContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error destroying context\n");
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

void createCSR(CRYPT_CONTEXT keyContext) {
  CRYPT_CERTIFICATE cryptCertRequest;
  void *certRequest;
  int certRequestMaxLength, certRequestLength;
  FILE *f = NULL;
  int status;
  
  /* Create a certification request and add the public key to it */
  status = cryptCreateCert( &cryptCertRequest, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTREQUEST );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error creating certRequest\n");
    exit(1);
  }
  status = cryptSetAttribute( cryptCertRequest, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, keyContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting pubkey: %d\n", status);
    exit(1);
  }
  /* Add identification information */
  
  status = cryptSetAttributeString(cryptCertRequest, CRYPT_CERTINFO_COUNTRYNAME, "US", 2);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting C\n");
    exit(1);
  }
  status = cryptSetAttributeString(cryptCertRequest, CRYPT_CERTINFO_ORGANIZATIONNAME, "example", 7);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting O\n");
    exit(1);
  }
  status = cryptSetAttributeString(cryptCertRequest, CRYPT_CERTINFO_COMMONNAME, "example", 7);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting CN\n");
    exit(1);
  }
  /* Sign the certification request with the private key and export it
  */
  status = cryptSignCert( cryptCertRequest, keyContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error signing CSR\n");
    exit(1);
  }
  status = cryptExportCert( NULL, 0, &certRequestMaxLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCertRequest );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error getting max cert length\n");
    exit(1);
  }
  certRequest = malloc( certRequestMaxLength );
  status = cryptExportCert( certRequest, certRequestMaxLength, &certRequestLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCertRequest);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error exporting cert\n");
    exit(1);
  }
  /* Destroy the certification request */
  status = cryptDestroyCert( cryptCertRequest );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error destroying cert request\n");
    exit(1);
  }
  
  f = fopen(CSR_FILE, "w");
  if (!f) { perror("fopen CSR_FILE"); exit(1); }
  fwrite(certRequest, certRequestLength, 1, f);
  fclose(f);
  free(certRequest);
}

void createCACert(CRYPT_CONTEXT keyContext) {
  CRYPT_CERTIFICATE cryptCertificate;
  void *cert;
  int certMaxLength, certLength;
  FILE *f = NULL;
  int status;
  
  /* Create a certification request and add the public key to it */
  status = cryptCreateCert( &cryptCertificate, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error creating certificate\n");
    exit(1);
  }
  status = cryptSetAttribute( cryptCertificate, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, keyContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting pubkey: %d\n", status);
    exit(1);
  }
  /* Add identification information */
  
  status = cryptSetAttributeString(cryptCertificate, CRYPT_CERTINFO_COUNTRYNAME, "US", 2);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting C\n");
    exit(1);
  }
  status = cryptSetAttributeString(cryptCertificate, CRYPT_CERTINFO_ORGANIZATIONNAME, "example", 7);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting O\n");
    exit(1);
  }
  status = cryptSetAttributeString(cryptCertificate, CRYPT_CERTINFO_COMMONNAME, "example", 7);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting CN\n");
    exit(1);
  }
  status = cryptSetAttribute(cryptCertificate, CRYPT_CERTINFO_SELFSIGNED, 1);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting SELFSIGNED\n");
    exit(1);
  }
  status = cryptSetAttribute(cryptCertificate, CRYPT_CERTINFO_CA, 1);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error setting CA bit\n");
    exit(1);
  }
  /* Sign the certificate with the private key and export it
  */
  status = cryptSignCert( cryptCertificate, keyContext );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error signing CA cert\n");
    exit(1);
  }
  status = cryptExportCert( NULL, 0, &certMaxLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCertificate );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error getting max cert length\n");
    exit(1);
  }
  cert = malloc( certMaxLength );
  status = cryptExportCert( cert, certMaxLength, &certLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCertificate);
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error exporting cert\n");
    exit(1);
  }
  /* Destroy the certification request */
  status = cryptDestroyCert( cryptCertificate );
  if (status != CRYPT_OK) {
    fprintf(stderr, "Error destroying cert request\n");
    exit(1);
  }
  
  f = fopen(CACERT_FILE, "w");
  if (!f) { perror("fopen CACERT_FILE"); exit(1); }
  fwrite(cert, certLength, 1, f);
  fclose(f);
  free(cert);
}
