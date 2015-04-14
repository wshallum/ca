/* Code to convert between OpenSSL PEM RSA private key and cryptlib
 * keyset.
 *
 * NOTE: uses dumb default password. You should probably use pemtrans
 * instead.
 *
 * adapted from pemtrans.c 
 * here is pemtrans.c copyright notice
 *
 * Copyright 2004 Abhijit Menon-Set <ams@oryx.com>
 * Use, modification, and distribution of pemtrans is allowed without
 * any limitations. There is no warranty, express or implied.
 */

#include "cryptlib.h"
#include <openssl/pem.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DIE do { fprintf(stderr, "(%s:%d) -- fatal error\n", __FILE__, __LINE__); } while (0)

int main(int argc, char **argv) {
  const char *keysetFilename;

  CRYPT_KEYSET keyset;
  CRYPT_CONTEXT keys;
  CRYPT_PKCINFO_RSA rsa;

  RSA *openssl_key;
  EVP_PKEY *evp;
  void *buf[8];
  FILE *f;
  int status;

  f = fopen(argv[1], "r");
  if (!f) { exit(1); }
  evp = PEM_read_PrivateKey( f, NULL, NULL, NULL );
  if (!evp) DIE;
  openssl_key = EVP_PKEY_get1_RSA(evp);
  if (!openssl_key) DIE;
  fclose(f);

  keysetFilename = argv[2];
  status = cryptInit();
  if (!cryptStatusOK(status)) DIE;
  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keysetFilename, CRYPT_KEYOPT_CREATE);
  if (!cryptStatusOK(status)) DIE;

  /* transfer */

    if ( ( buf[0] = malloc( BN_num_bytes( openssl_key->n ) ) ) != NULL &&
         ( buf[1] = malloc( BN_num_bytes( openssl_key->e ) ) ) != NULL &&
         ( buf[2] = malloc( BN_num_bytes( openssl_key->d ) ) ) != NULL &&
         ( buf[3] = malloc( BN_num_bytes( openssl_key->p ) ) ) != NULL &&
         ( buf[4] = malloc( BN_num_bytes( openssl_key->q ) ) ) != NULL &&
         ( buf[5] = malloc( BN_num_bytes( openssl_key->iqmp ) ) ) != NULL &&
         ( buf[6] = malloc( BN_num_bytes( openssl_key->dmp1 ) ) ) != NULL &&
         ( buf[7] = malloc( BN_num_bytes( openssl_key->dmq1 ) ) ) != NULL )
    {
        int i;

        BN_bn2bin( openssl_key->n, buf[0] );
        BN_bn2bin( openssl_key->e, buf[1] );
        BN_bn2bin( openssl_key->d, buf[2] );
        BN_bn2bin( openssl_key->p, buf[3] );
        BN_bn2bin( openssl_key->q, buf[4] );
        BN_bn2bin( openssl_key->iqmp, buf[5] );
        BN_bn2bin( openssl_key->dmp1, buf[6] );
        BN_bn2bin( openssl_key->dmq1, buf[7] );

        cryptSetComponent( (&rsa)->n, buf[0], BN_num_bits( openssl_key->n ) );
        cryptSetComponent( (&rsa)->e, buf[1], BN_num_bits( openssl_key->e ) );
        cryptSetComponent( (&rsa)->d, buf[2], BN_num_bits( openssl_key->d ) );
        cryptSetComponent( (&rsa)->p, buf[3], BN_num_bits( openssl_key->p ) );
        cryptSetComponent( (&rsa)->q, buf[4], BN_num_bits( openssl_key->q ) );
        cryptSetComponent( (&rsa)->u, buf[5], BN_num_bits( openssl_key->iqmp ) );
        cryptSetComponent( (&rsa)->e1, buf[6], BN_num_bits( openssl_key->dmp1 ) );
        cryptSetComponent( (&rsa)->e2, buf[7], BN_num_bits( openssl_key->dmq1 ) );

        i = 0;
        while ( i < 8 )
            free( buf[i++] );
    }
    else {
        fprintf( stderr, "Couldn't initialise PKCINFO_RSA data.\n" );
        exit( -1 );
    }

  status = cryptCreateContext(&keys, CRYPT_UNUSED, CRYPT_ALGO_RSA);
  if (!cryptStatusOK(status)) DIE;
  status = cryptSetAttributeString(keys, CRYPT_CTXINFO_LABEL, "Keys", 4);
  if (!cryptStatusOK(status)) DIE;
  status = cryptSetAttributeString(keys, CRYPT_CTXINFO_KEY_COMPONENTS, &rsa, sizeof( CRYPT_PKCINFO_RSA ));
  if (!cryptStatusOK(status)) DIE;

  status = cryptAddPrivateKey(keyset, keys, "asdf");
  if (!cryptStatusOK(status)) DIE;
  status = cryptKeysetClose(keyset);
  if (!cryptStatusOK(status)) DIE;

  status = cryptEnd();
  if (!cryptStatusOK(status)) DIE;
  
  return 0;
}
