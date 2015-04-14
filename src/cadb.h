#ifndef LMZ_CADB_H_DEFINED
#define LMZ_CADB_H_DEFINED
#include "cryptlib.h"
#include <sqlite3.h>

/* just to keep things straightened out */
typedef int LMZ_CL_ERROR;
typedef int LMZ_SQLITE_ERROR;

#ifndef BOOL
#define BOOL int
#ifndef FALSE
#define FALSE 0
#define TRUE (!FALSE)
#endif
#endif


typedef struct TAG_LMZ_CA_DB {
  sqlite3 *db;
  char *db_filename;
  char *ca_name;
  CRYPT_CERTIFICATE ca_cert;
} LMZ_CA_DB, *PLMZ_CA_DB;

typedef struct TAG_LMZ_SIGN_OPT {
  int ku_bits;
  int valid_days;
  int eku_num;
  int eku_flags[10];
} LMZ_SIGN_OPT, *PLMZ_SIGN_OPT;

/* the request types */
#define LMZ_CA_REQUEST_CSR 1
#define LMZ_CA_REQUEST_RENEW 2


int lmz_export_cert(CRYPT_CERTIFICATE cert, CRYPT_CERTFORMAT_TYPE format, void **pCert, int *pLen);

void *lmz_file_read_full(const char *filename, int *pLen);
void *lmz_cl_get_attribute_string(CRYPT_HANDLE h, CRYPT_ATTRIBUTE_TYPE attr, int *pLen);

LMZ_CL_ERROR lmz_ca_create(/* OUT */PLMZ_CA_DB *ppDB, const char *db_filename, CRYPT_CONTEXT privkey, CRYPT_CERTIFICATE cert, const char *password);
LMZ_CL_ERROR lmz_ca_open(/* OUT */ PLMZ_CA_DB *ppDB, const char *db_filename, const char *ca_name);
LMZ_SQLITE_ERROR lmz_ca_get_existing_names(const char *db_filename, char ***pNames);
void lmz_ca_free_names(char **names);
LMZ_CL_ERROR lmz_ca_close(PLMZ_CA_DB pDB);
LMZ_CL_ERROR lmz_ca_add_request(PLMZ_CA_DB pDB, CRYPT_CERTIFICATE request, /* OUT */int *pID);
/* sign request by id, no questions asked, automatically stores signed cert */
LMZ_CL_ERROR lmz_ca_sign_request(PLMZ_CA_DB pDB, int id, const char *signing_password);
/* manual signing steps */
/* get request by id */
LMZ_CL_ERROR lmz_ca_get_request(PLMZ_CA_DB pDB, int id, /* OUT */CRYPT_CERTIFICATE *pRequest, /* OUT */int *pHandled, /* OUT */char **pNotes);
/* get the signing key */
LMZ_CL_ERROR lmz_ca_get_signing_key(PLMZ_CA_DB pDB, const char *signing_password, /* OUT */CRYPT_CONTEXT *pSigningKey);
/* save signed cert */
LMZ_CL_ERROR lmz_ca_save_cert(PLMZ_CA_DB pDB, int request_id, CRYPT_CERTIFICATE signed_cert);
/* revoke a certificate for a certain reason */
LMZ_CL_ERROR lmz_ca_revoke_cert(PLMZ_CA_DB pDB, int cert_id, int revoke_reason, CRYPT_CONTEXT signing_key);
/* renew a certificate -- revoke the previous one w/ reason superseded
and publish a new one based on the given cert_id as template for DN comps, KU, and EKU */
LMZ_CL_ERROR lmz_ca_renew_cert(PLMZ_CA_DB pDB, int cert_id, int valid_days, CRYPT_CONTEXT signing_key);
/* generate a CRL (not signed) for a certain CA */
LMZ_CL_ERROR lmz_ca_gen_crl(PLMZ_CA_DB pDB, /* OUT */CRYPT_CERTIFICATE *pCRL);
/* return cert */
LMZ_CL_ERROR lmz_ca_get_cert(PLMZ_CA_DB pDB, int id, /* OUT */CRYPT_CERTIFICATE *pRequest);
/*

*/
LMZ_CL_ERROR lmz_ca_get_ca_cert(PLMZ_CA_DB pDB, /* OUT */CRYPT_CERTIFICATE *pCert);
/*
TODO test

*/
LMZ_CL_ERROR lmz_ca_enum_signopts(PLMZ_CA_DB pDB, char ***pNames);
/*
TODO test

*/
void lmz_ca_free_enum_signopts(char **names);
/*
TODO test
return CRYPT_OK, CRYPT_ERROR_READ, or CRYPT_ERROR_NOTFOUND
*/
LMZ_CL_ERROR lmz_ca_get_signopt(PLMZ_CA_DB pDB, const char *name, /* OUT */PLMZ_SIGN_OPT opt);
/*
TODO test
return CRYPT_OK or CRYPT_ERROR_WRITE
*/
LMZ_CL_ERROR lmz_ca_save_signopt(PLMZ_CA_DB pDB, const char *name, PLMZ_SIGN_OPT opt);
/*
TODO
return CRYPT_OK, CRYPT_ERROR_WRITE or CRYPT_ERROR_NOTFOUND
*/
LMZ_CL_ERROR lmz_ca_delete_signopt(PLMZ_CA_DB pDB, const char *name);
/*
  apply a signing option to a certificate (still to-be-signed),
  clears all KU and EKU not in sign opt,
  changes VALIDFROM to current time, VALIDTO to current time + valid_days
 */
LMZ_CL_ERROR lmz_ca_apply_sign_opt(PLMZ_SIGN_OPT pOpt, CRYPT_CERTIFICATE tbsCert);
LMZ_CL_ERROR lmz_ca_renew_cert(PLMZ_CA_DB pDB, int cert_id, int valid_days, CRYPT_CONTEXT signing_key);

LMZ_SQLITE_ERROR lmz_ca_create_web_db(PLMZ_CA_DB pDB, const char *webdb_filename);
LMZ_CL_ERROR lmz_ca_sync_web_db(PLMZ_CA_DB pDB, const char *webdb_filename);
#endif
