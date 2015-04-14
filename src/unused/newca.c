/* This was used for command line testing of some routines.
 *
 * There's a dumb default password used, so it's probably best
 * that you don't use this.
 */
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "cryptlib.h"
#include <sqlite3.h>
#include "cadb.h"
#include "certinfo.h"


#define WARN(x) do { fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); } while(0)
#define WARN_IF(x) do { if(!cryptStatusOK(x)) fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); fflush(stderr); } while(0)
#define WARN_AND_RETURN_IF(x) do { if(!cryptStatusOK(x)) { fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); fflush(stderr); return x; }  } while(0)

#define DEFAULT_PASSWORD "asdf"

typedef int (*cmd_exec_func_t)(int,char **);

static int exec_create(int argc, char **argv);
static int exec_request(int argc, char **argv);
static int exec_sign(int argc, char **argv);
static int exec_revoke(int argc, char **argv);
static int exec_gencrl(int argc, char **argv);
static int exec_cdsc(int argc, char **argv);
static int exec_lsc(int argc, char **argv);
static int exec_lsr(int argc, char **argv);
static int exec_showc(int argc, char **argv);
static int exec_showr(int argc, char **argv);
static int exec_renew(int argc, char **argv);
static void process_opt(const char *opt);

int main(int argc, char **argv) {
  const char *cmd;
  struct cmd_func_pair {
    const char *cmd;
    cmd_exec_func_t func;
  } *pair_ptr, exec_funcs[] =
  {
    { "create", exec_create },
    { "request", exec_request },
    { "sign", exec_sign },
    { "revoke", exec_revoke },
    { "gencrl", exec_gencrl },
    { "cdsc", exec_cdsc },
    { "lsc", exec_lsc },
    { "lsr", exec_lsr },
    { "showc", exec_showc },
    { "showr", exec_showr },
    { "renew", exec_renew },
    { NULL, NULL }
  };
  int retval, status;
  int argv_cmd_index;


  /* set umask 077 so that our files are private */
  umask(S_IRWXG | S_IRWXO);

  if (argc < 2) {
    fprintf(stderr, "usage: %s [opts] command [params]\n", argv[0]);
    fprintf(stderr, "%s help gives more help\n", argv[0]);
    exit(1);
  }
  status = cryptInit();
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while initializing cryptlib\n", status);
  }
  argv_cmd_index = 1;
  while (argv[argv_cmd_index][0] == '-') {
    process_opt(argv[argv_cmd_index]); argv_cmd_index++;
  }
  cmd = argv[argv_cmd_index];
  for (pair_ptr = exec_funcs; pair_ptr->cmd; pair_ptr++) {
    if (strcmp(cmd, pair_ptr->cmd) == 0) {
      retval = pair_ptr->func(argc - argv_cmd_index - 1, argv + argv_cmd_index + 1);
      break;
    }
  }
  if (pair_ptr->cmd == 0) {
    fprintf(stderr, "unknown command %s\n", cmd);
    fprintf(stderr, "%s help gives more help\n", argv[0]);
    retval = 1;
  }
  status = cryptEnd();
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while deinitializing cryptlib\n", status);
  }
  return retval;
}


static int create_selfsigned_cert(CRYPT_CONTEXT ca_key_pair, const char *dn_c, const char *dn_sp, const char *dn_l, const char *dn_o, const char *dn_ou, const char *dn_cn, /* out */ CRYPT_CERTIFICATE *pCert);
static int create_keypair(CRYPT_CONTEXT *pCtx, const char *label);
static int export_cert(CRYPT_CERTIFICATE cert, int format, const char *filename);

/* usage: create dbname caname dn_c dn_sp dn_l dn_o dn_ou dn_cn cacertfilename */

static int exec_create(int argc, char **argv) {
  const char *dbname = argv[0];
  const char *caname = argv[1];
  const char *dn_c = argv[2];
  const char *dn_sp = argv[3];
  const char *dn_l = argv[4];
  const char *dn_o = argv[5];
  const char *dn_ou = argv[6];
  const char *dn_cn = argv[7];
  const char *cacrtfilename = argv[8];
  int status, retval;
  PLMZ_CA_DB pDB;
  CRYPT_CONTEXT keypair; CRYPT_CERTIFICATE cert;

  retval = 0;
  if ((argc != 9)) {
    fprintf(stderr, "usage: create db ca certid dn_c dn_sp dn_l dn_o dn_ou dn_cn cacertfilename\n"
    "dn_c and dn_cn must not be empty\n");
    return 1;
  }

  status = create_keypair(&keypair, caname);
  WARN_AND_RETURN_IF(status);
  status = create_selfsigned_cert(keypair, dn_c, dn_sp, dn_l, dn_o, dn_ou, dn_cn, &cert);
  WARN_AND_RETURN_IF(status);

  pDB = NULL;
  status = lmz_ca_create(&pDB, dbname, keypair, cert, DEFAULT_PASSWORD);
  if (status == CRYPT_ERROR_DUPLICATE) {
    fprintf(stderr, "Duplicate CA name in database\n");
    retval = 1; goto cleanup;
  }
  else WARN_AND_RETURN_IF(status);
  status = export_cert(cert, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cacrtfilename);
  WARN_AND_RETURN_IF(status);
cleanup:
  if (pDB != NULL) {
    status = lmz_ca_close(pDB);
    WARN_AND_RETURN_IF(status);
  }
  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyContext(keypair);
  WARN_AND_RETURN_IF(status);
  return retval;
}

static int create_selfsigned_cert(CRYPT_CONTEXT ca_key_pair, const char *dn_c, const char *dn_sp, const char *dn_l, const char *dn_o, const char *dn_ou, const char *dn_cn, /* out */ CRYPT_CERTIFICATE *pCert) {
  CRYPT_CERTIFICATE result_certificate;
  int status;
  time_t valid_from, valid_to;

  /* create the certificate and associate it with the CA's pubkey */
  status = cryptCreateCert(&result_certificate, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while creating CA selfsigned cert\n", status);
    return status;
  }

  status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, ca_key_pair);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while associating CA cert with key\n", status);
    goto err_cert_exit;
  }

  /* set the DN components */
  /* cryptlib USE_CERT_DNSTRING no longer on by default so can't set in one call */
#define setdncmp(attr,var) \
  if (var != NULL && *var) { \
    status = cryptSetAttributeString(result_certificate, attr, var, strlen(var)); \
    if (!cryptStatusOK(status)) { \
      fprintf(stderr, "cryptlib error %d while setting %s\n", status, #attr); \
      goto err_cert_exit; \
    } \
  }

  setdncmp(CRYPT_CERTINFO_COUNTRYNAME, dn_c);
  setdncmp(CRYPT_CERTINFO_STATEORPROVINCENAME, dn_sp);
  setdncmp(CRYPT_CERTINFO_LOCALITYNAME, dn_l);
  setdncmp(CRYPT_CERTINFO_ORGANIZATIONNAME, dn_o);
  setdncmp(CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, dn_ou);
  setdncmp(CRYPT_CERTINFO_COMMONNAME, dn_cn);
#undef setdncmp

  /* set validity */
  valid_from = time(NULL);
  valid_to = valid_from + (365 * 86400);
  status = cryptSetAttributeString(result_certificate, CRYPT_CERTINFO_VALIDFROM, &valid_from, sizeof(time_t));
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CRYPT_CERTINFO_VALIDFROM\n", status);
    goto err_cert_exit;
  }
  status = cryptSetAttributeString(result_certificate, CRYPT_CERTINFO_VALIDTO, &valid_to, sizeof(time_t));
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CRYPT_CERTINFO_VALIDTO\n", status);
    goto err_cert_exit;
  }

  /* set self-signed and CA bits */
  status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_SELFSIGNED, 1);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CA cert selfsigned bit\n", status);
    goto err_cert_exit;
  }

  status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_CA, 1);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CA cert CA bit\n", status);
    goto err_cert_exit;
  }

  /* set implicit trust bit
  status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_TRUSTED_USAGE, CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CA cert implicit trust bit\n", status);
    goto err_cert_exit;
  }
  */

  /* sign it */
  status = cryptSignCert(result_certificate, ca_key_pair);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while self-signing CA cert\n", status);
    goto err_cert_exit;
  }

  *pCert = result_certificate; return CRYPT_OK;
err_cert_exit:
  cryptDestroyCert(result_certificate); return status;
}
static int create_keypair(CRYPT_CONTEXT *pCtx, const char *label) {
  int status;
  CRYPT_CONTEXT local_context;

  /* create the RSA context */
  status = cryptCreateContext( &local_context, CRYPT_UNUSED, CRYPT_ALGO_RSA );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while creating keypair context\n", status);
    return status;
  }

  /* set key label */
  status = cryptSetAttributeString( local_context, CRYPT_CTXINFO_LABEL, label, strlen(label));
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting privkey label\n", status);
    goto err_ctx_exit;
  }

  /* generate key */
  status = cryptGenerateKey( local_context );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while generating CA keypair\n", status);
    goto err_ctx_exit;
  }

  /* normal (OK) exit */
  *pCtx = local_context; return CRYPT_OK;
err_ctx_exit:
  cryptDestroyContext(local_context); return status;
}
static void process_opt(const char *opt) {return;}

static int export_cert(CRYPT_CERTIFICATE cert, int format, const char *filename) {
  int status;
  void *certData;
  int maxLength, actualLength;
  FILE *f;

  status = cryptExportCert( NULL, 0, &maxLength, format, cert);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while getting max exported CA cert length\n", status);
    return status;
  }
  certData = malloc( maxLength );
  if (certData == NULL) {
    /* not sure we can recover from this */
    fprintf(stderr, "error allocating memory\n");
    return CRYPT_ERROR_MEMORY;
  }
  actualLength = maxLength;
  status = cryptExportCert( certData, maxLength, &actualLength, format, cert);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while getting max exported CA cert length\n", status);
    return status;
  }

  f = fopen(filename, "w");
  if (f == NULL) {
    status = CRYPT_ERROR_PARAM2;
    goto err_certdata_exit;
  }
  fwrite(certData, actualLength, 1, f);
  fclose(f);

  return CRYPT_OK;
err_certdata_exit:
  free(certData); return status;
}

/* usage: request dbfilename caname csrfilename */
/* prints request id number on stdout */
static int exec_request(int argc, char **argv) {
  const char *dbfilename = argv[0], *ca_name = argv[1], *csrfilename = argv[2];
  PLMZ_CA_DB pDB;
  CRYPT_CERTIFICATE csr;
  int status;
  void *csr_data; int csr_data_len;
  int id;

  /* open CA */
  status = lmz_ca_open(&pDB, dbfilename, ca_name);
  WARN_AND_RETURN_IF(status);
  /* import cert request */
  csr_data = lmz_file_read_full(csrfilename, &csr_data_len);
  status = cryptImportCert(csr_data, csr_data_len, CRYPT_UNUSED, &csr);
  WARN_AND_RETURN_IF(status);
  free(csr_data);
  /* insert request into CA, get resulting ID number */
  status = lmz_ca_add_request(pDB, csr, &id);
  /* XXX check autocommit is on */
  if (!sqlite3_get_autocommit(pDB->db)) { fprintf(stderr, "(%s:%d) autocommit not restored!\n", __FILE__, __LINE__); exit(1); }
  if (status == CRYPT_ERROR_DUPLICATE) {
    fprintf(stderr, "duplicate request\n");
    status = cryptDestroyCert(csr);
    WARN_AND_RETURN_IF(status);
    /* close CA */
    status = lmz_ca_close(pDB);
    WARN_AND_RETURN_IF(status);
    return 1;
  }
  else WARN_AND_RETURN_IF(status);
  printf("%d\n", id);
  /* destroy cert request */
  status = cryptDestroyCert(csr);
  WARN_AND_RETURN_IF(status);
  /* close CA */
  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);
  return 0;
}

/* usage: sign dbfilename caname req_id crtfilename */
/* outputs certificate in crtfilename */
static int exec_sign(int argc, char **argv) {
  const char *dbfilename = argv[0], *ca_name = argv[1], *req_id_s = argv[2], *crtfilename = argv[3];
  PLMZ_CA_DB pDB;
  CRYPT_CERTIFICATE signed_cert, csr;
  CRYPT_CONTEXT key;
  int handled;
  int status;
  int id;
  int retval;

  /* open CA */
  status = lmz_ca_open(&pDB, dbfilename, ca_name);
  WARN_AND_RETURN_IF(status);

  id = atoi(req_id_s);
  status = lmz_ca_get_request(pDB, id, &csr, &handled, NULL);
  WARN_AND_RETURN_IF(status);

  if (handled) {
    cryptDestroyCert(csr);
    fprintf(stderr, "Request %d already handled\n", id);
    lmz_ca_close(pDB);
    return 1;
  }
  else {
    retval = 0;
    status = lmz_ca_get_signing_key(pDB, DEFAULT_PASSWORD, &key);
    WARN_AND_RETURN_IF(status);
    status = cryptCreateCert(&signed_cert, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE);
    WARN_AND_RETURN_IF(status);
    status = cryptSetAttribute(signed_cert, CRYPT_CERTINFO_CERTREQUEST, csr);
    WARN_AND_RETURN_IF(status);
    status = cryptSignCert(signed_cert, key);
    WARN_AND_RETURN_IF(status);
    status = lmz_ca_save_cert(pDB, id, signed_cert);
    assert(sqlite3_get_autocommit(pDB->db) != 0);
    if (status == CRYPT_ERROR_DUPLICATE) {
      fprintf(stderr, "duplicate signing / request\n");
      retval = 1;
      goto cleanup;
    }
    else WARN_AND_RETURN_IF(status);
    status = export_cert(signed_cert, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, crtfilename);
    WARN_AND_RETURN_IF(status);
  cleanup:
    status = cryptDestroyCert(csr);
    WARN_AND_RETURN_IF(status);
    status = cryptDestroyCert(signed_cert);
    WARN_AND_RETURN_IF(status);
    status = cryptDestroyContext(key);
    WARN_AND_RETURN_IF(status);
    status = lmz_ca_close(pDB);
    WARN_AND_RETURN_IF(status);
    return retval;
  }
}

/* usage: revoke dbfilename caname certid [ac|cac|coo|kc|sup] */
static int exec_revoke(int argc, char **argv) {
  const char *dbfilename = argv[0], *ca_name = argv[1], *crt_id_s = argv[2], *reason = argv[3];
  PLMZ_CA_DB pDB;
  int status;
  int id;
  CRYPT_CONTEXT key;

  if ((argc != 3) && (argc != 4)) {
    fprintf(stderr, "usage: revoke db ca certid [ac|cac|coo|kc|sup]\n"
    "ac: aff. changed, cac: CA compromise, coo: cessation of ops.\n"
    "kc: key compromise, sup: superseded\n");
    return 1;
  }
  if (argc == 3) { reason = NULL; }

  /* open CA */
  status = lmz_ca_open(&pDB, dbfilename, ca_name);
  WARN_AND_RETURN_IF(status);

  id = atoi(crt_id_s);
  status = lmz_ca_get_signing_key(pDB, DEFAULT_PASSWORD, &key);
  WARN_AND_RETURN_IF(status);
  if (reason == NULL) {
     status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_UNSPECIFIED, key);
  }
  else {
    if (strcmp(reason, "ac") == 0) {
      status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_AFFILIATIONCHANGED, key);
    }
    else if (strcmp(reason, "cac") == 0) {
      status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_CACOMPROMISE, key);
    }
    else if (strcmp(reason, "coo") == 0) {
      status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_CESSATIONOFOPERATION, key);
    }
    else if (strcmp(reason, "kc") == 0) {
      status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_KEYCOMPROMISE, key);
    }
    else if (strcmp(reason, "sup") == 0) {
      status = lmz_ca_revoke_cert(pDB, id, CRYPT_CRLREASON_SUPERSEDED, key);
    }
    else {
      fprintf(stderr, "bad reason \"%s\"\n", reason);
      cryptDestroyContext(key);
      status = lmz_ca_close(pDB);
      WARN_AND_RETURN_IF(status);
      return 1;
    }
  }
  cryptDestroyContext(key);
  if (status == CRYPT_ERROR_NOTFOUND) {
    fprintf(stderr, "id %d not found\n", id);
  }
  else if (status == CRYPT_ERROR_WRITE) {
    fprintf(stderr, "generic write error\n");
  }
  else WARN_AND_RETURN_IF(status);
  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);
  return 0;
}

/* usage: gencrl dbname caname crlfilename */
static int exec_gencrl(int argc, char **argv) {
  const char *dbfilename = argv[0], *ca_name = argv[1], *crlfilename = argv[2];
  PLMZ_CA_DB pDB;
  CRYPT_CERTIFICATE crl_tbs;
  CRYPT_CONTEXT key;
  int status;

  /* open CA */
  status = lmz_ca_open(&pDB, dbfilename, ca_name);
  WARN_AND_RETURN_IF(status);

  status = lmz_ca_gen_crl(pDB, &crl_tbs);
  WARN_AND_RETURN_IF(status);

  status = lmz_ca_get_signing_key(pDB, DEFAULT_PASSWORD, &key);
  WARN_AND_RETURN_IF(status);
  status = cryptSignCert(crl_tbs, key);
  WARN_AND_RETURN_IF(status);
  status = export_cert(crl_tbs, CRYPT_CERTFORMAT_CERTIFICATE, crlfilename);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyContext(key);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(crl_tbs);
  WARN_AND_RETURN_IF(status);

  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);


  return 0;
}

/* usage: cdsc certfilename */
static int exec_cdsc(int argc, char **argv) {
  const char *certfilename = argv[0];
  void *crt_data; int crt_data_len;
  CRYPT_CERTIFICATE cert;
  int status;


  crt_data = lmz_file_read_full(certfilename, &crt_data_len);
  status = cryptImportCert(crt_data, crt_data_len, CRYPT_UNUSED, &cert);
  free(crt_data);
  if( status == CRYPT_ERROR_NOSECURE ) {
    fprintf(stderr, "Certificate import failed with CRYPT_ERROR_NOSECURE -- probably the key is too short\n");
    return 1;
  }
  WARN_AND_RETURN_IF(status);

  lmz_certinfo_print_cert(cert);

  cryptDestroyCert(cert);
  return 0;

}

/* lsc db ca */
static int exec_lsc_callback(void*,int,char**, char**);

static int exec_lsc(int argc, char **argv) {
  PLMZ_CA_DB pDB;
  const char *dbfilename = argv[0], *caname = argv[1];
  int status, err;
  char *errmsg;
  char *query;


  status = lmz_ca_open(&pDB, dbfilename, caname);
  WARN_AND_RETURN_IF(status);
  query = sqlite3_mprintf("SELECT id, C, SP, L, O, OU, CN, validTo, revoked, skid FROM certificates WHERE issuer = '%q' ORDER BY id ASC", caname);
  errmsg = NULL;
  err = sqlite3_exec(pDB->db,
  query, exec_lsc_callback, NULL, &errmsg);
  if (errmsg) { fprintf(stderr, "%s\n", errmsg); sqlite3_free(errmsg); errmsg = NULL; }
  sqlite3_free(query);
  status = lmz_ca_close(pDB);
  return 0;
}

static int exec_lsc_callback(void* userdata, int argc, char **argv, char **azColName) {
  time_t dt;
  struct tm gmt_time;
  int revoked;
  unsigned char *pc;

  fprintf(stdout, "Certificate id: %s\n", argv[0]);
  if (argv[1]) { fprintf(stdout, "C: %s\n", argv[1]); }
  if (argv[2]) { fprintf(stdout, "SP: %s\n", argv[2]); }
  if (argv[3]) { fprintf(stdout, "L: %s\n", argv[3]); }
  if (argv[4]) { fprintf(stdout, "O: %s\n", argv[4]); }
  if (argv[5]) { fprintf(stdout, "OU: %s\n", argv[5]); }
  if (argv[6]) { fprintf(stdout, "CN: %s\n", argv[6]); }
  dt = atoi(argv[7]);
  gmtime_r(&dt, &gmt_time);
  fprintf(stdout, "Not After: %.2d-%.2d-%d %.2d:%.2d:%.2d UTC\n", gmt_time.tm_mday, gmt_time.tm_mon + 1, gmt_time.tm_year + 1900, gmt_time.tm_hour, gmt_time.tm_min, gmt_time.tm_sec);
  revoked = atoi(argv[8]);
  if (revoked) {
    fprintf(stdout, "***REVOKED***\n");
  }
  fprintf(stdout, "SubjectKeyIdentifier: ");
  pc = (unsigned char *)argv[9];
  while (*pc) {
    fprintf(stdout, "%.2X ", *pc);
    pc++;
  }
  fprintf(stdout, "\n\n");
  return 0;
}

/* lsr db ca [all] */
static int exec_lsr(int argc, char **argv) {
  PLMZ_CA_DB pDB;
  const char *dbfilename = argv[0], *caname = argv[1];
  int status, err;
  int all;
  sqlite3_stmt *stmt;
  const char *tail;
  time_t receive_time; struct tm gmt_time;
  CRYPT_CERTIFICATE csr;
  char *dn; int dn_len;

  all = (argc > 2);

  status = lmz_ca_open(&pDB, dbfilename, caname);
  WARN_AND_RETURN_IF(status);
  stmt = NULL;
  if (all) {
    err = sqlite3_prepare(pDB->db, "SELECT id, received_on, request_type, request_data, handled FROM requests WHERE recipient = ?  ORDER BY id ASC", -1, &stmt, &tail);
  }
  else {
    err = sqlite3_prepare(pDB->db, "SELECT id, received_on, request_type, request_data, handled FROM requests WHERE (recipient = ?) AND (handled = 0) ORDER BY id ASC", -1, &stmt, &tail);
  }
  if (err != SQLITE_OK) { goto cleanup; }
  err = sqlite3_bind_text(stmt, 1, caname, -1, SQLITE_TRANSIENT);
  if (err != SQLITE_OK) { goto cleanup; }
  while ((err = sqlite3_step(stmt)) == SQLITE_ROW) {
    fprintf(stdout, "Certificate request id: %d\n", sqlite3_column_int(stmt, 0));
    receive_time = sqlite3_column_int(stmt, 1);
    gmtime_r(&receive_time, &gmt_time);
    fprintf(stdout, "Request Received: %.2d-%.2d-%d %.2d:%.2d:%.2d UTC\n", gmt_time.tm_mday, gmt_time.tm_mon + 1, gmt_time.tm_year + 1900, gmt_time.tm_hour, gmt_time.tm_min, gmt_time.tm_sec);
    fprintf(stdout, "Request Type: %d\n", sqlite3_column_int(stmt, 2));
    if (all) {
      if (sqlite3_column_int(stmt, 4)) { /* handled */
        fprintf(stdout, "Request handled: TRUE\n");
      }
      else {
        fprintf(stdout, "Request handled: FALSE\n");
      }
    }
    /* extract the DN from the CSR */
    status = cryptImportCert(sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3), CRYPT_UNUSED, &csr);
    if (!cryptStatusOK(status)) {
      fprintf(stderr, "Failed to read csr data: cl error %d\n", status);
    }
    else {
      dn = lmz_cl_get_attribute_string(csr, CRYPT_CERTINFO_DN, &dn_len);
      fprintf(stdout, "DN: %s\n", dn);
      free(dn);
      cryptDestroyCert(csr);
    }
    fprintf(stdout, "\n");
  }
  if (err == SQLITE_DONE) {
  }
  else { fprintf(stderr, "sqlite error %d\n", err); }
cleanup:
  if (stmt) sqlite3_finalize(stmt);
  status = lmz_ca_close(pDB);
  return 0;
}

/* showc db ca cid */
static int exec_showc(int argc, char **argv) {
  PLMZ_CA_DB pDB;
  const char *dbfilename = argv[0], *caname = argv[1], *id_s = argv[2];
  int cid;
  int status;
  CRYPT_CERTIFICATE cert;
  cid = atoi(id_s);
  status = lmz_ca_open(&pDB, dbfilename, caname);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_get_cert(pDB, cid, &cert);
  WARN_AND_RETURN_IF(status);
  lmz_certinfo_print_cert(cert);
  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);
  return 0;
}

/* showr db ca rid */
static int exec_showr(int argc, char **argv) {
  PLMZ_CA_DB pDB;
  const char *dbfilename = argv[0], *caname = argv[1], *id_s = argv[2];
  int rid;
  int handled;
  int status;
  CRYPT_CERTIFICATE csr;
  rid = atoi(id_s);
  status = lmz_ca_open(&pDB, dbfilename, caname);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_get_request(pDB, rid, &csr, &handled, NULL);
  WARN_AND_RETURN_IF(status);
  lmz_certinfo_print_req(csr);
  status = cryptDestroyCert(csr);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);
  return 0;
}

/* renew db ca certid days */
static int exec_renew(int argc, char **argv) {
  PLMZ_CA_DB pDB;
  const char *dbfilename = argv[0], *caname = argv[1], *id_s = argv[2], *days_s = argv[3];
  int certid;
  int days;
  int status;
  CRYPT_CONTEXT key;
  certid = atoi(id_s);
  days = atoi(days_s);
  status = lmz_ca_open(&pDB, dbfilename, caname);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_get_signing_key(pDB, DEFAULT_PASSWORD, &key);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_renew_cert(pDB, certid, days, key);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyContext(key);
  WARN_AND_RETURN_IF(status);
  status = lmz_ca_close(pDB);
  WARN_AND_RETURN_IF(status);
  return 0;
}
