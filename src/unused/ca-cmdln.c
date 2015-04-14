/* This was used for testing of the sqlite3 keyset adapter.
 * It is not used since we did not use the cryptlib keyset stuff in the end.
 *
 * The actual sqlite3 keyset adapter itself is not included.
 */
#include "cryptlib.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define WARN(x) do { fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); } while(0)
#define WARN_IF(x) do { if(!cryptStatusOK(x)) fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); fflush(stderr); } while(0)
#define WARN_AND_RETURN_IF(x) do { if(!cryptStatusOK(x)) { fprintf(stderr, "(%s:%d) cryptlib error %d\n", __FILE__, __LINE__, x); fflush(stderr); return x; }  } while(0)
typedef int (*cmd_exec_func_t)(int,char **);

static int exec_help(int argc, char **argv);
static int exec_create(int argc, char **argv);
static int exec_enroll(int argc, char **argv);
static int exec_request(int argc, char **argv);
static int exec_sign(int argc, char **argv);
static int exec_revoke(int argc, char **argv);
static int exec_gencrl(int argc, char **argv);
static int exec_cmpsvr(int argc, char **argv);
static int exec_cmpcli(int argc, char **argv);
static int exec_info(int argc, char **argv);
static int exec_addpubkey(int argc, char **argv);
static void process_opt(const char *opt);

int opt_verbose = 0, opt_predef = 0;

int main(int argc, char **argv) {
  const char *cmd;
  struct cmd_func_pair {
    const char *cmd;
    cmd_exec_func_t func;
  } *pair_ptr, exec_funcs[] =
  {
    { "help", exec_help },
    { "create", exec_create },
    { "enroll", exec_enroll },
    { "request", exec_request },
    { "sign", exec_sign },
    { "revoke", exec_revoke },
    { "gencrl", exec_gencrl },
    { "cmpsvr", exec_cmpsvr },
    { "cmpcli", exec_cmpcli },
    { "info", exec_info },
    { "addpubkey", exec_addpubkey },
    { NULL, NULL }
  };
  int retval, status;
  int argv_cmd_index;
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

/********************************************************************************
Utility Functions
********************************************************************************/
static int create_keypair(/* out */ CRYPT_CONTEXT *ctx, const char *label);
static int save_ca_keypair_and_cert_to_file(CRYPT_CONTEXT ctx, CRYPT_CERTIFICATE cert, const char *filename, const char *password);
static int create_selfsigned_cert(CRYPT_CONTEXT ca_key_pair, const char *dn, /* out */ CRYPT_CERTIFICATE *pCert);
static int export_cert(CRYPT_CERTIFICATE cert, const char *filename);
static int add_ca_cert_to_store(CRYPT_KEYSET store, const char *dn, CRYPT_CERTIFICATE cert);
static void *read_full_file(const char *filename, int *pLen);
/********************************************************************************
Execute Functions
********************************************************************************/

static int exec_addpubkey(int argc, char **argv) {
  CRYPT_KEYSET keyset;
  CRYPT_CERTIFICATE cert;
  const char *certfilename, *keysetfilename;
  void *data;
  int data_len;
  int status;

  if (argc != 2) {
    fprintf(stderr, "usage: addpubkey keyset cert\n");
    return 1;
  }
  keysetfilename = argv[0]; certfilename = argv[1];
  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keysetfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);
  data = read_full_file(certfilename, &data_len);
  status = cryptImportCert(data, data_len, CRYPT_UNUSED, &cert);
  WARN_AND_RETURN_IF(status);
  status = cryptAddPublicKey(keyset, cert);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(keyset);
  WARN_AND_RETURN_IF(status);
  free(data);
  return 0;

}

static int exec_help(int argc, char **argv) {
  static const char *names[] = { "help", "create", "enroll", "request", "sign", "revoke", "gencrl", NULL };
  static const char *helps[] = {
    "help [command]                           -- print help on [command] or all commands",
    "create dbfile                            -- create new CA database in dbfile",
    "enroll dbfile dn                         -- enroll new PKI user in dbfile",
    "request dbfile csrfilename               -- enter CSR into CA database",
    "sign dbfile (-e email|-n name) certfile  -- sign received CSR",
    "revoke dbfile (-e email|-n name)         -- revoke a certificate",
    "gencrl dbfile crlfile                    -- generate CRL into file",
    NULL
  };
  const char **p;

  if (argc > 0) {
    const char *helpcmd = argv[0];
    for (p = names; *p; p++) {
      if (strcmp(*p, helpcmd) == 0) {
        fprintf(stderr, "%s\n", helps[p-names]);
        return 0;
      }
    }
    fprintf(stderr, "unknown command %s -- printing complete help:\n", helpcmd);
  }
  for (p = helps; *p; p++) {
    fprintf(stderr, "%s\n", *p);
  }

  return 0;
}

/* TODO pass from cmdline */
#define DEFAULT_DN "cn=Example CA, o=Example, c=ID"
#define DEFAULT_PASSWORD "asdf"
#define DEFAULT_CA_PRIVKEY_LABEL "CA Private Key"
#define DEFAULT_PRIVKEY_LABEL "Keys"
static int exec_create(int argc, char **argv) {
  CRYPT_KEYSET keyset;
  CRYPT_CERTIFICATE cert;
  CRYPT_CONTEXT context;
  int status;
  const char *filename = argv[0];
  char keyfilename[4096]; /* PATH_MAX */
  char certfilename[4096]; /* PATH_MAX */

  /* create the tables using cryptlib */
  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, filename, CRYPT_KEYOPT_CREATE);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while opening keyset\n", status);
    return 1;
  }
  status = cryptKeysetClose(keyset);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while closing keyset\n", status);
    return 1;
  }
  if (opt_verbose) fprintf(stdout, "file %s created OK as cert keyset store\n", filename);

  /* the database has been created, but there is still no CA key
   * and CA cert -- now we generate it and put the CA key in a file
   * and import the public key & cert into the db.
   */
  status = create_keypair(&context, DEFAULT_CA_PRIVKEY_LABEL);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while generating CA keypair\n", status);
    return 1;
  }
  /* generate cert */
  status = create_selfsigned_cert(context, DEFAULT_DN, &cert);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while generating CA cert\n", status);
    goto err_ctx_exit;
  }
  snprintf(keyfilename, 4095, "%s.keys", filename);
  status = save_ca_keypair_and_cert_to_file(context, cert, keyfilename, DEFAULT_PASSWORD); /* TODO password */
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while saving CA keypair to %s\n", status, keyfilename);
    goto err_ctx_exit;
  }
  if (opt_verbose) fprintf(stdout, "CA keys saved to file keyset %s\n", filename);


  /* save it */
  snprintf(certfilename, 4095, "%s.ca.crt", filename);
  status = export_cert(cert, certfilename);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while saving CA cert\n", status);
    goto err_cert_exit;
  }

#if 0
  /* add to store */
  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, filename, CRYPT_KEYOPT_NONE);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while opening CA cert store to save CA cert\n", status);
    goto err_cert_exit;
  }


  status = add_ca_cert_to_store(keyset, DEFAULT_DN, cert);
  /* status = cryptCAAddItem(keyset, cert); */
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while saving CA cert to CA cert store\n", status);
    cryptKeysetClose(keyset);
    goto err_cert_exit;
  }
  status = cryptKeysetClose(keyset);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while closing CA cert store\n", status);
    goto err_cert_exit;
  }
  if (opt_verbose) fprintf(stdout, "CA certs for %s saved to %s\n", DEFAULT_DN, filename);
#endif

  /* cleanup */
  status = cryptDestroyCert(cert);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while destroying CA cert\n", status);
    goto err_ctx_exit;
  }
  status = cryptDestroyContext(context);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while destroying CA keypair context\n", status);
    /* NO ERROR CASE */
    return 1;
  }

  return 0;

err_cert_exit:
  cryptDestroyCert(cert);
err_ctx_exit:
  cryptDestroyContext(context);
  return 1;
}

static int add_ca_cert_to_store(CRYPT_KEYSET store, const char *dn, CRYPT_CERTIFICATE cert) {
  int status;
  CRYPT_CERTIFICATE pki_user;

  status = cryptCreateCert(&pki_user, CRYPT_UNUSED, CRYPT_CERTTYPE_PKIUSER);
  WARN_AND_RETURN_IF(status);

  status = cryptSetAttributeString(pki_user, CRYPT_CERTINFO_DN, dn, strlen(dn));
  WARN_AND_RETURN_IF(status);

  status = cryptSetAttribute(pki_user, CRYPT_CERTINFO_CA, 1);
  WARN_AND_RETURN_IF(status);

  status = cryptCAAddItem(store, pki_user);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyCert(pki_user);
  WARN_AND_RETURN_IF(status);

  status = cryptCAAddItem(store, cert);
  if (!cryptStatusOK(status)) {
    int errorLocus;
    int errorType;

    cryptGetAttribute(store, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus);
    cryptGetAttribute(store, CRYPT_ATTRIBUTE_ERRORTYPE, &errorType);
    fprintf(stderr, "locus %d type %d\n", errorLocus, errorType);
    cryptGetAttribute(cert, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus);
    cryptGetAttribute(cert, CRYPT_ATTRIBUTE_ERRORTYPE, &errorType);
    fprintf(stderr, "locus %d type %d\n", errorLocus, errorType);
  }
  WARN_AND_RETURN_IF(status);

  return CRYPT_OK;
}
static int export_cert(CRYPT_CERTIFICATE cert, const char *filename) {
  int status;
  void *certData;
  int maxLength, actualLength;
  FILE *f;

  status = cryptExportCert( NULL, 0, &maxLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cert);
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
  status = cryptExportCert( certData, maxLength, &actualLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cert);
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
static int create_selfsigned_cert(CRYPT_CONTEXT ca_key_pair, const char *dn, /* out */ CRYPT_CERTIFICATE *pCert) {
  CRYPT_CERTIFICATE result_certificate;
  int status;

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

  /* set the DN */
  cryptSetAttributeString(result_certificate, CRYPT_CERTINFO_DN, dn, strlen(dn));
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CA cert DN\n", status);
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

  /* set implicit trust bit */
  status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_TRUSTED_USAGE, CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while setting CA cert implicit trust bit\n", status);
    goto err_cert_exit;
  }

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

  /* set key label -- TODO make label parameter */
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

static int save_ca_keypair_and_cert_to_file(CRYPT_CONTEXT ctx, CRYPT_CERTIFICATE cert, const char *filename, const char *password) {
  int status;
  CRYPT_KEYSET keyset;

  status = cryptKeysetOpen( &keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, filename, CRYPT_KEYOPT_CREATE );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while creating ca privkey keyset file %s\n", status, filename);
    return status;
  }

  status = cryptAddPrivateKey( keyset, ctx, password );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while adding CA privkey to keyset\n", status);
    goto err_keyset_exit;
  }

  status = cryptAddPublicKey( keyset, cert );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while adding CA cert to keyset\n", status);
    goto err_keyset_exit;
  }

#if 0
  status = cryptAddPublicKey( keyset, ctx );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while adding CA pubkey to keyset\n", status);
    goto err_keyset_exit;
  }
#endif

  status = cryptKeysetClose( keyset );
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "cryptlib error %d while closing CA privkey keyset\n", status);
    return status; /* what do we do now, close it again? */
  }

  return CRYPT_OK;

err_keyset_exit:
  cryptKeysetClose( keyset ); return status;
}

static int exec_info(int argc, char **argv) {
  const char *dbfilename;
  CRYPT_KEYSET keyset;
  CRYPT_CERTIFICATE pki_user;
  char userID[CRYPT_MAX_TEXTSIZE + 1], issuePW[CRYPT_MAX_TEXTSIZE + 1], revPW[CRYPT_MAX_TEXTSIZE + 1];
  int userIDlen, issuePWlen, revPWlen;
  int status;
  CRYPT_KEYID_TYPE id_type;
  const char *id;
  if (argc < 3) return 1;
  dbfilename = argv[0];
  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "(%s:%d) cryptlib error %d while closing CA privkey keyset\n", __FILE__, __LINE__, status);
    return 1;
  }
  id = argv[2];
  if (strcmp(argv[1], "-e") == 0) {
    id_type = CRYPT_KEYID_EMAIL;
  }
  else if (strcmp(argv[1], "-n") == 0) {
    id_type = CRYPT_KEYID_NAME;
  }
  status = cryptCAGetItem(keyset, &pki_user, CRYPT_CERTTYPE_PKIUSER, id_type, id);
  WARN_IF(status);
  status = cryptKeysetClose(keyset);
  WARN_IF(status);
  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_ID, userID, &userIDlen);
  WARN_IF(status);
  userID[userIDlen] = '\0';
  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD, issuePW, &issuePWlen);
  WARN_IF(status);
  issuePW[issuePWlen] = '\0';
  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_REVPASSWORD, revPW, &revPWlen);
  WARN_IF(status);
  revPW[revPWlen] = '\0';

  fprintf(stdout, "%s\n", userID);
  fprintf(stdout, "%s\n", issuePW);
  fprintf(stdout, "%s\n", revPW);

  status = cryptDestroyCert(pki_user);
  WARN_IF(status);
  return 0;

}

static int exec_enroll(int argc, char **argv) {
  const char *dbfilename, *dn;
  CRYPT_KEYSET keyset;
  CRYPT_CERTIFICATE pki_user;
  char userID[CRYPT_MAX_TEXTSIZE + 1], issuePW[CRYPT_MAX_TEXTSIZE + 1], revPW[CRYPT_MAX_TEXTSIZE + 1];
  int userIDlen, issuePWlen, revPWlen;
  int status;

  /* get args */
  if (argc != 2) {
    fprintf(stderr, "usage: enroll dbfilename dn\n");
    return 1;
  }
  dbfilename = argv[0]; dn = argv[1];

  status = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "(%s:%d) cryptlib error %d while closing CA privkey keyset\n", __FILE__, __LINE__, status);
    return 1;
  }

  status = cryptCreateCert(&pki_user, CRYPT_UNUSED, CRYPT_CERTTYPE_PKIUSER);
  WARN_IF(status);

  status = cryptSetAttributeString(pki_user, CRYPT_CERTINFO_DN, dn, strlen(dn));
  WARN_IF(status);

  status = cryptCAAddItem(keyset, pki_user);
  WARN_IF(status);

  status = cryptKeysetClose(keyset);
  WARN_IF(status);

  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_ID, userID, &userIDlen);
  WARN_IF(status);
  userID[userIDlen] = '\0';
  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD, issuePW, &issuePWlen);
  WARN_IF(status);
  issuePW[issuePWlen] = '\0';
  status = cryptGetAttributeString(pki_user, CRYPT_CERTINFO_PKIUSER_REVPASSWORD, revPW, &revPWlen);
  WARN_IF(status);
  revPW[revPWlen] = '\0';

  fprintf(stdout, "%s\n", userID);
  fprintf(stdout, "%s\n", issuePW);
  fprintf(stdout, "%s\n", revPW);

  status = cryptDestroyCert(pki_user);
  WARN_IF(status);

  return 0;
}

static void *read_full_file(const char *filename, int *pLen) {
  FILE *f;
  int len;
  void *data;
  if (opt_verbose) fprintf(stderr, "opening \"%s\" for reading\n", filename);
  f = fopen(filename, "r");
  if (opt_verbose && !f) fprintf(stderr, "failed to open \"%s\" for reading\n", filename);
  if (f == NULL) return NULL;
  fseek(f, 0, SEEK_END);
  len = ftell(f);
  fseek(f, 0, SEEK_SET);
  data = malloc(len);
  if (data == NULL) { fclose(f); return NULL; }
  fread(data, len, 1, f);
  *pLen = len;
  fclose(f);
  if (opt_verbose) fprintf(stderr, "read %d bytes from \"%s\"\n", len, filename);
  return data;
}

static int exec_request(int argc, char **argv) {
  int status;
  const char *dbfilename, *csrfilename;
  void *csr_data;
  int csr_len;
  CRYPT_KEYSET store;
  CRYPT_CERTIFICATE request;

  if (argc != 2) {
    fprintf(stderr, "usage: request dbfilename csrfilename\n");
    return 1;
  };


  dbfilename = argv[0];
  csrfilename = argv[1];
  if (opt_verbose) fprintf(stderr, "exec request db \"%s\" csr \"%s\"\n", dbfilename, csrfilename);

  status = cryptKeysetOpen(&store, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  if (opt_verbose) fprintf(stderr, "finished opening ks\n");
  if (!cryptStatusOK(status)) {
    fprintf(stderr, "(%s:%d) -> %d\n", __FILE__, __LINE__, status);
    return status;
  }

  csr_data = read_full_file(csrfilename, &csr_len);
  if (opt_verbose) fprintf(stderr, "finished reading csr\n"); fflush(stderr);
  status = cryptImportCert(csr_data, csr_len, CRYPT_UNUSED, &request);
  free(csr_data);
  if (opt_verbose) fprintf(stderr, "finished importing csr\n");
  WARN_AND_RETURN_IF(status);
  status = cryptCAAddItem(store, request);
  WARN_AND_RETURN_IF(status);
  if (opt_verbose) fprintf(stderr, "finished adding csr to  store\n");
  status = cryptDestroyCert(request);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(store);
  WARN_AND_RETURN_IF(status);
  if (opt_verbose) fprintf(stderr, "finished closing store\n");

  return 0;
}

static int exec_sign(int argc, char **argv) {
  const char *id, *dbfilename, *certfilename;
  char cakeysfilename[4096];
  CRYPT_KEYID_TYPE id_type;
  CRYPT_KEYSET store, cakeys;
  CRYPT_CERTIFICATE cert, csr;
  CRYPT_CONTEXT ca_privkey;
  int status;

  if (argc != 4) {
    fprintf(stderr, "usage: sign dbfile (-e email | -n name) certfile\n");
    return 1;
  }

  dbfilename = argv[0];
  certfilename = argv[3];
  id = argv[2];
  if (strcmp(argv[1], "-e") == 0) {
    id_type = CRYPT_KEYID_EMAIL;
  }
  else if (strcmp(argv[1], "-n") == 0) {
    id_type = CRYPT_KEYID_NAME;
  }
  else {
    fprintf(stderr, "usage: sign dbfile (-e email | -n name) certfile\n");
    return 1;
  }

  status = cryptKeysetOpen(&store, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);

  status = cryptCAGetItem(store, &csr, CRYPT_CERTTYPE_CERTREQUEST, id_type, id);
  WARN_AND_RETURN_IF(status);

  snprintf(cakeysfilename, 4095, "%s.keys", dbfilename);
  status = cryptKeysetOpen(&cakeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, cakeysfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);

  status = cryptGetPrivateKey(cakeys, &ca_privkey, CRYPT_KEYID_NAME, DEFAULT_CA_PRIVKEY_LABEL, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(cakeys);
  WARN_AND_RETURN_IF(status);

  status = cryptCACertManagement(&cert, CRYPT_CERTACTION_ISSUE_CERT, store, ca_privkey, csr);
  if (!cryptStatusOK(status)) {
    int errorLocus;
    int errorType;

    cryptGetAttribute(store, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus);
    cryptGetAttribute(store, CRYPT_ATTRIBUTE_ERRORTYPE, &errorType);
    fprintf(stderr, "store: locus %d type %d\n", errorLocus, errorType);
    cryptGetAttribute(csr, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus);
    cryptGetAttribute(csr, CRYPT_ATTRIBUTE_ERRORTYPE, &errorType);
    fprintf(stderr, "csr: locus %d type %d\n", errorLocus, errorType);
    cryptGetAttribute(ca_privkey, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus);
    cryptGetAttribute(ca_privkey, CRYPT_ATTRIBUTE_ERRORTYPE, &errorType);
    fprintf(stderr, "ca_privkey: locus %d type %d\n", errorLocus, errorType);
  }
  WARN_AND_RETURN_IF(status);

  status = export_cert(cert, certfilename);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyCert(csr);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyContext(ca_privkey);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(store);
  WARN_AND_RETURN_IF(status);
  return 0;
}

static int exec_revoke(int argc, char **argv) {
  const char *id, *dbfilename, *pass;
  char cakeysfilename[4096];
  CRYPT_KEYID_TYPE id_type;
  CRYPT_KEYSET store, cakeys;
  CRYPT_CERTIFICATE cert, crl;
  CRYPT_CONTEXT ca_privkey;
  int status;

  if (argc != 4) {
    fprintf(stderr, "usage: revoke dbfile (-e email | -n name) pass\n");
    return 1;
  }

  dbfilename = argv[0];
  id = argv[2];
  pass = argv[3];
  if (strcmp(argv[1], "-e") == 0) {
    id_type = CRYPT_KEYID_EMAIL;
  }
  else if (strcmp(argv[1], "-n") == 0) {
    id_type = CRYPT_KEYID_NAME;
  }
  else {
    fprintf(stderr, "usage: revoke dbfile (-e email | -n name)\n");
    return 1;
  }

  /* open store */
  status = cryptKeysetOpen(&store, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);

  /* get ca privkey */
  snprintf(cakeysfilename, 4095, "%s.keys", dbfilename);
  status = cryptKeysetOpen(&cakeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, cakeysfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);
  status = cryptGetPrivateKey(cakeys, &ca_privkey, CRYPT_KEYID_NAME, DEFAULT_CA_PRIVKEY_LABEL, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(cakeys);
  WARN_AND_RETURN_IF(status);

  /* get cert to revoke */
  status = cryptCAGetItem(store, &cert, CRYPT_CERTTYPE_CERTIFICATE, id_type, id);
  WARN_AND_RETURN_IF(status);

  /* create CRL */
  status = cryptCreateCert(&crl, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(crl, CRYPT_CERTINFO_CERTIFICATE, cert);
  WARN_AND_RETURN_IF(status);
  status = cryptSignCert(crl, ca_privkey);
  WARN_AND_RETURN_IF(status);

  status = cryptAddPublicKey(store, crl);
  WARN_AND_RETURN_IF(status);


  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyCert(crl);
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyContext(ca_privkey);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(store);
  WARN_AND_RETURN_IF(status);
  return 0;
}

static int exec_gencrl(int argc, char **argv) {
  CRYPT_KEYSET cakeys, store;
  CRYPT_CERTIFICATE crl;
  CRYPT_CONTEXT ca_privkey;
  const char *dbfilename;
  char cakeysfilename[4096];
  int status;
  if (argc < 2) { fprintf(stderr, "missing dbfilename/outfilename\n"); return 1; }
  dbfilename = argv[0];

  /* open store */
  status = cryptKeysetOpen(&store, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);

  /* get ca privkey */
  snprintf(cakeysfilename, 4095, "%s.keys", dbfilename);
  cakeysfilename[4095] = '\0';
  status = cryptKeysetOpen(&cakeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, cakeysfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);
  status = cryptGetPrivateKey(cakeys, &ca_privkey, CRYPT_KEYID_NAME, DEFAULT_CA_PRIVKEY_LABEL, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(cakeys);
  WARN_AND_RETURN_IF(status);

  status = cryptCACertManagement(&crl, CRYPT_CERTACTION_ISSUE_CRL, store, ca_privkey, CRYPT_UNUSED);
  WARN_AND_RETURN_IF(status);

  status = export_cert(crl, argv[1]);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(crl);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(store);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyContext(ca_privkey);
  WARN_AND_RETURN_IF(status);
  return 0;
}

static int exec_cmpsvr(int argc, char **argv) {
  CRYPT_KEYSET cakeys, store;
  CRYPT_SESSION session;
  CRYPT_CONTEXT ca_privkey;
  int status;
  const char *dbfilename = argv[0];
  char cakeysfilename[4096]; /* PATH_MAX */

  if (argc < 1) { fprintf(stderr, "missing dbfilename\n"); return 1; }

  status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_CMP_SERVER);
  WARN_AND_RETURN_IF(status);

  /* open store */
  status = cryptKeysetOpen(&store, CRYPT_UNUSED, CRYPT_KEYSET_DATABASE_STORE, dbfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);

  /* get ca privkey */
  snprintf(cakeysfilename, 4095, "%s.keys", dbfilename);
  cakeysfilename[4095] = '\0';
  status = cryptKeysetOpen(&cakeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, cakeysfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);
  status = cryptGetPrivateKey(cakeys, &ca_privkey, CRYPT_KEYID_NAME, DEFAULT_CA_PRIVKEY_LABEL, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(cakeys);
  WARN_AND_RETURN_IF(status);

  status = cryptSetAttribute(session, CRYPT_SESSINFO_KEYSET, store);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_PRIVATEKEY, ca_privkey);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, "127.0.0.1", 9);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_SERVER_PORT, 65000);
  WARN_AND_RETURN_IF(status);
  fprintf(stderr, "before setting ACTIVE\n");
  status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, 1);
  if (!cryptStatusOK(status)) {
    CRYPT_ERRTYPE_TYPE errtype;
    CRYPT_ATTRIBUTE_TYPE locus;
    char *errstring;
    int errstringlen;
    cryptGetAttribute(session, CRYPT_ATTRIBUTE_ERRORTYPE, (int *)&errtype);
    cryptGetAttribute(session, CRYPT_ATTRIBUTE_ERRORLOCUS, (int *)&locus);
    fprintf(stderr, "session errtype %d locus %d\n", errtype, locus);
    cryptGetAttributeString(session, CRYPT_ATTRIBUTE_ERRORMESSAGE, NULL, &errstringlen);
    errstring = malloc(errstringlen + 10);
    cryptGetAttributeString(session, CRYPT_ATTRIBUTE_ERRORMESSAGE, errstring, &errstringlen);
    errstring[errstringlen] = 0;
    fprintf(stderr, "session errmsg: %s\n", errstring);
    free(errstring);
  }
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(store);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyContext(ca_privkey);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroySession(session);
  WARN_AND_RETURN_IF(status);
  return 0;
}

static int exec_cmpcli_revoke(int argc, char **argv);
static int exec_cmpcli_init(int argc, char **argv);
static int exec_cmpcli(int argc, char **argv) {
  const char *cmd;
  if (argc < 1) {
    fprintf(stderr, "cmpcli min 1 arg\n"); return 1;
  }
  cmd = argv[0];
  if (strcmp(cmd, "revoke") == 0) {
    return exec_cmpcli_revoke(argc, argv);
  }
  else if (strcmp(cmd, "init") == 0) {
    return exec_cmpcli_init(argc, argv);
  }
  else {
    fprintf(stderr, "cmpcli unknown command\n"); return 1;
  }
}

static int exec_cmpcli_init(int argc, char **argv) {
  CRYPT_SESSION session;
  CRYPT_CERTIFICATE cert, cacert, req;
  CRYPT_CONTEXT keypair;
  CRYPT_KEYSET privkeys;
  const char *cmd, *uid, *ipwd, *crtfilename, *cacrtfilename, *kpfilename;
  void *crtdata;
  int status, data_len;

  if (argc != 6) { fprintf(stderr, "cmpcli argv!=6\n"); return 1; }
  cmd = argv[0]; uid = argv[1]; ipwd = argv[2]; crtfilename=argv[3]; cacrtfilename=argv[4]; kpfilename = argv[5];
  fprintf(stderr, "uid=\"%s\" ipwd=\"%s\"\n", uid, ipwd);
#if 0
  crtdata = read_full_file(crtfilename, &data_len);
  if (!crtdata) return 1;
  status = cryptImportCert(crtdata, data_len, CRYPT_UNUSED, &cert);
  WARN_AND_RETURN_IF(status);
  free(crtdata);
#endif
  crtdata = read_full_file(cacrtfilename, &data_len);
  if (!crtdata) return 1;
  status = cryptImportCert(crtdata, data_len, CRYPT_UNUSED, &cacert);
  WARN_AND_RETURN_IF(status);
  free(crtdata);

  status = create_keypair(&keypair, DEFAULT_PRIVKEY_LABEL);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetOpen(&privkeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, kpfilename, CRYPT_KEYOPT_CREATE);
  WARN_AND_RETURN_IF(status);
  status = cryptAddPrivateKey(privkeys, keypair, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);


  status = cryptCreateCert(&req, CRYPT_UNUSED, CRYPT_CERTTYPE_REQUEST_CERT);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(req, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, keypair);
  WARN_AND_RETURN_IF(status);
  status = cryptSignCert(req, keypair);
  WARN_AND_RETURN_IF(status);

  status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_CMP);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_CMP_REQUESTTYPE, CRYPT_REQUESTTYPE_INITIALIZATION);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_CACERTIFICATE, cacert);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_REQUEST, req);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_USERNAME, uid, strlen(uid));
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_PASSWORD, ipwd, strlen(ipwd));
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, "127.0.0.1", 9);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_SERVER_PORT, 65000);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, 1);
  WARN_AND_RETURN_IF(status);
  status = cryptGetAttribute(session, CRYPT_SESSINFO_RESPONSE, &cert);
  WARN_AND_RETURN_IF(status);
  status = export_cert(cert, crtfilename);
  WARN_AND_RETURN_IF(status);
  status = cryptAddPublicKey(privkeys, cert);
  WARN_AND_RETURN_IF(status);

  status = cryptKeysetClose(privkeys);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroySession(session);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(cacert);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(req);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyContext(keypair);
  return 0;
}

static int exec_cmpcli_revoke(int argc, char **argv) {
  CRYPT_SESSION session;
  CRYPT_CONTEXT privkey;
  CRYPT_KEYSET privkeys;
  CRYPT_CERTIFICATE cert, cacert, revreq;
  const char *cmd, *crtfilename, *cacrtfilename, *kpfilename;
  void *crtdata;
  int status, data_len;

  if (argc != 4) { fprintf(stderr, "cmpcli revoke argv!=4\n"); return 1; }
  cmd = argv[0]; crtfilename=argv[1]; cacrtfilename=argv[2]; kpfilename = argv[3];
  if (strcmp(cmd, "revoke") != 0) { fprintf(stderr, "cmpcli knows revoke only\n"); return 1; }

  crtdata = read_full_file(crtfilename, &data_len);
  if (!crtdata) return 1;
  status = cryptImportCert(crtdata, data_len, CRYPT_UNUSED, &cert);
  WARN_AND_RETURN_IF(status);
  free(crtdata);

  crtdata = read_full_file(cacrtfilename, &data_len);
  if (!crtdata) return 1;
  status = cryptImportCert(crtdata, data_len, CRYPT_UNUSED, &cacert);
  WARN_AND_RETURN_IF(status);
  free(crtdata);

  status = cryptKeysetOpen(&privkeys, CRYPT_UNUSED, CRYPT_KEYSET_FILE, kpfilename, CRYPT_KEYOPT_NONE);
  WARN_AND_RETURN_IF(status);
  status = cryptGetPrivateKey(privkeys, &privkey, CRYPT_KEYID_NAME, DEFAULT_PRIVKEY_LABEL, DEFAULT_PASSWORD);
  WARN_AND_RETURN_IF(status);
  status = cryptKeysetClose(privkeys);
  WARN_AND_RETURN_IF(status);


  status = cryptCreateCert(&revreq, CRYPT_UNUSED, CRYPT_CERTTYPE_REQUEST_REVOCATION);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(revreq, CRYPT_CERTINFO_CERTIFICATE, cert);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(revreq, CRYPT_CERTINFO_CRLREASON, CRYPT_CRLREASON_AFFILIATIONCHANGED);
  WARN_AND_RETURN_IF(status);
  #if 0
  status = cryptSignCert(revreq, privkey);
  WARN_AND_RETURN_IF(status);
  #endif

  status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_CMP);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_CMP_REQUESTTYPE, CRYPT_REQUESTTYPE_REVOCATION);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_PRIVATEKEY, privkey);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_REQUEST, revreq);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_CACERTIFICATE, cacert);
  WARN_AND_RETURN_IF(status);

  #if 0
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_USERNAME, uid, strlen(uid));
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttributeString(session, CRYPT_SESSINFO_PASSWORD, rpwd, strlen(rpwd));
  WARN_AND_RETURN_IF(status);
  #endif

  status = cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, "127.0.0.1", 9);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_SERVER_PORT, 65000);
  WARN_AND_RETURN_IF(status);
  status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, 1);
  if (!cryptStatusOK(status)) {
    CRYPT_ERRTYPE_TYPE errtype;
    CRYPT_ATTRIBUTE_TYPE locus;
    char *errstring;
    int errstringlen;
    cryptGetAttribute(session, CRYPT_ATTRIBUTE_ERRORTYPE, (int *)&errtype);
    cryptGetAttribute(session, CRYPT_ATTRIBUTE_ERRORLOCUS, (int *)&locus);
    fprintf(stderr, "session errtype %d locus %d\n", errtype, locus);
    cryptGetAttribute(revreq, CRYPT_ATTRIBUTE_ERRORTYPE, (int *)&errtype);
    cryptGetAttribute(revreq, CRYPT_ATTRIBUTE_ERRORLOCUS, (int *)&locus);
    fprintf(stderr, "revreq errtype %d locus %d\n", errtype, locus);
    cryptGetAttribute(cert, CRYPT_ATTRIBUTE_ERRORTYPE, (int *)&errtype);
    cryptGetAttribute(cert, CRYPT_ATTRIBUTE_ERRORLOCUS, (int *)&locus);
    fprintf(stderr, "cert errtype %d locus %d\n", errtype, locus);
    cryptGetAttribute(cacert, CRYPT_ATTRIBUTE_ERRORTYPE, (int *)&errtype);
    cryptGetAttribute(cacert, CRYPT_ATTRIBUTE_ERRORLOCUS, (int *)&locus);
    fprintf(stderr, "cacert errtype %d locus %d\n", errtype, locus);
    cryptGetAttributeString(session, CRYPT_ATTRIBUTE_ERRORMESSAGE, NULL, &errstringlen);
    errstring = malloc(errstringlen + 10);
    cryptGetAttributeString(session, CRYPT_ATTRIBUTE_ERRORMESSAGE, errstring, &errstringlen);
    errstring[errstringlen] = 0;
    fprintf(stderr, "session errmsg: %s\n", errstring);
    free(errstring);
  }
  WARN_AND_RETURN_IF(status);

  status = cryptDestroyContext(privkey);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroySession(session);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(cacert);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(cert);
  WARN_AND_RETURN_IF(status);
  status = cryptDestroyCert(revreq);
  WARN_AND_RETURN_IF(status);
  return 0;
}

void process_opt(const char *opt) {
  if (strcmp(opt, "-v") == 0) {
    opt_verbose = 1;
  }
  else if (strcmp(opt, "-p") == 0) {
    opt_predef = 1;
  }
}
