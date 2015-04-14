#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "cryptlib.h"
#include "cadb.h"

#define LMZ_CL_DIE(status) do { if (!cryptStatusOK(status)) { fprintf(stderr, "(%s:%d) cl err %d\n", __FILE__, __LINE__, status); exit(255); } } while (0)
#define LMZ_SQLITE_DIE(err) do { if (err != SQLITE_OK) { fprintf(stderr, "(%s:%d) sqlite3 err %d\n", __FILE__, __LINE__, err); exit(255); } } while (0)

#define TMPFN_LEN 4096
typedef struct TAG_TMPFN {
    char filename[TMPFN_LEN];
    int dirname_len;
} TMPFN;

static int lmz_tmpfn_init(TMPFN * pTmpfn, const char *prefix) {
    memset(pTmpfn, sizeof(TMPFN), 0);
    if (strlen(prefix) > 16)
        return 1;
    snprintf(pTmpfn->filename, TMPFN_LEN - 1, "/tmp/%s-XXXXXX", prefix);
    pTmpfn->filename[TMPFN_LEN - 1] = '\0';
    mkdtemp(pTmpfn->filename);
    pTmpfn->dirname_len = strlen(pTmpfn->filename);
    strncat(pTmpfn->filename, "/file", TMPFN_LEN - 1 - strlen(pTmpfn->filename));
    pTmpfn->filename[TMPFN_LEN - 1] = '\0';
    return 0;
}

static int lmz_tmpfn_destroy(TMPFN * pTmpfn) {
    remove(pTmpfn->filename);
    pTmpfn->filename[pTmpfn->dirname_len] = '\0';
    remove(pTmpfn->filename);
    return 0;
}

void *lmz_file_read_full(const char *filename, int *pLen) {
    FILE *f;
    int len;
    void *data;

    f = fopen(filename, "r");
    if (f == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data = malloc(len);
    if (data == NULL) {
        fclose(f);
        return NULL;
    }
    fread(data, len, 1, f);
    *pLen = len;
    fclose(f);
    return data;
}

void *lmz_cl_get_attribute_string(CRYPT_HANDLE h, CRYPT_ATTRIBUTE_TYPE attr,
                                  int *pLen) {
    char *data;
    int len;
    LMZ_CL_ERROR status;

    status = cryptGetAttributeString(h, attr, NULL, &len);
    if (status == CRYPT_ERROR_NOTFOUND) {
        *pLen = 0;
        return NULL;
    }
    else if (!cryptStatusOK(status)) {
        fprintf(stderr, "bad attr %d\n", attr);
        LMZ_CL_DIE(status);
    }
    data = malloc(len + 16);
    status = cryptGetAttributeString(h, attr, data, &len);
    LMZ_CL_DIE(status);
    data[len] = '\0';
    *pLen = len;
    return data;
}

LMZ_CL_ERROR lmz_cl_open_mem_keyset(void *ks_data, int ks_len,
                                    /* OUT */ CRYPT_KEYSET * pKS) {
    TMPFN tmp;
    FILE *f;
    int status;

    lmz_tmpfn_init(&tmp, "lmzca");
    f = fopen(tmp.filename, "w");
    fwrite(ks_data, ks_len, 1, f);
    fclose(f);
    status =
        cryptKeysetOpen(pKS, CRYPT_UNUSED, CRYPT_KEYSET_FILE, tmp.filename,
                        CRYPT_KEYOPT_NONE);
    lmz_tmpfn_destroy(&tmp);
    return status;
}

static LMZ_CL_ERROR lmz_sign_data(const void *data, int data_len,
                                  CRYPT_CONTEXT sig_key, void **ret_sig,
                                  int *ret_sig_len) {
    /* ref cl manual pg. 140 */
    CRYPT_ENVELOPE cryptEnvelope;
    int bytesCopied;
    int status;
    char buffer[4096]; /* hopefully a detached signature is <= 4K in binary */
    char dummy[32];

    *ret_sig = NULL;
    *ret_sig_len = 0;

    status =
        cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED,
                            CRYPT_FORMAT_CRYPTLIB);
    LMZ_CL_DIE(status);
    /* Add the signing key and specify that we're using a detached signature */
    status = cryptSetAttribute(cryptEnvelope, CRYPT_ENVINFO_SIGNATURE, sig_key);
    LMZ_CL_DIE(status);
    status =
        cryptSetAttribute(cryptEnvelope, CRYPT_ENVINFO_DETACHEDSIGNATURE, 1);
    LMZ_CL_DIE(status);
    /* Add the data size information and data, wrap up the processing, 
     * and pop out the detached signature */
    status = cryptSetAttribute(cryptEnvelope, CRYPT_ENVINFO_DATASIZE, data_len);
    LMZ_CL_DIE(status);
    status = cryptPushData(cryptEnvelope, data, data_len, &bytesCopied);
    LMZ_CL_DIE(status);
    if (bytesCopied != data_len) {      
        /* we're not expecting to store megabytes here after all */
        fprintf(stderr,
                "(%s:%d) data (%d bytes) not fully copied (%d bytes copied)\n",
                __FILE__, __LINE__, data_len, bytesCopied);
        exit(255);
    }
    status = cryptFlushData(cryptEnvelope);
    LMZ_CL_DIE(status);
    status = cryptPopData(cryptEnvelope, buffer, 4096, &bytesCopied);
    LMZ_CL_DIE(status);
    *ret_sig_len = bytesCopied;
    status = cryptPopData(cryptEnvelope, dummy, 32, &bytesCopied);
    LMZ_CL_DIE(status);
    if (bytesCopied != 0) {
        fprintf(stderr, "(%s:%d) help, help -- detached sig exceeds 4K \n",
                __FILE__, __LINE__);
        exit(255);
    }
    *ret_sig = malloc(*ret_sig_len);
    memcpy(*ret_sig, buffer, *ret_sig_len);

    status = cryptDestroyEnvelope(cryptEnvelope);
    LMZ_CL_DIE(status);
    return CRYPT_OK;
}

static BOOL lmz_verify_sig(const void *data, int data_len,
                           CRYPT_CERTIFICATE pubkey, const void *sig,
                           int sig_len) {
    /* ref cl manual pg. 140 */
    CRYPT_ENVELOPE cryptEnvelope;
    int bytesCopied, sigCheckStatus;
    int status;
    status =
        cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
    LMZ_CL_DIE(status);
    /* Push in the detached signature */
    status = cryptPushData(cryptEnvelope, sig, sig_len, &bytesCopied);
    LMZ_CL_DIE(status);
    if (bytesCopied != sig_len) {
        fprintf(stderr, "verify sig partial sig read (%d/%d)\n", bytesCopied,
                sig_len);
    }
    status = cryptFlushData(cryptEnvelope);
    LMZ_CL_DIE(status);
    /* Push in the data */
    status = cryptPushData(cryptEnvelope, data, data_len, &bytesCopied);
    LMZ_CL_DIE(status);
    if (bytesCopied != data_len) {
        fprintf(stderr, "verify sig partial data read (%d/%d)\n", bytesCopied,
                data_len);
    }
    status = cryptFlushData(cryptEnvelope);
    LMZ_CL_DIE(status);
    /* add the cert */
    status = cryptSetAttribute(cryptEnvelope, CRYPT_ENVINFO_SIGNATURE, pubkey);
    if (status == CRYPT_ERROR_SIGNATURE) {
        cryptDestroyEnvelope(cryptEnvelope);
        return FALSE;
    }
    else
        LMZ_CL_DIE(status);
    /* Determine the result of the signature check */
    status =
        cryptGetAttribute(cryptEnvelope, CRYPT_ENVINFO_SIGNATURE_RESULT,
                          &sigCheckStatus);
    LMZ_CL_DIE(status);
    status = cryptDestroyEnvelope(cryptEnvelope);
    LMZ_CL_DIE(status);
    if (sigCheckStatus == CRYPT_OK) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

BOOL lmz_file_exists(const char *filename) {
    struct stat statbuf;
    int err;
    memset(&statbuf, sizeof(statbuf), 0);
    err = stat(filename, &statbuf);
    return (err == 0);
}

/*
   exports a certificate <cert> using format <format> to a memory buffer. The
   address of the buffer will be stored in <*pCert> and the length of the
   exported data will be stored in <*pLen>. pCert and pLen may not be NULL.

   On failure, *pCert is set to NULL and *pLen is set to 0.

   Returns: cryptlib error code.
 */

int lmz_export_cert(CRYPT_CERTIFICATE cert, CRYPT_CERTFORMAT_TYPE format,
                    void **pCert, int *pLen) {
    void *result;
    int len, status;
    *pCert = NULL;
    *pLen = 0;
    status = cryptExportCert(NULL, 0, &len, format, cert);
    if (!cryptStatusOK(status)) {
        return status;
    }
    result = malloc(len + 16);
    if (!result) {
        return CRYPT_ERROR_MEMORY;
    }
    status = cryptExportCert(result, len, &len, format, cert);
    if (!cryptStatusOK(status)) {
        free(result);
        return status;
    }
    *pCert = result;
    *pLen = len;
    return CRYPT_OK;
}

/*
   binds a certificate <cert> in binary format (CRYPT_CERTFORMAT_CERTIFICATE)
   to a parameter identified by <index> in the sqlite3 statement <stmt>.  The
   certificate is bound as a BLOB using sqlite3_bind_blob.  If <pSqliteError>
   is not NULL, any errors from sqlite will be stored in *pSqliteError.

   Returns: cryptlib error code. If an sqlite error happens, returns
   CRYPT_ERROR_PARAM1 and stores the sqlite error code in *pSqliteError.
 */

int lmz_bind_cert(sqlite3_stmt * stmt, int index, CRYPT_CERTIFICATE cert,
                  int *pSqliteError) {
    int status, err;
    void *data;
    int len;
    *pSqliteError = SQLITE_OK;
    status = lmz_export_cert(cert, CRYPT_CERTFORMAT_CERTIFICATE, &data, &len);
    if (!cryptStatusOK(status)) {
        return status;
    }
    err = sqlite3_bind_blob(stmt, index, data, len, free);
    if (err != SQLITE_OK) {
        if (pSqliteError) {
            *pSqliteError = err;
        };
        return CRYPT_ERROR_PARAM1;
    }
    if (pSqliteError) {
        *pSqliteError = err;
    };
    return CRYPT_OK;
}

/*
Opens a database connection to <filename> and returns it in <*pDB>.

If <filename> does not exist, creates an sqlite3 database with
that name, adds the necessary table+index structure, and returns
a connection to the newly created database, ready for a CA to be added.

Returns: cryptlib error code. CRYPT_ERROR_NOTFOUND if create_if_not_found is FALSE and
the file named in <filename> does not exist, CRYPT_ERROR_PARAM1 if bad file contents.
*/

/*
table structure:
  requests: id (autoincrement)
            recipient (CA name)
            received_on (unix time_t)
            request_type (TODO - csr / renewal)
            request_data (CSR data)
            fingerprint
              (fingerprint of CSR data, (recipient, fingerprint)
              should be unique for requests of type CSR)

  certificates: id (autoincrement)
                issuer (CA name)
                C, SP, L, O, OU, CN (DN components)
                validTo (unix time_t)
                cert_data (Cert data)
                revoked (0/1)
                request_id (id of request in requests table)
                skid (CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER)
                fingerprint
                  (fingerprint of cert data, unique even without issuer
                   -- guaranteed if the signing cert is different and who
                   in their right mind would create two ca names with same
                   signing cert? certainly not through this interface )

  actually we should put the unique constraint for subject key in requests
  but you can't actually get at the csr-signing key info from outside
  cryptlib. grr.

  revocations: cert_id (ref certificates(id))
               reason
               revoke_time

*/


LMZ_CL_ERROR lmz_ca_get_db(const char *filename, sqlite3 ** pDB,
                           BOOL create_if_not_found) {
    sqlite3 *db;
    int err;
    BOOL new_file;
    static const char *create_sql = 
        "CREATE TABLE requests ( "
        " id INTEGER PRIMARY KEY, "
        " recipient VARCHAR(20) NOT NULL, "
        " received_on INTEGER NOT NULL, "
        " request_type INTEGER NOT NULL, "
        " request_data BLOB NOT NULL, "
        " fingerprint BLOB NOT NULL, "
        " handled INTEGER NOT NULL, "
        " notes VARCHAR(100), "
        " CHECK (handled IN (0,1)) "
        "); "
        "CREATE INDEX idx_rq_fp ON requests(recipient, request_type, fingerprint);"
        "CREATE TABLE certificates ( "
        "  id INTEGER PRIMARY KEY, "
        "  issuer VARCHAR(20) NOT NULL, "
        "  C VARCHAR(2), SP VARCHAR(64), L VARCHAR(64), "
        "  O VARCHAR(64), OU VARCHAR(64), CN VARCHAR(64), "
        "  validTo INTEGER NOT NULL, cert_data BLOB NOT NULL, "
        "  revoked INTEGER NOT NULL, "
        "  request_id INTEGER NOT NULL, "
        "  skid BLOB NOT NULL, "
        "  fingerprint BLOB NOT NULL, "
        "  CHECK (revoked IN (0,1)) "
        ");"
        "CREATE UNIQUE INDEX idx_cert_fp ON certificates(issuer, fingerprint);"
        "CREATE INDEX idx_cert_skid ON certificates(issuer, skid, revoked);"
        "CREATE UNIQUE INDEX idx_cert_rq ON certificates(request_id);"    /* implies issuer thru requests.recipient */
        "CREATE TABLE revocations ( "
        "  id INTEGER NOT NULL, "
        "  revoke_date INTEGER NOT NULL, "
        "  reason INTEGER, "
        "  signature BLOB NOT NULL "
        ");"
        "CREATE UNIQUE INDEX idx_rev_id ON revocations(id);"
        "CREATE TABLE CAs ( "
        "  name VARCHAR(20) NOT NULL, "
        "  keyset BLOB NOT NULL "
        ");"
        "CREATE UNIQUE INDEX idx_ca_name ON CAs(name);"
        "CREATE TABLE signopts ( "
        " caname VARCHAR(20) NOT NULL, "
        " signopt_name VARCHAR(50) NOT NULL, "
        " valid_days INTEGER NOT NULL, "
        " keyusage INTEGER NOT NULL, "
        " extkeyusage INTEGER NOT NULL"
        ");"
        "CREATE UNIQUE INDEX idx_signopt_ca_opt ON signopts(caname, signopt_name);";

    *pDB = NULL;
    new_file = !lmz_file_exists(filename);
    if (new_file && !create_if_not_found)
        return CRYPT_ERROR_NOTFOUND;

    err = sqlite3_open(filename, &db);
    LMZ_SQLITE_DIE(err);

    if (new_file) {
        err = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
        LMZ_SQLITE_DIE(err);
    }
    else {                      
        /* is this really a database ? */
        /*
           just check, opening does not write so we try locking the db,
           if it's a db, then sqlite3_exec "BEGIN IMMEDIATE" will 
           return OK / BUSY,
           if it's not, it will return NOTADB
         */
        err = sqlite3_busy_timeout(db, 0);
        LMZ_SQLITE_DIE(err);
        err = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        if (err == SQLITE_OK) {
            /* ok, we grabbed a transaction -- now release it */
            err = sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        }
        else if (err == SQLITE_BUSY) {
            /* it succeeded in (trying to) lock anyway, ignore this failure */
        }
        else if (err == SQLITE_NOTADB) {
            /* not a database */
            sqlite3_close(db);
            return CRYPT_ERROR_PARAM1;
        }
        else
            LMZ_SQLITE_DIE(err);
    }
    err = sqlite3_busy_timeout(db, 10000);      /* wait max. 10s for a lock */
    LMZ_SQLITE_DIE(err);
    *pDB = db;

    return CRYPT_OK;
}

static void *lmz_ca_get_keyset_data(sqlite3 * db, const char *ca_name,
                                    int *pLen) {
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    void *result;

    result = NULL;
    *pLen = 0;
    err =
        sqlite3_prepare(db, "SELECT keyset FROM CAs WHERE name = ?", -1, &stmt,
                        &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return NULL;
    }
    else if (err == SQLITE_ROW) {
        *pLen = sqlite3_column_bytes(stmt, 0);
        result = malloc(*pLen);
        memcpy(result, sqlite3_column_blob(stmt, 0), *pLen);
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
        return result;
    }
    else {                      /* unexpected */
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
        return NULL;
    }
}



static BOOL lmz_ca_name_exists(sqlite3 * db, const char *ca_name) {
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    BOOL result;

    err =
        sqlite3_prepare(db, "SELECT 1 FROM CAs WHERE name = ?", -1, &stmt,
                        &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err != SQLITE_ROW) {
        result = FALSE;
    }
    else {
        result = TRUE;
    }
    sqlite3_finalize(stmt);
    return result;
}

/*
returns: CRYPT_ERROR_DUPLICATE if exists and update_on_conflict is false
*/
static LMZ_CL_ERROR lmz_ca_insert_keyset_data(sqlite3 * db, const char *ca_name,
                                              void *keyset_data,
                                              int keyset_data_len,
                                              BOOL update_on_conflict) {
    sqlite3_stmt *stmt;
    const char *tail;
    int error;

    if (update_on_conflict) {
        error =
            sqlite3_prepare(db,
                            "INSERT OR REPLACE INTO CAs (name, keyset) VALUES (?, ?)",
                            -1, &stmt, &tail);
    }
    else {
        error =
            sqlite3_prepare(db, "INSERT INTO CAs (name, keyset) VALUES (?, ?)",
                            -1, &stmt, &tail);
    }
    LMZ_SQLITE_DIE(error);
    error = sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(error);
    error =
        sqlite3_bind_blob(stmt, 2, keyset_data, keyset_data_len,
                          SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(error);
    error = sqlite3_step(stmt);
    if (error != SQLITE_DONE) {
        /* some error occured -- can't possibly be SQLITE_ROW can it? */
        error = sqlite3_finalize(stmt);
        if (error == SQLITE_CONSTRAINT) {
            return CRYPT_ERROR_DUPLICATE;
        }
        else {
            LMZ_SQLITE_DIE(error);
            return CRYPT_ERROR_WRITE;
        }
    }
    else {
        /* OK */
        error = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(error);
        return CRYPT_OK;
    }
}

/*
Adds a CA to the database in <db_filename>. If the database named by
<db_filename> does not exist, it will be created. <privkeys> is a CRYPT_CONTEXT
containing the CA private key, <cert> is the CA self-signed certificate. It
will be stored encrypted in the database using the password given in
<password>.

The name of the CA is the corresponding CRYPT_CTXINFO_LABEL of the
CRYPT_CONTEXT <privkey>.

Returns: cryptlib error code; CRYPT_ERROR_DUPLICATE if the same name already
exists.
*/

LMZ_CL_ERROR lmz_ca_create( /* OUT */ PLMZ_CA_DB * ppDB,
                           const char *db_filename, CRYPT_CONTEXT privkey,
                           CRYPT_CERTIFICATE cert, const char *password) {
    LMZ_SQLITE_ERROR error;
    LMZ_CL_ERROR status;
    sqlite3 *db;
    TMPFN temp_ks_filename;
    CRYPT_KEYSET temp_ks;
    void *ks_data;
    int ks_len;                 /* raw keyset data */
    char *ca_name;
    int ca_name_len;            /* context keylabel data == CA name */
    CRYPT_CERTIFICATE ca_cert;

    *ppDB = 0;

    /* get the connection */
    error = lmz_ca_get_db(db_filename, &db, TRUE);
    LMZ_SQLITE_DIE(error);

    /* store the key data into a keyset */
    lmz_tmpfn_init(&temp_ks_filename, "lmzca");
    status =
        cryptKeysetOpen(&temp_ks, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                        temp_ks_filename.filename, CRYPT_KEYOPT_CREATE);
    LMZ_CL_DIE(status);
    status = cryptAddPrivateKey(temp_ks, privkey, password);
    LMZ_CL_DIE(status);
    status = cryptAddPublicKey(temp_ks, cert);
    LMZ_CL_DIE(status);

    /* get the certificate */
    ca_name =
        (char *) lmz_cl_get_attribute_string(privkey, CRYPT_CTXINFO_LABEL,
                                             &ca_name_len);
    status = cryptGetPublicKey(temp_ks, &ca_cert, CRYPT_KEYID_NAME, ca_name);
    LMZ_CL_DIE(status);
    status = cryptKeysetClose(temp_ks);
    LMZ_CL_DIE(status);

    /* read it back into memory */
    ks_data = lmz_file_read_full(temp_ks_filename.filename, &ks_len);
    lmz_tmpfn_destroy(&temp_ks_filename);

    /* store it in the DB */
    status = lmz_ca_insert_keyset_data(db, ca_name, ks_data, ks_len, FALSE);
    if (status == CRYPT_ERROR_DUPLICATE) {
        sqlite3_close(db);
        free(ca_name);
        free(ks_data);
        cryptDestroyCert(ca_cert);
        return CRYPT_ERROR_DUPLICATE;
    }

    free(ks_data);
    *ppDB = malloc(sizeof(LMZ_CA_DB));
    (*ppDB)->db = db;
    (*ppDB)->db_filename = strdup(db_filename);
    (*ppDB)->ca_name = ca_name;
    (*ppDB)->ca_cert = ca_cert;
    return CRYPT_OK;
}

/*
open the CA database given in <db_filename> and return a char ** of names
terminated with NULL. Free with lmz_ca_free_names().

Returns: sqlite error code. SQLITE_NOTFOUND if no such db file. The database
handle is ALWAYS closed.  If return is not SQLITE_OK no need to free names;
*/

LMZ_SQLITE_ERROR lmz_ca_get_existing_names(const char *db_filename,
                                           char ***pNames) {
    sqlite3 *db;
    int err, status, rows, cols;
    char **sqlite_tbl;
    char **result_tbl;
    int i;

    status = lmz_ca_get_db(db_filename, &db, FALSE);
    if (status == CRYPT_ERROR_NOTFOUND)
        return SQLITE_NOTFOUND;
    if (status == CRYPT_ERROR_PARAM1)
        return SQLITE_NOTADB;
    LMZ_CL_DIE(status);

    err =
        sqlite3_get_table(db, "SELECT name FROM CAs ORDER BY name", &sqlite_tbl,
                          &rows, &cols, NULL);
    if (err != SQLITE_OK)
        return err;

    result_tbl = calloc(sizeof(char *), rows + 1);
    result_tbl[rows] = NULL;
    for (i = 0; i < rows; i++) {
        result_tbl[i] = strdup(sqlite_tbl[i + 1]);
    }

    sqlite3_free_table(sqlite_tbl);
    sqlite3_close(db);
    *pNames = result_tbl;
    return SQLITE_OK;

}

void lmz_ca_free_names(char **names) {
    char **n;
    n = names;
    while (*n != NULL) {
        free(*n);
        n++;
    }
    free(names);
}

/*
open the CA database given in <db_filename> and return a pointer
to the allocated structure in <*ppDB>. Close using lmz_ca_close.

Returns: cryptlib error code: CRYPT_ERROR_PARAM2 if db_filename does not exist
or CRYPT_ERROR_PARAM3 if ca name is not found.
*/

LMZ_CL_ERROR lmz_ca_open( /* OUT */ PLMZ_CA_DB * ppDB, const char *db_filename,
                         const char *ca_name) {
    sqlite3 *db;
    LMZ_CL_ERROR status;
    void *ks_data;
    int ks_len;
    CRYPT_KEYSET keyset;
    CRYPT_CERTIFICATE ca_cert;

    *ppDB = 0;

    db = NULL;
    /* get the connection */
    status = lmz_ca_get_db(db_filename, &db, FALSE);
    if (status == CRYPT_ERROR_NOTFOUND) {
        return CRYPT_ERROR_PARAM2;
    }
    else
        LMZ_CL_DIE(status);

    if (!lmz_ca_name_exists(db, ca_name)) {
        status = CRYPT_ERROR_PARAM3;
        sqlite3_close(db);
        return status;
    }

    ks_data = lmz_ca_get_keyset_data(db, ca_name, &ks_len);
    if (ks_data == NULL) {
        return CRYPT_ERROR_PARAM3;
    }
    status = lmz_cl_open_mem_keyset(ks_data, ks_len, &keyset);
    LMZ_CL_DIE(status);
    status = cryptGetPublicKey(keyset, &ca_cert, CRYPT_KEYID_NAME, ca_name);
    cryptKeysetClose(keyset);
    LMZ_CL_DIE(status);

    *ppDB = malloc(sizeof(LMZ_CA_DB));
    (*ppDB)->db = db;
    (*ppDB)->db_filename = strdup(db_filename);
    (*ppDB)->ca_name = strdup(ca_name);
    (*ppDB)->ca_cert = ca_cert;

    return CRYPT_OK;
}

/*
close the CA database given in <pDB>.

Returns: cryptlib error code.
*/

LMZ_CL_ERROR lmz_ca_close(PLMZ_CA_DB pDB) {
    LMZ_SQLITE_ERROR err;

    err = sqlite3_close(pDB->db);
    LMZ_SQLITE_DIE(err);
    free(pDB->ca_name);
    free(pDB->db_filename);
    cryptDestroyCert(pDB->ca_cert);
    free(pDB);
    return CRYPT_OK;
}


static LMZ_CL_ERROR lmz_ca_add_request_internal(PLMZ_CA_DB pDB,
                                                int request_type,
                                                const char *notes,
                                                time_t * received_on,
                                                CRYPT_CERTIFICATE request,
                                                /* OUT */ int *pID);
LMZ_CL_ERROR lmz_ca_add_request(PLMZ_CA_DB pDB, CRYPT_CERTIFICATE request,
                                /* OUT */ int *pID) {
    int status;
    int err;

    /* read and lock other writers out -- shouldn't normally return busy 
     * since we set a 10s timeout */
    err = sqlite3_exec(pDB->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    LMZ_SQLITE_DIE(err);
    status =
        lmz_ca_add_request_internal(pDB, LMZ_CA_REQUEST_CSR, NULL, NULL,
                                    request, pID);
    if (cryptStatusOK(status)) {
        err = sqlite3_exec(pDB->db, "COMMIT", NULL, NULL, NULL);
        LMZ_SQLITE_DIE(err);
    }
    else {
        err = sqlite3_exec(pDB->db, "ROLLBACK", NULL, NULL, NULL);
        LMZ_SQLITE_DIE(err);
    }
    return status;
}

static LMZ_CL_ERROR lmz_hash_data(void *data, int data_len, void **pHashBytes,
                                  int *pHashLen) {
    CRYPT_CONTEXT hash_ctx;
    char hash_value[CRYPT_MAX_HASHSIZE + 8];
    int hash_len;
    int status;

    status = cryptCreateContext(&hash_ctx, CRYPT_UNUSED, CRYPT_ALGO_SHA1);
    if (cryptStatusError(status))
        return status;
    status = cryptEncrypt(hash_ctx, data, data_len);
    if (cryptStatusError(status)) {
        cryptDestroyContext(hash_ctx);
        return status;
    }
    status = cryptEncrypt(hash_ctx, data, 0);   /* final call */
    if (cryptStatusError(status)) {
        cryptDestroyContext(hash_ctx);
        return status;
    }
    status =
        cryptGetAttributeString(hash_ctx, CRYPT_CTXINFO_HASHVALUE, hash_value,
                                &hash_len);
    if (cryptStatusError(status)) {
        cryptDestroyContext(hash_ctx);
        return status;
    }
    status = cryptDestroyContext(hash_ctx);
    if (cryptStatusError(status)) {
        return status;
    }
    *pHashBytes = malloc(hash_len);
    if (*pHashBytes == NULL)
        LMZ_CL_DIE(CRYPT_ERROR_MEMORY);
    *pHashLen = hash_len;
    memcpy(*pHashBytes, hash_value, hash_len);
    return CRYPT_OK;
}


static LMZ_CL_ERROR lmz_ca_csr_request_exists(PLMZ_CA_DB pDB, void *fp,
                                              int fp_len, BOOL * exists) {
    sqlite3_stmt *stmt;
    int err;
    const char *tail;

    err =
        sqlite3_prepare(pDB->db,
                        "SELECT 1 FROM requests WHERE (recipient = ?) AND (request_type = ?) AND (fingerprint = ?)",
                        -1, &stmt, &tail);
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 2, LMZ_CA_REQUEST_CSR);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_blob(stmt, 3, fp, fp_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_ROW) {    
        /* found */
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
        *exists = TRUE;
        return CRYPT_OK;
    }
    else if (err == SQLITE_DONE) {      
        /* not found */
        err = sqlite3_finalize(stmt);
        *exists = FALSE;
        return CRYPT_OK;
    }
    else { 
        /* other error */
        err = sqlite3_finalize(stmt);
        return CRYPT_ERROR_READ;
    }
}

/*

add the request in <request> to the CA database <pDB> returning the generated
sequential integer ID (database ID, not serial number), into <*pID>.

Returns: cryptlib error code.
*/

static LMZ_CL_ERROR lmz_ca_add_request_internal(PLMZ_CA_DB pDB,
                                                int request_type,
                                                const char *notes,
                                                time_t * received_on,
                                                CRYPT_CERTIFICATE request,
                                                /* OUT */ int *pID) {
    sqlite3_stmt *stmt;
    int err;
    void *req_data;
    int req_len;
    const char *tail;
    int status;
    void *hash_value;
    int hash_len;
    time_t rcv_tm;

    rcv_tm = (received_on != NULL) ? (*received_on) : time(NULL);
    /* check recipient, fingerprint unique for request if it's a CSR 
     * or new request */
    status =
        cryptExportCert(NULL, 0, &req_len, CRYPT_CERTFORMAT_CERTIFICATE,
                        request);
    LMZ_CL_DIE(status);
    req_data = malloc(req_len + 16);
    status =
        cryptExportCert(req_data, req_len + 16, &req_len,
                        CRYPT_CERTFORMAT_CERTIFICATE, request);
    LMZ_CL_DIE(status);

    status = lmz_hash_data(req_data, req_len, &hash_value, &hash_len);
    LMZ_CL_DIE(status);

    if (request_type == LMZ_CA_REQUEST_CSR) {
        BOOL exists;
        status = lmz_ca_csr_request_exists(pDB, hash_value, hash_len, &exists);
        if (!cryptStatusOK(status)) {
            free(req_data);
            free(hash_value);
            return status;
        }
        if (exists) {
            free(req_data);
            free(hash_value);
            return CRYPT_ERROR_DUPLICATE;
        }
    }

    /* either there is no duplicate or this is a renewal */
    err =
        sqlite3_prepare(pDB->db,
                        "INSERT INTO requests (recipient, received_on, request_type, request_data, fingerprint, handled, notes) VALUES (?, ?, ?, ?, ?, 0, ?)",
                        -1, &stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 2, rcv_tm);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 3, request_type);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_blob(stmt, 4, req_data, req_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_blob(stmt, 5, hash_value, hash_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    if (notes) {
        err = sqlite3_bind_text(stmt, 6, notes, -1, SQLITE_TRANSIENT);
    }
    else {
        err = sqlite3_bind_null(stmt, 6);
    }
    err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
    }
    err = sqlite3_finalize(stmt);
    LMZ_SQLITE_DIE(err);
    *pID = (int) sqlite3_last_insert_rowid(pDB->db);
    free(req_data);
    free(hash_value);
    return CRYPT_OK;
}

/*

gets the request in the CA database <pDB> corresponding to the database id
given in <id>, returning it into <*pRequest>.

Returns: cryptlib error code. CRYPT_ERROR_NOTFOUND if there is no such id for
the CA in pDB.

*/

LMZ_CL_ERROR lmz_ca_get_request(PLMZ_CA_DB pDB, int id,
                                /* OUT */ CRYPT_CERTIFICATE * pRequest, 
                                int *pHandled, char **pNotes) {
    sqlite3_stmt *stmt;
    int err;
    void *req_data;
    int req_len;
    const char *tail;
    int status;
    int notes_len;
    err =
        sqlite3_prepare(pDB->db,
                        "SELECT request_data, handled, notes FROM requests WHERE (recipient = ?) AND (id = ?)",
                        -1, &stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 2, id);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_ROW) {
        req_len = sqlite3_column_bytes(stmt, 0);
        req_data = malloc(req_len);
        memcpy(req_data, sqlite3_column_blob(stmt, 0), req_len);
        *pHandled = sqlite3_column_int(stmt, 1);
        if (pNotes) {
            if (sqlite3_column_type(stmt, 2) == SQLITE_NULL) {
                *pNotes = NULL;
            }
            else {
                notes_len = sqlite3_column_bytes(stmt, 2);
                *pNotes = malloc(notes_len + 16);
                strcpy(*pNotes, sqlite3_column_text(stmt, 2));
            }
        }
        status = cryptImportCert(req_data, req_len, CRYPT_UNUSED, pRequest);
        LMZ_CL_DIE(status);
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
        return CRYPT_OK;
    }
    else if (err == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_NOTFOUND;
    }
    else {
        err = sqlite3_finalize(stmt);
        LMZ_SQLITE_DIE(err);
        return CRYPT_ERROR_READ;
    }
}

/*

Gets the signing key for the CA named in <pDB>, with the privatekey password
<signing_password>.

Returns: cryptlib error code; CRYPT_ERROR_WRONGKEY if wrong password,
CRYPT_ERROR_NOTFOUND if no rows (how come?)

*/

LMZ_CL_ERROR lmz_ca_get_signing_key(PLMZ_CA_DB pDB, const char *signing_password,
                                    /* OUT */ CRYPT_CONTEXT * pSigningKey) {
    void *ks_data;
    int ks_len;
    CRYPT_KEYSET keyset;
    int status;
    *pSigningKey = CRYPT_ERROR_NOTINITED;
    ks_data = lmz_ca_get_keyset_data(pDB->db, pDB->ca_name, &ks_len);
    if (ks_data == NULL) {
        return CRYPT_ERROR_NOTFOUND;
    }
    status = lmz_cl_open_mem_keyset(ks_data, ks_len, &keyset);
    LMZ_CL_DIE(status);
    status =
        cryptGetPrivateKey(keyset, pSigningKey, CRYPT_KEYID_NAME, pDB->ca_name,
                           signing_password);
    if (status == CRYPT_ERROR_PARAM5) {
        status = CRYPT_ERROR_WRONGKEY;
    }
    if (status == CRYPT_ERROR_WRONGKEY) {
        cryptKeysetClose(keyset);  /* don't bother with the status of this */
        return status;
    }
    else {
        status = cryptKeysetClose(keyset);
        LMZ_CL_DIE(status);
        return CRYPT_OK;
    }
}

static LMZ_CL_ERROR lmz_ca_save_cert_internal(PLMZ_CA_DB pDB, int request_id,
                                              CRYPT_CERTIFICATE signed_cert);
LMZ_CL_ERROR lmz_ca_save_cert(PLMZ_CA_DB pDB, int request_id,
                              CRYPT_CERTIFICATE signed_cert) {
    int err;
    int status;
    err = sqlite3_exec(pDB->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if (err != SQLITE_OK) {
        return CRYPT_ERROR_WRITE;
    }
    status = lmz_ca_save_cert_internal(pDB, request_id, signed_cert);
    if (!cryptStatusOK(status)) {
        err = sqlite3_exec(pDB->db, "ROLLBACK", NULL, NULL, NULL);
        return status;
    }
    else {
        err = sqlite3_exec(pDB->db, "COMMIT", NULL, NULL, NULL);
        if (err != SQLITE_OK) {
            return CRYPT_ERROR_WRITE;
        }
    }
    return CRYPT_OK;
}

/* Bind the cryptlib attributes (e.g. C, OU, CN) of the certificate <cert> to 
 * parameters of the sqlite3 statement <stmt>. Number of attributes (and 
 * parameter indices) is in <nattrs>. The indices are in <indices> and the
 * attributes are in <attrs>.
 *
 * On an sqlite error returns CRYPT_ERROR_PARAM1 and set *pErr to the sqlite 
 * error.
 * On a cryptlib error will return the error.
 */
static LMZ_CL_ERROR lmz_bind_cert_components(sqlite3_stmt *stmt, 
                                    CRYPT_CERTIFICATE cert,
                                    int nattrs, int indices[],
                                    CRYPT_ATTRIBUTE_TYPE attrs[], int *pErr) {
    int i;
    int status;
    int err;
    char dn_comp_buf[CRYPT_MAX_TEXTSIZE + 16];
    int dn_comp_len;

    *pErr = SQLITE_OK;
    for (i = 0; i < nattrs; i++) {
        fprintf(stderr, "binding attr %d\n", attrs[i]);
        status =
            cryptGetAttributeString(cert, attrs[i], dn_comp_buf, &dn_comp_len);
        if (status == CRYPT_ERROR_NOTFOUND) {
            fprintf(stderr, "-- %d not found, binding NULL\n", attrs[i]);
            err = sqlite3_bind_null(stmt, indices[i]);
            if (err != SQLITE_OK) {
                *pErr = err;
                return CRYPT_ERROR_PARAM1;
            }
        }
        else if (cryptStatusOK(status)) {
            fprintf(stderr, "-- %d found -- len = %d\n", attrs[i], dn_comp_len);
            err =
                sqlite3_bind_text(stmt, indices[i], dn_comp_buf, dn_comp_len,
                                  SQLITE_TRANSIENT);
            if (err != SQLITE_OK) {
                *pErr = err;
                return CRYPT_ERROR_PARAM1;
            }
        }
        else
            return status;
    }
    return CRYPT_OK;
}

/*
Inserts the signed cert in <signed_cert> which originated from the request with
id <request_id> into the CA database <pDB>.

Returns: cryptlib error code: CRYPT_ERROR_PARAM3 if cert not signed.
CRYPT_ERROR_DUPLICATE if duplicate insert.
*/

static LMZ_CL_ERROR lmz_ca_save_cert_internal(PLMZ_CA_DB pDB,
                                              int request_id,
                                              CRYPT_CERTIFICATE signed_cert) {
    int err;
    int status;
    sqlite3_stmt *ins_stmt, *upd_stmt, *sel_stmt;
    const char *tail;
    time_t valid_to;
    int valid_to_len;
    void *fp;
    int fp_len;
    void *skid;
    int skid_len;
    int param_indices[] = { 2, 3, 4, 5, 6, 7 }; /* param# for below attrs */
    CRYPT_ATTRIBUTE_TYPE attrs[] = { 
        CRYPT_CERTINFO_COUNTRYNAME, 
        CRYPT_CERTINFO_STATEORPROVINCENAME,
        CRYPT_CERTINFO_LOCALITYNAME, 
        CRYPT_CERTINFO_ORGANIZATIONNAME, 
        CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
        CRYPT_CERTINFO_COMMONNAME
    };

    /* Prepare statements for execution.
     * There are 3 statements: 
     * - select to check if there is a duplicate unrevoked cert for the same key
     * - update to set the handled flag on the request
     * - insert to insert the actual certificate into the certificates table
     */
    err =
        sqlite3_prepare(pDB->db,
                        "SELECT 1 FROM certificates WHERE (issuer = ?) AND (skid = ?) AND (revoked = 0)",
                        -1, &sel_stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(sel_stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    skid =
        lmz_cl_get_attribute_string(signed_cert,
                                    CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
                                    &skid_len);
    err = sqlite3_bind_blob(sel_stmt, 2, skid, skid_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    free(skid);

    err =
        sqlite3_prepare(pDB->db,
                        "UPDATE requests SET handled = 1 WHERE (id = ?)", -1,
                        &upd_stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(upd_stmt, 1, request_id);
    LMZ_SQLITE_DIE(err);

    err = sqlite3_prepare(pDB->db,
                          "INSERT INTO certificates (issuer, C, SP, L, O, OU, CN, validTo, cert_data, request_id, fingerprint, skid, revoked) "
                          " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)", -1,
                          &ins_stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(ins_stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);

    /* reselect subj DN */

    status =
        cryptSetAttribute(signed_cert, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CERTINFO_SUBJECTNAME);
    LMZ_CL_DIE(status);
    status = lmz_bind_cert_components(ins_stmt, signed_cert,
                                      sizeof(attrs) / sizeof(attrs[0]),
                                      param_indices, attrs, &err);
    if (!cryptStatusOK(status)) {
        if (status == CRYPT_ERROR_PARAM1)
            LMZ_SQLITE_DIE(err);
        else
            LMZ_CL_DIE(status);
    }
    status =
        cryptGetAttributeString(signed_cert, CRYPT_CERTINFO_VALIDTO, &valid_to,
                                &valid_to_len);
    LMZ_CL_DIE(status);
    err = sqlite3_bind_int(ins_stmt, 8, valid_to);
    LMZ_SQLITE_DIE(err);
    status = lmz_bind_cert(ins_stmt, 9, signed_cert, &err);
    if (!cryptStatusOK(status)) {
        if (err != SQLITE_OK)
            LMZ_SQLITE_DIE(err);
        else
            LMZ_CL_DIE(status);
    }
    err = sqlite3_bind_int(ins_stmt, 10, request_id);
    LMZ_SQLITE_DIE(err);
    fp = lmz_cl_get_attribute_string(signed_cert,
                                     CRYPT_CERTINFO_FINGERPRINT_SHA1, &fp_len);
    err = sqlite3_bind_blob(ins_stmt, 11, fp, fp_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    skid =
        lmz_cl_get_attribute_string(signed_cert,
                                    CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
                                    &skid_len);
    err = sqlite3_bind_blob(ins_stmt, 12, skid, skid_len, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    free(fp);
    free(skid);
    /* end prepare statements for execution */

    /* check for existing skid that is not yet revoked */
    err = sqlite3_step(sel_stmt);
    if (err == SQLITE_ROW)
        goto rollback_dup_skid;
    else if (err != SQLITE_DONE)
        goto rollback_sel;
    /* update request set handled */
    err = sqlite3_step(upd_stmt);
    if (err != SQLITE_DONE)
        goto rollback_upd;
    /* insert certificate */
    err = sqlite3_step(ins_stmt);
    if (err != SQLITE_DONE)
        goto rollback_ins;

    err = sqlite3_finalize(ins_stmt);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_finalize(upd_stmt);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_finalize(sel_stmt);
    LMZ_SQLITE_DIE(err);
    return CRYPT_OK;

  rollback_dup_skid:
    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
    sqlite3_finalize(sel_stmt);
    return CRYPT_ERROR_DUPLICATE;
  rollback_sel:
    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
    sqlite3_finalize(sel_stmt);
    LMZ_SQLITE_DIE(err);
    return CRYPT_ERROR_WRITE;
  rollback_ins:
    err = sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
    sqlite3_finalize(sel_stmt);
    if (err == SQLITE_CONSTRAINT)
        return CRYPT_ERROR_DUPLICATE;
    LMZ_SQLITE_DIE(err);
    return CRYPT_ERROR_WRITE;
  rollback_upd:
    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
    sqlite3_finalize(sel_stmt);
    LMZ_CL_DIE(err);
    return CRYPT_ERROR_WRITE;
}


static LMZ_CL_ERROR lmz_ca_revoke_cert_internal(PLMZ_CA_DB pDB, int cert_id,
                                                int revoke_reason,
                                                time_t * revoke_time,
                                                CRYPT_CONTEXT signing_key);

/* Revoke a certificate <cert_id> for the reason <revoke_reason> in
 * CRYPT_CRLREASON_*.
 *
 * This wraps lmz_ca_revoke_cert_internal in a transaction.
 */
LMZ_CL_ERROR lmz_ca_revoke_cert(PLMZ_CA_DB pDB, int cert_id, int revoke_reason,
                                CRYPT_CONTEXT signing_key) {
    int err;
    int status;
    if ((revoke_reason >= CRYPT_CRLREASON_UNSPECIFIED)
        && (revoke_reason < CRYPT_CRLREASON_LAST)) {
        err = sqlite3_exec(pDB->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        if (err != SQLITE_OK) {
            return CRYPT_ERROR_WRITE;
        }
        status =
            lmz_ca_revoke_cert_internal(pDB, cert_id, revoke_reason, NULL,
                                        signing_key);
        if (!cryptStatusOK(status)) {
            err = sqlite3_exec(pDB->db, "ROLLBACK", NULL, NULL, NULL);
            return status;
        }
        else {
            err = sqlite3_exec(pDB->db, "COMMIT", NULL, NULL, NULL);
            if (err != SQLITE_OK) {
                return CRYPT_ERROR_WRITE;
            }
        }
        return CRYPT_OK;
    }
    else {
        return CRYPT_ERROR_PARAM3;
    }
}

/* Called by lmz_ca_revoke_cert. 
 */
static LMZ_CL_ERROR lmz_ca_revoke_cert_internal(PLMZ_CA_DB pDB, int cert_id,
                                                int revoke_reason,
                                                time_t * revoke_time,
                                                CRYPT_CONTEXT signing_key) {
    int err;
    char *update_stmt_text = NULL;
    time_t now;
    int n_rows;
    int status = CRYPT_OK;
    struct {
        int id;
        time_t revoke_time;
        int reason;
    } revoke_data;
    void *sig;
    int sig_len;
    sqlite3_stmt *ins_stmt = NULL;
    const char *tail;

    if ((revoke_reason >= CRYPT_CRLREASON_UNSPECIFIED)
        && (revoke_reason < CRYPT_CRLREASON_LAST)) {
        now = time(NULL);
        revoke_data.id = cert_id;
        if (revoke_time == NULL) {
            revoke_data.revoke_time = now;
        }
        else {
            revoke_data.revoke_time = *revoke_time;
        }
        revoke_data.reason = revoke_reason;
        status =
            lmz_sign_data(&revoke_data, sizeof(revoke_data), signing_key, &sig,
                          &sig_len);
        LMZ_CL_DIE(status);
        err =
            sqlite3_prepare(pDB->db,
                            "INSERT INTO revocations (id, revoke_date, reason, signature) VALUES (?, ?, ?, ?)",
                            -1, &ins_stmt, &tail);
        LMZ_SQLITE_DIE(err);
        err = sqlite3_bind_int(ins_stmt, 1, revoke_data.id);
        LMZ_SQLITE_DIE(err);
        err = sqlite3_bind_int(ins_stmt, 2, revoke_data.revoke_time);
        LMZ_SQLITE_DIE(err);
        if (revoke_reason == CRYPT_CRLREASON_UNSPECIFIED) {
            err = sqlite3_bind_null(ins_stmt, 3);
        }
        else {
            err = sqlite3_bind_int(ins_stmt, 3, revoke_data.reason);
        }
        LMZ_SQLITE_DIE(err);
        err = sqlite3_bind_blob(ins_stmt, 4, sig, sig_len, free);
        LMZ_SQLITE_DIE(err);

        /*
           begin immediate; -- handled by caller
           insert into revocations (..)
           update certificates set revoked=1 where
         */

        update_stmt_text =
            sqlite3_mprintf
            ("UPDATE certificates SET revoked = 1 WHERE (id = %d) AND (issuer = '%q')",
             revoke_data.id, pDB->ca_name);

        /* execute the update and verify that it found a row */
        err = sqlite3_exec(pDB->db, update_stmt_text, NULL, NULL, NULL);
        if (err != SQLITE_OK) {
            status = CRYPT_ERROR_WRITE;
            goto rollback;
        }
        n_rows = sqlite3_changes(pDB->db);
        if (n_rows != 1) {
            status = CRYPT_ERROR_NOTFOUND;
            goto rollback;
        }

        /* do the insert, converting SQLITE_CONSTRAINT error to
           CRYPT_ERROR_DUPLICATE and any other to CRYPT_ERROR_WRITE */
        err = sqlite3_step(ins_stmt);
        if (err != SQLITE_DONE) {
            status = CRYPT_ERROR_WRITE;
            err = sqlite3_finalize(ins_stmt);
            ins_stmt = NULL;
            if (err == SQLITE_CONSTRAINT) {
                status = CRYPT_ERROR_DUPLICATE;
            }
            goto rollback;
        }

        sqlite3_finalize(ins_stmt);
        sqlite3_free(update_stmt_text);
        return CRYPT_OK;

      rollback:
        if (ins_stmt != NULL)
            sqlite3_finalize(ins_stmt);
        sqlite3_free(update_stmt_text);
        return status;
    }
    else {
        return CRYPT_ERROR_PARAM3;
    }
}


/* Generates the CRL for a CA by querying the revocations table. 
 * The CRL's next-update date is set to a far future date because 
 * CRL generation is done manually and there is no guarantee that the user 
 * will ever generate another CRL. This is allowed by the RFC.
 */
LMZ_CL_ERROR lmz_ca_gen_crl(PLMZ_CA_DB pDB, /* OUT */ CRYPT_CERTIFICATE * pCRL) {
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    int status;
    CRYPT_CERTIFICATE crl;
    CRYPT_CERTIFICATE temp_cert;
    const void *temp_cert_data;
    int temp_cert_len;
    time_t future_date;
    struct {
        int id;
        time_t revoke_time;
        int reason;
    } revoke_data;
    const void *sig;
    int sig_len;

    *pCRL = CRYPT_ERROR_NOTINITED;

    err =
        sqlite3_prepare(pDB->db,
                        "SELECT c.cert_data, r.id, r.revoke_date, r.reason, r.signature FROM certificates c INNER JOIN revocations r ON (c.id = r.id) WHERE c.issuer = ?",
                        -1, &stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);

    status = cryptCreateCert(&crl, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL);
    /* max. signed value for a time_t */
    if (sizeof(time_t) == 8) {
        future_date = 0x7fffffffffffffff;
    }
    else { 
        /* assume sizeof time_t == 4 */
        future_date = 0x7fffffff;
    }
    status =
        cryptSetAttributeString(crl, CRYPT_CERTINFO_NEXTUPDATE, &future_date,
                                sizeof(time_t));
    LMZ_CL_DIE(status);

    /* run through revocations */
    while ((err = sqlite3_step(stmt)) == SQLITE_ROW) {
        temp_cert_len = sqlite3_column_bytes(stmt, 0);
        temp_cert_data = sqlite3_column_blob(stmt, 0);
        revoke_data.id = sqlite3_column_int(stmt, 1);
        revoke_data.revoke_time = sqlite3_column_int(stmt, 2);
        if (sqlite3_column_type(stmt, 3) == SQLITE_NULL) {
            revoke_data.reason = CRYPT_CRLREASON_UNSPECIFIED;
        }
        else {
            revoke_data.reason = sqlite3_column_int(stmt, 3);
        }
        sig_len = sqlite3_column_bytes(stmt, 4);
        sig = sqlite3_column_blob(stmt, 4);

        if (lmz_verify_sig
            (&revoke_data, sizeof(revoke_data), pDB->ca_cert, sig, sig_len)) {
            status =
                cryptImportCert(temp_cert_data, temp_cert_len, CRYPT_UNUSED,
                                &temp_cert);
            LMZ_CL_DIE(status);
            status =
                cryptSetAttribute(crl, CRYPT_CERTINFO_CERTIFICATE, temp_cert);
            LMZ_CL_DIE(status);
            status =
                cryptSetAttributeString(crl, CRYPT_CERTINFO_REVOCATIONDATE,
                                        &revoke_data.revoke_time,
                                        sizeof(time_t));
            LMZ_CL_DIE(status);
            status =
                cryptSetAttribute(crl, CRYPT_CERTINFO_CRLREASON,
                                  revoke_data.reason);
            LMZ_CL_DIE(status);
            status = cryptDestroyCert(temp_cert);
            LMZ_CL_DIE(status);
        }
        else {
            fprintf(stderr, "found bad rev sig (id: %d)\n", revoke_data.id);
        }

    }
    if (err == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        *pCRL = crl;
        return CRYPT_OK;
    }
    else {
        sqlite3_finalize(stmt);
        cryptDestroyCert(crl);
        LMZ_SQLITE_DIE(err);
        return CRYPT_ERROR_READ;
    }

}

LMZ_CL_ERROR lmz_ca_get_cert(PLMZ_CA_DB pDB, int id,
                             /* OUT */ CRYPT_CERTIFICATE * pCert) {
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    int status;
    CRYPT_CERTIFICATE cert;
    const void *cert_data;
    int cert_len;

    *pCert = CRYPT_ERROR_NOTINITED;
    cert = CRYPT_ERROR_NOTINITED;

    err =
        sqlite3_prepare(pDB->db,
                        "SELECT c.cert_data FROM certificates c WHERE (c.issuer = ?) AND (c.id = ?)",
                        -1, &stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 2, id);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_NOTFOUND;
    }
    else if (err == SQLITE_ROW) {
        cert_len = sqlite3_column_bytes(stmt, 0);
        cert_data = sqlite3_column_blob(stmt, 0);
        status = cryptImportCert(cert_data, cert_len, CRYPT_UNUSED, &cert);
        LMZ_CL_DIE(status);
        *pCert = cert;
        sqlite3_finalize(stmt);
        return CRYPT_OK;
    }
    else
        LMZ_SQLITE_DIE(err);
    return CRYPT_ERROR_READ;
}

/*
  apply a signing option to a certificate (still to-be-signed),
  clears all KU and EKU not in sign opt,
  changes VALIDFROM to current time, VALIDTO to current time + valid_days
 */
LMZ_CL_ERROR lmz_ca_apply_sign_opt(PLMZ_SIGN_OPT pOpt,
                                   CRYPT_CERTIFICATE tbsCert) {
    int status;
    int i;
    time_t now, then;

    /* set ku */
    status = cryptSetAttribute(tbsCert, CRYPT_CERTINFO_KEYUSAGE, pOpt->ku_bits);
    if (!cryptStatusOK(status))
        return status;
    /* clear eku first to prevent any unknown/unsupported flags sneaking in 
     * from the CSR */
    status = cryptDeleteAttribute(tbsCert, CRYPT_CERTINFO_EXTKEYUSAGE);
    if (status == CRYPT_ERROR_NOTFOUND) {
        /* do nothing -- maybe it doesn't have EKU */
    }
    else if (!cryptStatusOK(status))
        return status;
    /* add what we have */
    for (i = 0; i < pOpt->eku_num; i++) {
        status = cryptSetAttribute(tbsCert, pOpt->eku_flags[i], CRYPT_UNUSED);
        if (!cryptStatusOK(status))
            return status;
    }

    /* set validity period from now to <valid_days> days from now */
    now = time(NULL);
    then = now + (86400 * pOpt->valid_days);


    status =
        cryptSetAttributeString(tbsCert, CRYPT_CERTINFO_VALIDFROM, &now,
                                sizeof(time_t));
    if (!cryptStatusOK(status))
        return status;
    status =
        cryptSetAttributeString(tbsCert, CRYPT_CERTINFO_VALIDTO, &then,
                                sizeof(time_t));
    if (!cryptStatusOK(status))
        return status;
    return CRYPT_OK;
}

LMZ_CL_ERROR lmz_ca_enum_signopts(PLMZ_CA_DB pDB, char ***pNames) {
    int err, rows, cols;
    char *query;
    char **sqlite_tbl;
    char **result_tbl;
    int i;

    query =
        sqlite3_mprintf
        ("SELECT signopt_name FROM signopts WHERE caname = '%q' ORDER BY signopt_name",
         pDB->ca_name);
    err = sqlite3_get_table(pDB->db, query, &sqlite_tbl, &rows, &cols, NULL);
    if (err != SQLITE_OK) {
        printf("sqlite error %d\n", err);
        sqlite3_free(query);
        return CRYPT_ERROR_READ;
    }
    result_tbl = calloc(sizeof(char *), rows + 1);
    result_tbl[rows] = NULL;
    for (i = 0; i < rows; i++) {
        result_tbl[i] = strdup(sqlite_tbl[i + 1]);
    }
    sqlite3_free_table(sqlite_tbl);
    sqlite3_free(query);
    *pNames = result_tbl;
    return CRYPT_OK;

}

void lmz_ca_free_enum_signopts(char **names) {
    char **n;
    n = names;
    while (*n != NULL) {
        free(*n);
        n++;
    }
    free(names);
}

static int eku_attr_encode[] = {
    CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
    CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
    CRYPT_CERTINFO_EXTKEY_CODESIGNING,
    CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
    CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
    0
};


LMZ_CL_ERROR lmz_ca_get_signopt(PLMZ_CA_DB pDB, const char *name,
                                /* OUT */ PLMZ_SIGN_OPT opt) {
    int err;
    const char *tail;
    sqlite3_stmt *stmt;
    err = sqlite3_prepare(pDB->db,
                          "SELECT valid_days, keyusage, extkeyusage FROM signopts WHERE (caname = ?) AND (signopt_name = ?)",
                          -1, &stmt, &tail);
    if (err != SQLITE_OK) {
        return CRYPT_ERROR_READ;
    }
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_NOTFOUND;
    }
    else if (err == SQLITE_ROW) {
        int i;
        int encoded_eku;
        opt->valid_days = sqlite3_column_int(stmt, 0);
        opt->ku_bits = sqlite3_column_int(stmt, 1);
        opt->eku_num = 0;
        encoded_eku = sqlite3_column_int(stmt, 2);
        for (i = 0; eku_attr_encode[i] != 0; i++) {
            if ((encoded_eku & (1 << i)) != 0) {
                opt->eku_flags[opt->eku_num++] = eku_attr_encode[i];
            }
        }
        sqlite3_finalize(stmt);
        return CRYPT_OK;
    }
    else {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_READ;
    }
}


LMZ_CL_ERROR lmz_ca_save_signopt(PLMZ_CA_DB pDB, const char *name,
                                 PLMZ_SIGN_OPT opt) {
    int err;
    const char *tail;
    sqlite3_stmt *stmt;
    int i, j;
    int encoded_eku;
    err =
        sqlite3_prepare(pDB->db,
                        "INSERT OR REPLACE INTO signopts (caname, signopt_name, valid_days, keyusage, extkeyusage) VALUES (?, ?, ?, ?, ?)",
                        -1, &stmt, &tail);
    if (err != SQLITE_OK) {
        return CRYPT_ERROR_WRITE;
    }
    encoded_eku = 0;
    for (i = 0; i < opt->eku_num; i++) {
        for (j = 0; eku_attr_encode[j] != 0; j++) {
            if (opt->eku_flags[i] == eku_attr_encode[j]) {
                encoded_eku = encoded_eku | (1 << j);
            }
        }
    }
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 3, opt->valid_days);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 4, opt->ku_bits);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 5, encoded_eku);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_WRITE;
    }
    sqlite3_finalize(stmt);
    return CRYPT_OK;

}

LMZ_CL_ERROR lmz_ca_delete_signopt(PLMZ_CA_DB pDB, const char *name) {
    int err;
    const char *tail;
    sqlite3_stmt *stmt;
    int num;
    err =
        sqlite3_prepare(pDB->db,
                        "DELETE FROM signopts WHERE (caname = ?) AND (signopt_name = ?)",
                        -1, &stmt, &tail);
    if (err != SQLITE_OK) {
        return CRYPT_ERROR_WRITE;
    }
    err = sqlite3_bind_text(stmt, 1, pDB->ca_name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CRYPT_ERROR_WRITE;
    }
    sqlite3_finalize(stmt);
    num = sqlite3_changes(pDB->db);
    if (num == 1) {
        return CRYPT_OK;
    }
    else {
        return CRYPT_ERROR_NOTFOUND;
    }
}

LMZ_CL_ERROR lmz_ca_renew_cert(PLMZ_CA_DB pDB, int cert_id, int valid_days,
                               CRYPT_CONTEXT signing_key) {
    CRYPT_CERTIFICATE old_cert;
    CRYPT_CERTIFICATE new_cert;
    time_t now, then;
    void *dn_comp;
    int dn_comp_len;
    int status, err;
    int copied_attrs[] = { 
        CRYPT_CERTINFO_COUNTRYNAME, 
        CRYPT_CERTINFO_STATEORPROVINCENAME,
        CRYPT_CERTINFO_LOCALITYNAME,
        CRYPT_CERTINFO_ORGANIZATIONNAME, 
        CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
        CRYPT_CERTINFO_COMMONNAME,
        CRYPT_CERTINFO_EMAIL, 
        0
    };
    int copied_ekus[] = { 
        CRYPT_CERTINFO_EXTKEY_SERVERAUTH, 
        CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
        CRYPT_CERTINFO_EXTKEY_CODESIGNING,
        CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
        CRYPT_CERTINFO_EXTKEY_TIMESTAMPING, 
        0
    };
    int i;
    int ku, unused;
    int oldreq_id;
    CRYPT_CERTIFICATE oldreq;
    int oldreq_handled;
    int newreq_id;
    sqlite3_stmt *stmt;
    const char *tail;


    /* fetch cert */
    status = lmz_ca_get_cert(pDB, cert_id, &old_cert);
    if (!cryptStatusOK(status)) {
        return CRYPT_ERROR_READ;
    }
    /* create tbs-cert */
    status =
        cryptCreateCert(&new_cert, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(old_cert);
        return status;
    }
    /* copy attrs -- DN comps */
    for (i = 0; copied_attrs[i] != 0; i++) {
        dn_comp =
            lmz_cl_get_attribute_string(old_cert, copied_attrs[i],
                                        &dn_comp_len);
        if (dn_comp != NULL) {
            status =
                cryptSetAttributeString(new_cert, copied_attrs[i], dn_comp,
                                        dn_comp_len);
            if (!cryptStatusOK(status)) {
                cryptDestroyCert(old_cert);
                cryptDestroyCert(new_cert);
                free(dn_comp);
                return status;
            }
            free(dn_comp);
        }
    }
    /* copy attrs -- KU */
    status = cryptGetAttribute(old_cert, CRYPT_CERTINFO_KEYUSAGE, &ku);
    if (status == CRYPT_ERROR_NOTFOUND) {
        /* do nothing */
    }
    else if (cryptStatusOK(status)) {
        cryptSetAttribute(new_cert, CRYPT_CERTINFO_KEYUSAGE, ku);
    }
    else {
        cryptDestroyCert(old_cert);
        cryptDestroyCert(new_cert);
        return status;
    }
    /* copy attrs -- EKU */
    status = cryptGetAttribute(old_cert, CRYPT_CERTINFO_EXTKEYUSAGE, &unused);
    /* verify existence */
    if (cryptStatusOK(status)) {
        for (i = 0; copied_ekus[i] != 0; i++) {
            status = cryptGetAttribute(old_cert, copied_ekus[i], &unused);
            /* verify existence */
            if (cryptStatusOK(status)) {
                status =
                    cryptSetAttribute(new_cert, copied_ekus[i], CRYPT_UNUSED);
                if (!cryptStatusOK(status)) {
                    cryptDestroyCert(old_cert);
                    cryptDestroyCert(new_cert);
                    return status;
                }
            }
        }
    }
    /* copy attrs -- pubkey */
    status =
        cryptSetAttribute(new_cert, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
                          old_cert);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(old_cert);
        cryptDestroyCert(new_cert);
        return status;
    }
    /* t := now */
    now = time(NULL);
    /* tbs-cert.validity = t to t + valid_days */
    then = now + (valid_days * 86400);
    status =
        cryptSetAttributeString(new_cert, CRYPT_CERTINFO_VALIDFROM, &now,
                                sizeof(time_t));
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(old_cert);
        cryptDestroyCert(new_cert);
        return status;
    }
    status =
        cryptSetAttributeString(new_cert, CRYPT_CERTINFO_VALIDTO, &then,
                                sizeof(time_t));
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(old_cert);
        cryptDestroyCert(new_cert);
        return status;
    }
    /* sign tbs-cert */
    status = cryptSignCert(new_cert, signing_key);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(old_cert);
        cryptDestroyCert(new_cert);
        return status;
    }
    /* atomic begin */
    err = sqlite3_exec(pDB->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    LMZ_SQLITE_DIE(err);
    /*   revoke reason: superseded time: t */
    status =
        lmz_ca_revoke_cert_internal(pDB, cert_id, CRYPT_CRLREASON_SUPERSEDED,
                                    &now, signing_key);
    if (!cryptStatusOK(status)) {
        goto rollback;
    }
    /*   insert renewal request based on old request */
    /*     get request id for old cert */
    err =
        sqlite3_prepare(pDB->db,
                        "SELECT request_id FROM certificates WHERE id = ?", -1,
                        &stmt, &tail);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_bind_int(stmt, 1, cert_id);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(stmt);
    if (err == SQLITE_DONE) {
        status = CRYPT_ERROR_NOTFOUND;
        sqlite3_finalize(stmt);
        goto rollback;
    }
    else if (err == SQLITE_ROW) {
        oldreq_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    else {
        status = CRYPT_ERROR_READ;
        sqlite3_finalize(stmt);
        goto rollback;
    }
    /*     get request from request id */
    status = lmz_ca_get_request(pDB, oldreq_id, &oldreq, &oldreq_handled, NULL);
    if (!cryptStatusOK(status)) {
        goto rollback;
    }
    /*     reinsert as renewal and get renewal request id */
    status =
        lmz_ca_add_request_internal(pDB, LMZ_CA_REQUEST_RENEW, NULL, &now,
                                    oldreq, &newreq_id);
    cryptDestroyCert(oldreq);
    if (!cryptStatusOK(status)) {
        goto rollback;
    }
    /*   insert signed cert */
    status = lmz_ca_save_cert_internal(pDB, newreq_id, new_cert);
    if (!cryptStatusOK(status)) {
        goto rollback;
    }
    /* atomic end */
    err = sqlite3_exec(pDB->db, "COMMIT", NULL, NULL, NULL);
    LMZ_SQLITE_DIE(err);
    cryptDestroyCert(old_cert);
    cryptDestroyCert(new_cert);
    return CRYPT_OK;

  rollback:
    cryptDestroyCert(old_cert);
    cryptDestroyCert(new_cert);
    err = sqlite3_exec(pDB->db, "ROLLBACK", NULL, NULL, NULL);
    LMZ_SQLITE_DIE(err);
    return status;

}

LMZ_SQLITE_ERROR lmz_ca_create_web_db(PLMZ_CA_DB pDB,
                                      const char *webdb_filename) {
    sqlite3 *webdb;
    int err, status;
    const char *create_ddl =
        "    DROP TABLE IF EXISTS requests;"
        "    DROP TABLE IF EXISTS certificates;"
        "    CREATE TABLE certificates ("
        "      id INTEGER PRIMARY KEY, "
        "      C VARCHAR(2), SP VARCHAR(64), L VARCHAR(64),"
        "      O VARCHAR(64), OU VARCHAR(64), CN VARCHAR(64),"
        "      validTo INTEGER NOT NULL, cert_data BLOB NOT NULL"
        "    );"
        "    CREATE TABLE requests ("
        "      id INTEGER PRIMARY KEY, "
        "      name VARCHAR(50) NOT NULL,"
        "      email VARCHAR(50) NOT NULL,"
        "      phone VARCHAR(50),"
        "      notes VARCHAR(100),"
        "      request_data BLOB NOT NULL,"
        "      fingerprint BLOB NOT NULL"
        "    );"
        "    CREATE TABLE ca_data ("
        "      certificate BLOB, "
        "      _lock CHAR(1) PRIMARY KEY DEFAULT 'X' CHECK (_lock = 'X') "
        "    );"
        "    INSERT INTO ca_data (certificate, _lock) VALUES (NULL, 'X'); ";
    err = sqlite3_open(webdb_filename, &webdb);
    if (err) {
        return err;
    }
    err = sqlite3_exec(webdb, create_ddl, NULL, NULL, NULL);
    if (err) {
        sqlite3_close(webdb);
        return err;
    }
    err = sqlite3_close(webdb);
    if (err) {
        return err;
    }
    status = lmz_ca_sync_web_db(pDB, webdb_filename);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "sync: cl err %d\n", status);
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

LMZ_CL_ERROR lmz_ca_sync_web_db(PLMZ_CA_DB pDB, const char *webdb_filename) {
    const char *select_web_reqs_text =
        "SELECT web.id, web.request_data, "
        "'Name: ' || web.name || X'0A' || "
        "'Email: ' || web.email || X'0A' || "
        "COALESCE('Phone: ' || web.phone || X'0A', '') || "
        "COALESCE(web.notes, '') " "FROM webdb.requests AS web ";

    const char *insert_web_certs_text =
        "  INSERT INTO webdb.certificates (id, C, SP, L, O, OU, CN, validTo, cert_data) "
        "  SELECT cacerts.id, cacerts.C, cacerts.SP, cacerts.L, cacerts.O, "
        "  cacerts.OU, cacerts.CN, cacerts.validTo, cacerts.cert_data "
        "  FROM main.certificates AS cacerts " "  WHERE cacerts.issuer = ? ";

    const char *insert_accepted_id_text =
        " INSERT INTO temp.accepted (id) VALUES (?) ";

    const char *update_ca_cert_text =
        " UPDATE webdb.ca_data SET certificate = ?";

    sqlite3_stmt *insert_web_certs_stmt, *select_web_reqs_stmt,
        *insert_accepted_id_stmt, *update_ca_cert_stmt;
    const char *tail;
    int err, rv = CRYPT_OK, status;
    char *attach_cmd;
    int do_commit = 0;
    /* 
       DO IT LIKE THIS

       steps = 0;
       x = prepare(); if (err) goto cleanup; steps++;
       y = prepare(); if (err) goto cleanup; steps++;
       cleanup:
       if (steps > 1) unprepare(y);
       if (steps > 0) unprepare(x);
     */
    int steps = 0;
    /* attach db */
    attach_cmd =
        sqlite3_mprintf("ATTACH DATABASE '%q' AS webdb", webdb_filename);
    err = sqlite3_exec(pDB->db, attach_cmd, NULL, NULL, NULL);
    sqlite3_free(attach_cmd);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_READ;
        goto cleanup;
    }
    steps++;
    /* begin trans */
    err = sqlite3_exec(pDB->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    /* create temp accepted table */
    err =
        sqlite3_exec(pDB->db,
                     "CREATE TEMPORARY TABLE temp.accepted (id integer)", NULL,
                     NULL, NULL);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    /* exec select web reqs */
    /* > prepare select web reqs */
    err =
        sqlite3_prepare(pDB->db, select_web_reqs_text, -1,
                        &select_web_reqs_stmt, &tail);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_READ;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    /* > prepare insert accepted id */
    err =
        sqlite3_prepare(pDB->db, insert_accepted_id_text, -1,
                        &insert_accepted_id_stmt, &tail);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_READ;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    while ((err = sqlite3_step(select_web_reqs_stmt)) == SQLITE_ROW) {
        CRYPT_CERTIFICATE request;
        int inserted_id;
        /* insert row into cadb reqs */
        /* > make CRYPT_CERTIFICATE from DER request data */
        status = cryptImportCert(sqlite3_column_blob(select_web_reqs_stmt, 1),
                                 sqlite3_column_bytes(select_web_reqs_stmt, 1),
                                 CRYPT_UNUSED, &request);
        if (status != CRYPT_OK) {
            rv = CRYPT_ERROR_READ;
            fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
            goto cleanup;
        }
        status =
            lmz_ca_add_request_internal(pDB, LMZ_CA_REQUEST_CSR,
                                        sqlite3_column_text
                                        (select_web_reqs_stmt, 2), NULL,
                                        request, &inserted_id);
        /* handle DUPLICATE & OK */
        if (status == CRYPT_OK) {
            /* if accepted: insert row into accepted */
            err =
                sqlite3_bind_int(insert_accepted_id_stmt, 1,
                                 sqlite3_column_int(select_web_reqs_stmt, 0));
            LMZ_SQLITE_DIE(err);
            err = sqlite3_step(insert_accepted_id_stmt);
            if (err != SQLITE_DONE) {
                cryptDestroyCert(request);
                rv = CRYPT_ERROR_WRITE;
                fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
                goto cleanup;
            }
            err = sqlite3_reset(insert_accepted_id_stmt);
            LMZ_SQLITE_DIE(err);
        }
        else if (status == CRYPT_ERROR_DUPLICATE) {
            /* not accepted, do nothing and don't insert into accepted */
        }
        else {
            /* unknown error, cleanup */
            cryptDestroyCert(request);
            goto cleanup;
        }
        cryptDestroyCert(request);
    }
    if (err != SQLITE_DONE) {
        rv = CRYPT_ERROR_READ;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    /* delete web reqs where id in accepted */
    err =
        sqlite3_exec(pDB->db,
                     "DELETE FROM webdb.requests WHERE webdb.requests.id IN (SELECT id FROM temp.accepted)",
                     NULL, NULL, NULL);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    /* delete web certs */
    err =
        sqlite3_exec(pDB->db, "DELETE FROM webdb.certificates", NULL, NULL,
                     NULL);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    /* exec insert into web certs select from cadb certs */
    /* > prepare stmt */
    err =
        sqlite3_prepare(pDB->db, insert_web_certs_text, -1,
                        &insert_web_certs_stmt, &tail);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_READ;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    err =
        sqlite3_bind_text(insert_web_certs_stmt, 1, pDB->ca_name, -1,
                          SQLITE_TRANSIENT);
    LMZ_SQLITE_DIE(err);
    err = sqlite3_step(insert_web_certs_stmt);
    if (err != SQLITE_DONE) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    err =
        sqlite3_prepare(pDB->db, update_ca_cert_text, -1, &update_ca_cert_stmt,
                        &tail);
    if (err != SQLITE_OK) {
        rv = CRYPT_ERROR_READ;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }
    steps++;
    status = lmz_bind_cert(update_ca_cert_stmt, 1, pDB->ca_cert, &err);
    if (cryptStatusError(status)) {
        if (status == CRYPT_ERROR_PARAM1) {
            fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        }
        else {
            fprintf(stderr, "(%s:%d) status: %d\n", __FILE__, __LINE__, status);
        }
        rv = CRYPT_ERROR_READ;
        goto cleanup;
    }
    err = sqlite3_step(update_ca_cert_stmt);
    if (err != SQLITE_DONE) {
        rv = CRYPT_ERROR_WRITE;
        fprintf(stderr, "(%s:%d) err: %d\n", __FILE__, __LINE__, err);
        goto cleanup;
    }

    do_commit = 1;
  cleanup:
    if (steps > 6) {
        err = sqlite3_finalize(update_ca_cert_stmt);
    }
    if (steps > 5) {
        err = sqlite3_finalize(insert_web_certs_stmt);
        /* LMZ_SQLITE_DIE(err); */
    }
    if (steps > 4) {
        err = sqlite3_finalize(insert_accepted_id_stmt);
        /* LMZ_SQLITE_DIE(err); */
    }
    if (steps > 3) {
        err = sqlite3_finalize(select_web_reqs_stmt);
        /* LMZ_SQLITE_DIE(err); */
    }
    if (steps > 2) {
        err =
            sqlite3_exec(pDB->db, "DROP TABLE temp.accepted", NULL, NULL, NULL);
        LMZ_SQLITE_DIE(err);
    }
    if (steps > 1) {
        err =
            sqlite3_exec(pDB->db, do_commit ? "COMMIT" : "ROLLBACK", NULL, NULL,
                         NULL);
        LMZ_SQLITE_DIE(err);
    }
    if (steps > 0) {
        err = sqlite3_exec(pDB->db, "DETACH DATABASE webdb", NULL, NULL, NULL);
        LMZ_SQLITE_DIE(err);
    }
    return rv;
}

/* vim: set sw=4 et: */
