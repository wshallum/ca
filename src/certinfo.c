/* Print attributes of certificates & requests.
 */
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cryptlib.h"
#include "cadb.h"
#include "certinfo.h"
/* unknown numeric printable binary groupname exists/not GeneralName Time */
#define U 0
#define N 1
#define P 2
#define B 3
#define G 4
#define E 5
#define GN 6
#define T 7


struct attr_desc {
    CRYPT_ATTRIBUTE_TYPE attr;
    const char *name;
    int type;
};
struct attr_desc attr_descs[] = {
    /* just the general types (not extensions) */
    {CRYPT_CERTINFO_SERIALNUMBER, "Serial Number", B},
    {CRYPT_CERTINFO_COUNTRYNAME, "Country", P},
    {CRYPT_CERTINFO_STATEORPROVINCENAME, "State/Province", P},
    {CRYPT_CERTINFO_LOCALITYNAME, "Locality", P},
    {CRYPT_CERTINFO_ORGANIZATIONNAME, "Organization", P},
    {CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, "Organizational Unit", P},
    {CRYPT_CERTINFO_COMMONNAME, "Common Name", P},
    {CRYPT_CERTINFO_EMAIL, "Email", P},
    {CRYPT_CERTINFO_VALIDFROM, "Valid From", T},
    {CRYPT_CERTINFO_VALIDTO, "Valid To", T},
    /* these are ordered as per the cryptlib manual pdf p.302 */
    {CRYPT_CERTINFO_ISSUERALTNAME, "Issuer altName", GN},
    {CRYPT_CERTINFO_SUBJECTALTNAME, "Subject altName", GN},

    {CRYPT_CERTINFO_BASICCONSTRAINTS, "Basic Constraints", G},
    {CRYPT_CERTINFO_CA, "CA", N},
    {CRYPT_CERTINFO_PATHLENCONSTRAINT, "Path Length Constraint", N},

    {CRYPT_CERTINFO_CERTIFICATEPOLICIES, "Certificate Policy", G},
    {CRYPT_CERTINFO_CERTPOLICYID, "OID of Policy", P},
    {CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, "CERTPOLICY_ORGANIZATION", P},
    {CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS, "CERTPOLICY_NOTICENUMBERS", N},
    {CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, "CERTPOLICY_EXPLICITTEXT", P},
    {CRYPT_CERTINFO_CERTPOLICY_CPSURI, "CPS URI", P},

    {CRYPT_CERTINFO_POLICYMAPPINGS, "Policy Mappings", G},
    {CRYPT_CERTINFO_ISSUERDOMAINPOLICY, "Source (Issuer) Policy OID", P},
    {CRYPT_CERTINFO_SUBJECTDOMAINPOLICY, "Dest. (Subject) Policy OID", P},

    {CRYPT_CERTINFO_POLICYCONSTRAINTS, "Policy Constraints", G},
    {CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, "CERTINFO_REQUIREEXPLICITPOLICY", N},
    {CRYPT_CERTINFO_INHIBITPOLICYMAPPING, "CERTINFO_INHIBITPOLICYMAPPING", N},

    {CRYPT_CERTINFO_INHIBITANYPOLICY, "Inhibit anyPolicy", N},

    /* CRL distribution point, freshest CRL -- RFC3280 sec 4.2.1.14 */
    {CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT, "CRL Distribution Point", G},
    {CRYPT_CERTINFO_CRLDIST_FULLNAME, "CRL Location", GN},
    {CRYPT_CERTINFO_CRLDIST_REASONS, "CRL Distribution Reason", N},
    {CRYPT_CERTINFO_CRLDIST_CRLISSUER, "CRL Issuer", GN},

    {CRYPT_CERTINFO_FRESHESTCRL, "Freshest CRL Distribution Point", G},
    {CRYPT_CERTINFO_FRESHESTCRL_FULLNAME, "CRL Location", GN},
    {CRYPT_CERTINFO_FRESHESTCRL_REASONS, "CRL Distribution Reason", N},
    {CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER, "CRL Issuer", GN},

    /* subject info access -- RFC3280 sec 4.2.2.2 */
    {CRYPT_CERTINFO_SUBJECTINFOACCESS, "Subject Information Access", G},
    {CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY, "CA Repository Location", GN},
    {CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING, "Location of TSP Services", GN},

    /* authority info access */
    {CRYPT_CERTINFO_AUTHORITYINFOACCESS, "Authority Information Access", G},
    {CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
     "Location of Superior CA Information", GN},
    {CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE, "CA Certificates Location", GN},
    {CRYPT_CERTINFO_AUTHORITYINFO_CRLS, "CA CRLs Location", GN},
    {CRYPT_CERTINFO_AUTHORITYINFO_OCSP, "CA OCSP Location", GN},
    {CRYPT_CERTINFO_AUTHORITYINFO_RTCS, "CA RTCS Location", GN},

    /* directory attributes */
    {CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES, "Subject Directory Attributes",
     G},
    {CRYPT_CERTINFO_SUBJECTDIR_TYPE, "Directory Attribute OID", P},
    {CRYPT_CERTINFO_SUBJECTDIR_VALUES, "Directory Attribute Value", P},

    /* Key Usage */
    {CRYPT_CERTINFO_KEYUSAGE, "Key Usage", N},

    /* Extended Key Usage and its many, many extension members -- RFC3280 sec 4.2.1.13 */
    {CRYPT_CERTINFO_EXTKEYUSAGE, "Extended Key Usage", G},
    {CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE, "Any key usage", E},
    {CRYPT_CERTINFO_EXTKEY_SERVERAUTH, "TLS WWW server authentication", E},
    {CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, "TLS WWW client authentication", E},
    {CRYPT_CERTINFO_EXTKEY_CODESIGNING,
     "Signing of downloadable executable code", E},
    {CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION, "E-mail protection", E},
    {CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
     "Binding the hash of an object to a time (Timestamping)", E},
    {CRYPT_CERTINFO_EXTKEY_OCSPSIGNING, "Signing OCSP responses", E},
    {CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE, "Directory service", E},
    {CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM, "ipsecEndSystem", E},
    {CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL, "ipsecTunnel", E},
    {CRYPT_CERTINFO_EXTKEY_IPSECUSER, "ipsecUser", E},
    {CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING, "MS individualCodeSigning",
     E},
    {CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING, "MS commercialCodeSigning",
     E},
    {CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
     "MS Cert Trust List signing ", E},
    {CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING, "MS timestamp signing", E},
    {CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO, "MS serverGatedCrypto ", E},
    {CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM, "MS encryptedFileSystem", E},
    {CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO, "Netscape serverGatedCrypto ",
     E},
    {CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
     "Verisign serverGatedCrypto CA ", E},

    /* Netscape cert. type -- bit field */
    {CRYPT_CERTINFO_NS_CERTTYPE, "Netscape Cert. Type", N},

    /* name constraints */
    {CRYPT_CERTINFO_NAMECONSTRAINTS, "Name Constraints", G},
    {CRYPT_CERTINFO_PERMITTEDSUBTREES, "Permitted Subtrees", GN},
    {CRYPT_CERTINFO_EXCLUDEDSUBTREES, "Excluded Subtrees", GN},

    /* private key usage period */
    {CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD, "Private Key Usage Period", G},
    {CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, "Priv. Key Not Before", T},
    {CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER, "Priv. Key Not After", T},

    /* authority key identifier */
    {CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER, "Authority Key Identifier", G},
    {CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
     "Authority Key Identifier (public key id)", B},
    {CRYPT_CERTINFO_AUTHORITY_CERTISSUER, "Signing Cert's Issuer", GN},
    {CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER, "Signing Cert's Serial Number",
     B},

    /* subject key identifier */
    {CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, "Subject Key Identifier", B},

    /* Netscape extensions */
    {CRYPT_CERTINFO_NS_BASEURL, "Netscape Base URL", P},
    {CRYPT_CERTINFO_NS_CAPOLICYURL, "Netscape CA Policy URL", P},
    {CRYPT_CERTINFO_NS_CAREVOCATIONURL,
     "Netscape CA Cert Revocation Status URL", P},
    {CRYPT_CERTINFO_NS_COMMENT, "Netscape Cert Comment", P},
    {CRYPT_CERTINFO_NS_REVOCATIONURL,
     "Netscape Server Cert Revocation Status URL", P},
    {CRYPT_CERTINFO_NS_SSLSERVERNAME, "Netscape SSL Server Name", P},
    {0, NULL, 0}
};

#undef U
#undef N
#undef P
#undef B
#undef B
#undef G

/*
handle cryptlib certinfo attributes

for a given attribute type, give:
- the friendly name
- the type (numeric/printable string/binary string/group)
*/

int lmz_certinfo_get_description(CRYPT_ATTRIBUTE_TYPE attr, const char **pName,
                                 int *pType) {
    struct attr_desc *pDesc;
    pDesc = attr_descs;
    while (pDesc->attr != 0) {
        if (pDesc->attr == attr) {
            *pName = pDesc->name;
            *pType = pDesc->type;
            return 1;
        }
        pDesc++;
    }
    *pName = NULL;
    *pType = 0;
    return 0;
}

#define READ_FAIL_IF(status, msg) do { if (!cryptStatusOK(status)) { fprintf(stderr, "(%s:%d) Cryptlib error %d : %s\n", __FILE__, __LINE__, status, msg); return;  } } while (0)

void lmz_certinfo_enum_simple_cert_attributes(CRYPT_CERTIFICATE cert,
                                              void (*callback) (int /* attr */ ,
                                                                int
                                                                /* attr_type */
                                                                , void *
                                                                /* data */ ,
                                                                int
                                                                /* data_len */ ,
                                                                void *
                                                                /* user_data */
                                              ), void *user_data) {
    int status;
    int int_attr;
    int field;
    void *str_attr;
    int str_attr_len;
    int is_request;

    status = cryptGetAttribute(cert, CRYPT_CERTINFO_CERTTYPE, &int_attr);
    is_request = (int_attr == CRYPT_CERTTYPE_CERTREQUEST);

    /* serial number */
    if (!is_request) {
        str_attr =
            lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_SERIALNUMBER,
                                        &str_attr_len);
        if (str_attr) {
            (*callback) (CRYPT_CERTINFO_SERIALNUMBER, LMZ_ATTR_TYPE_BINARY,
                         str_attr, str_attr_len, user_data);
            free(str_attr);
            str_attr = NULL;
        }
    }
    /* select subject DN and just print the string form */
    status =
        cryptSetAttribute(cert, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CERTINFO_SUBJECTNAME);
    READ_FAIL_IF(status, "while selecting cert subject name");
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_COUNTRYNAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_COUNTRYNAME, LMZ_ATTR_TYPE_PRINTABLE,
                     str_attr, str_attr_len, user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_STATEORPROVINCENAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_STATEORPROVINCENAME,
                     LMZ_ATTR_TYPE_PRINTABLE, str_attr, str_attr_len,
                     user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_LOCALITYNAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_LOCALITYNAME, LMZ_ATTR_TYPE_PRINTABLE,
                     str_attr, str_attr_len, user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_ORGANIZATIONNAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_ORGANIZATIONNAME, LMZ_ATTR_TYPE_PRINTABLE,
                     str_attr, str_attr_len, user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
                     LMZ_ATTR_TYPE_PRINTABLE, str_attr, str_attr_len,
                     user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_COMMONNAME,
                                    &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_COMMONNAME, LMZ_ATTR_TYPE_PRINTABLE,
                     str_attr, str_attr_len, user_data);
        free(str_attr);
        str_attr = NULL;
    }
    str_attr =
        lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_EMAIL, &str_attr_len);
    if (str_attr) {
        (*callback) (CRYPT_CERTINFO_EMAIL, LMZ_ATTR_TYPE_PRINTABLE, str_attr,
                     str_attr_len, user_data);
        free(str_attr);
        str_attr = NULL;
    }
    if (!is_request) {
        str_attr =
            lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_VALIDFROM,
                                        &str_attr_len);
        if (str_attr) {
            (*callback) (CRYPT_CERTINFO_VALIDFROM, LMZ_ATTR_TYPE_TIME, str_attr,
                         str_attr_len, user_data);
            free(str_attr);
            str_attr = NULL;
        }
        str_attr =
            lmz_cl_get_attribute_string(cert, CRYPT_CERTINFO_VALIDTO,
                                        &str_attr_len);
        if (str_attr) {
            (*callback) (CRYPT_CERTINFO_VALIDTO, LMZ_ATTR_TYPE_TIME, str_attr,
                         str_attr_len, user_data);
            free(str_attr);
            str_attr = NULL;
        }
        status = cryptGetAttribute(cert, CRYPT_CERTINFO_VERSION, &int_attr);
    }
    if (is_request || (int_attr >= 3)) {        
        /* request or cert (the above version check has happened and we can use the value */
        /* basicConstraints */
        status =
            cryptGetAttribute(cert, CRYPT_CERTINFO_BASICCONSTRAINTS, &int_attr);
        if (cryptStatusOK(status)) {
            int_attr = 1;
            (*callback) (CRYPT_CERTINFO_BASICCONSTRAINTS,
                         LMZ_ATTR_TYPE_EXISTENCE, &int_attr, 0, user_data);
            status = cryptGetAttribute(cert, CRYPT_CERTINFO_CA, &int_attr);
            if (cryptStatusOK(status)) {
                (*callback) (CRYPT_CERTINFO_CA, LMZ_ATTR_TYPE_NUMERIC,
                             &int_attr, 0, user_data);
            }
            status =
                cryptGetAttribute(cert, CRYPT_CERTINFO_PATHLENCONSTRAINT,
                                  &int_attr);
            if (cryptStatusOK(status)) {
                (*callback) (CRYPT_CERTINFO_PATHLENCONSTRAINT,
                             LMZ_ATTR_TYPE_NUMERIC, &int_attr, 0, user_data);
            }
            int_attr = 0;
            (*callback) (CRYPT_CERTINFO_BASICCONSTRAINTS,
                         LMZ_ATTR_TYPE_EXISTENCE, &int_attr, 0, user_data);
        }

        /* keyUsage */
        status = cryptGetAttribute(cert, CRYPT_CERTINFO_KEYUSAGE, &int_attr);
        if (cryptStatusOK(status)) {
            (*callback) (CRYPT_CERTINFO_KEYUSAGE, LMZ_ATTR_TYPE_NUMERIC,
                         &int_attr, 0, user_data);
        }

        /* extKeyUsage */
        status = cryptGetAttribute(cert, CRYPT_CERTINFO_EXTKEYUSAGE, &int_attr);
        if (cryptStatusOK(status)) {
            int_attr = 1;
            (*callback) (CRYPT_CERTINFO_EXTKEYUSAGE, LMZ_ATTR_TYPE_EXISTENCE,
                         &int_attr, 0, user_data);

            if (cryptSetAttribute
                (cert, CRYPT_ATTRIBUTE_CURRENT_GROUP,
                 CRYPT_CERTINFO_EXTKEYUSAGE) == CRYPT_OK) {
                do {
                    /* Get the ID of the extension attribute under the cursor */
                    cryptGetAttribute(cert, CRYPT_ATTRIBUTE_CURRENT, &field);
                    int_attr = 1;
                    (*callback) (field, LMZ_ATTR_TYPE_EXISTENCE, &int_attr, 0,
                                 user_data);
                } while (cryptSetAttribute
                         (cert, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CURSOR_NEXT) == CRYPT_OK);
            }
            int_attr = 0;
            (*callback) (CRYPT_CERTINFO_EXTKEYUSAGE, LMZ_ATTR_TYPE_EXISTENCE,
                         &int_attr, 0, user_data);
        }

    }
}
/* vim: set sw=4 et: */
