#ifndef LMZ_CERTINFO_H_DEFINED
#define LMZ_CERTINFO_H_DEFINED

#include "cryptlib.h"
#define LMZ_ATTR_TYPE_UNKNOWN 0
#define LMZ_ATTR_TYPE_NUMERIC 1
#define LMZ_ATTR_TYPE_PRINTABLE 2
#define LMZ_ATTR_TYPE_BINARY 3
#define LMZ_ATTR_TYPE_GROUP 4
#define LMZ_ATTR_TYPE_EXISTENCE 5
#define LMZ_ATTR_TYPE_GENERALNAME 6
#define LMZ_ATTR_TYPE_TIME 7
#define LMZ_ATTR_TYPE_BOOLEAN 8
int lmz_certinfo_get_description(CRYPT_ATTRIBUTE_TYPE attr, const char **pName, int *pType);
void lmz_certinfo_enum_simple_cert_attributes(
  CRYPT_CERTIFICATE cert,
  void (*callback)(int /* attr */, int /* attr_type */, void* /* data */, int /* data_len */, void* /* user_data */),
  void *user_data
);
#endif
