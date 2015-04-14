/*
 * Used for dumping the ASN.1 structure into a GtkTreeView.
 *
 * Don't remember now (2015) how much of this was inspired by asn1dump.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#include "cadb.h"
#include "frontend.h"


static int asc_is_print(unsigned char c) {
    return (c >= 32) && (c <= 126);
}

#define DEC_OK 0
#define DEC_TOOLONG 1
#define DEC_EOF 2
#define DEC_INDEF_LENGTH 3
#define DEC_UNKNOWN 4

typedef int DEC_ERROR;

typedef struct {
    const unsigned char *start;
    const unsigned char *end;
    const unsigned char *cur;
} buf_t;

#define RET_E(x) do { int dec_error_ = (x); if (dec_error_ != DEC_OK) return dec_error_; } while (0)

static uint8_t get_byte(buf_t * buf) {
    return *(buf->cur);
}

static DEC_ERROR advance(buf_t * buf, size_t n) {
    buf->cur += n;
    if (buf->cur > buf->end) {
        return DEC_EOF;
    }
    return DEC_OK;
}


static DEC_ERROR get_len(buf_t * buf, uint32_t * ret_len) {     /* pointing at length, moves ptr */
    uint8_t first_octet;
    uint32_t retval;
    retval = 0;
    first_octet = get_byte(buf);
    RET_E(advance(buf, 1));
    if (first_octet & 0x80) {
        int i;
        uint8_t num_octets = first_octet & 0x7f;
        if (num_octets > 4) {
            return DEC_TOOLONG;
        }
        else if (num_octets == 0) {     /* indefinite length encoding -- X.690 8.1.3.6 */
            return DEC_INDEF_LENGTH;
        }
        for (i = 0; i < num_octets; i++) {
            retval = (retval << 8) | get_byte(buf);
            RET_E(advance(buf, 1));
        }
        *ret_len = retval;
    }
    else {
        *ret_len = first_octet;
    }
    return DEC_OK;
}

#if 0
static DEC_ERROR skip(buf_t * buf) {    /* pointing at length */
    uint32_t len;
    RET_E(get_len(buf, &len));
    RET_E(advance(buf, len));
    return DEC_OK;
}
#endif


enum {
    TAG_COLUMN,
    LENGTH_COLUMN,
    CONTENTS_COLUMN,
    N_COLUMNS
};

#define N_TESTS 9
const struct {
    const char *data;
    int len;
} test_encodings[N_TESTS] = {
    {
    "\x01\x01\xFF", 3},         /* BOOLEAN TRUE */
    {
    "\x01\x01\x00", 3},         /* BOOLEAN FALSE */
    {
    "\x05\x00", 2},             /* NULL */
    {
    "\x04\x03\x01\x02\x03", 5}, /* PRIMITIVE OCTET STRING 01 02 03 */
    {
    "\x24\x03\x01\x02\x03", 5}, /* CONSTRUCTED OCTET STRING 01 02 03 */
    {
    "\x30\x05\x01\x01\xFF\x05\x00", 7}, /* SEQUENCE { TRUE, NULL } */
    {
    "\x30\x0A\x01\x01\xFF\x30\x05\x01\x01\xFF\x05\x00", 12},    /* SEQUENCE { TRUE, SEQUENCE { TRUE, NULL } } */
    {
    "\xC0\x03\x01\x02\x03", 6}, /* PRIVATE PRIMITIVE 0 (3 bytes) */
    {
    "\x06\x03\x81\x34\x03", 6}  /* OBJECT IDENTIFIER 2 100 3 */
};

static void add_error_entry(GtkTreeStore * store, GtkTreeIter * parent,
                            const char *format, ...) {
    GtkTreeIter new_row;
    gchar *errmsg;
    va_list args;
    va_start(args, format);
    g_vasprintf(&errmsg, format, args);
    va_end(args);
    gtk_tree_store_append(store, &new_row, parent);
    gtk_tree_store_set(store, &new_row,
                       TAG_COLUMN, "ERROR",
                       LENGTH_COLUMN, 0, CONTENTS_COLUMN, errmsg, -1);
    g_free(errmsg);
}

static void add_entry(GtkTreeStore * store, GtkTreeIter * parent,
                      const char *tag, uint32_t len, const char *contents) {
    GtkTreeIter new_row;
    gtk_tree_store_append(store, &new_row, parent);
    gtk_tree_store_set(store, &new_row,
                       TAG_COLUMN, tag,
                       LENGTH_COLUMN, len, CONTENTS_COLUMN, contents, -1);
}

static void add_entry_fmt(GtkTreeStore * store, GtkTreeIter * parent,
                          const char *tag, uint32_t len, const char *format,
                          ...) {
    GtkTreeIter new_row;
    va_list args;
    gchar *contents;
    va_start(args, format);
    g_vasprintf(&contents, format, args);
    va_end(args);
    gtk_tree_store_append(store, &new_row, parent);
    gtk_tree_store_set(store, &new_row,
                       TAG_COLUMN, tag,
                       LENGTH_COLUMN, len, CONTENTS_COLUMN, contents, -1);
    g_free(contents);
}

static int try_decode(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent);


static void decode_bool(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {
    DEC_ERROR e;
    uint32_t len;
    uint8_t b;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    if (len != 1) {
        add_error_entry(store, parent, "boolean len > 1 (is %d)", len);
        return;
    }
    b = get_byte(buf);
    if (b) {
        add_entry(store, parent, "BOOLEAN", len, "TRUE");
    }
    else {
        add_entry(store, parent, "BOOLEAN", len, "FALSE");
    }
    advance(buf, len);
}

static void decode_null(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {
    DEC_ERROR e;
    uint32_t len;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    if (len != 0) {
        add_error_entry(store, parent, "null len > 0 (is %d)", len);
        return;
    }
    add_entry(store, parent, "NULL", 0, "NULL");
    return;
}

static void decode_unknown(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {   /* {{{ */
    int tag_class;
    int constructed_p;
    int num_tag_bytes;
    uint32_t tag_num, len;
    DEC_ERROR e;
    gchar *tag_str = NULL;
    const char *constructed_str, *class_str;
    buf_t limbuf;
    /* 
       handle the tag {{{ 
     */
    /* get class */
    tag_class = get_byte(buf) & 0xC0;
    constructed_p = get_byte(buf) & 0x20;
    tag_num = get_byte(buf) & 0x1F;
    num_tag_bytes = 0;
    if (tag_num == 0x1F) {      /* long tag number */
        uint8_t b;
        tag_num = 0;
        do {
            e = advance(buf, 1);
            if (e != DEC_OK) {
                add_error_entry(store, parent, "decode error %d", e);
                return;
            }
            b = get_byte(buf);
            tag_num = (tag_num << 7) | (b & 0x7F);
            num_tag_bytes++;
        } while (b & 0x80);
    }
    /* skip last tag byte / only tag byte for short tag */
    e = advance(buf, 1);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }

    constructed_str = constructed_p ? "CONSTRUCTED" : "PRIMITIVE";
    if (tag_class == 0x00) {
        class_str = "UNIVERSAL";
    }
    else if (tag_class == 0x40) {
        class_str = "APPLICATION";
    }
    else if (tag_class == 0x80) {
        class_str = "CONTEXT SPECIFIC";
    }
    else if (tag_class == 0xC0) {
        class_str = "PRIVATE";
    }
    else {
        /* should not happen */
        class_str = "UNKNOWN";
    }

    if (num_tag_bytes > 4) {
        tag_str = g_strdup_printf("[%s %s <<long -- %d octets>>]", class_str,
                constructed_str, num_tag_bytes);
    }
    else {
        tag_str = g_strdup_printf("[%s %s %d]", class_str, constructed_str, tag_num);
    }
    /*
       }}} end tag handling
     */
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        if (tag_str) {
            g_free(tag_str);
            tag_str = NULL;
        }
        return;
    }
    /* try decoding it */
    {
        GtkTreeIter new_row;
        gtk_tree_store_append(store, &new_row, parent);
        gtk_tree_store_set(store, &new_row,
                           TAG_COLUMN, tag_str,
                           LENGTH_COLUMN, len, CONTENTS_COLUMN, "UNKNOWN", -1);
        if (tag_str) {
            g_free(tag_str);
            tag_str = NULL;
        }
        limbuf.cur = buf->cur;
        limbuf.start = buf->cur;
        limbuf.end = buf->cur + len;
        try_decode(&limbuf, store, &new_row);
    }
    advance(buf, len);
}                               /* }}} */

static void decode_utf8(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {      /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    char *str;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    str = malloc(len + 1);
    memcpy(str, buf->cur, len);
    str[len] = '\0';
    add_entry(store, parent, "UTF8String", len, str);   /* GTK+ uses UTF8 internally */
    free(str);
    advance(buf, len);
}                               /* }}} */

static void decode_asc(buf_t * buf, const char *tag, GtkTreeStore * store, GtkTreeIter * parent) {      /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    GString *str;
    int i;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    str = g_string_sized_new(len);
    for (i = 0; i < len; i++) {
        unsigned char c = buf->cur[i];
        if (c == '\\') {
            g_string_append(str, "\\\\");
        }
        else if (asc_is_print(c)) {
            g_string_append_c(str, c);
        }
        else {
            g_string_append_printf(str, "\\%.2x", (int) c);
        }
    }
    add_entry(store, parent, tag, len, str->str);
    g_string_free(str, TRUE);
    advance(buf, len);
}                               /* }}} */

static void decode_arb(buf_t * buf, const char *tag, int descend, GtkTreeStore * store, GtkTreeIter * parent) { /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    int dec_len;
    GString *str;
    int i;
    buf_t limbuf;

    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    dec_len = (len < 16) ? len : 16;
    str = g_string_sized_new(dec_len * 3);
    for (i = 0; i < dec_len; i++) {
        unsigned char c = buf->cur[i];
        g_string_append_printf(str, "%.2x ", (int) c);
    }
    if (dec_len < len) {
        g_string_append(str, " [...]");
    }
    {
        GtkTreeIter new_row;
        gtk_tree_store_append(store, &new_row, parent);
        gtk_tree_store_set(store, &new_row,
                           TAG_COLUMN, tag,
                           LENGTH_COLUMN, len, CONTENTS_COLUMN, str->str, -1);

        if (descend) {
            limbuf.cur = buf->cur;
            limbuf.start = buf->cur;
            limbuf.end = buf->cur + len;
            try_decode(&limbuf, store, &new_row);
        }
    }
    g_string_free(str, TRUE);
    advance(buf, len);
}                               /* }}} */

static void decode_oid(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {       /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    GString *str;
    uint32_t cur_oid_comp;
    int num_oid_comp_bytes;
    int first_oid_comp;
    const unsigned char *end;

    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    str = g_string_sized_new(16);
    end = buf->cur + len;
    first_oid_comp = 1;
    do {
        uint8_t b;
        cur_oid_comp = 0;
        num_oid_comp_bytes = 0;
        do {
            if (e != DEC_OK) {
                add_error_entry(store, parent, "decode error %d", e);
                return;
            }
            b = get_byte(buf);
            cur_oid_comp = (cur_oid_comp << 7) | (b & 0x7F);
            num_oid_comp_bytes++;
            e = advance(buf, 1);
        } while (b & 0x80);
        if (num_oid_comp_bytes > 4) {
            g_string_append_printf(str, "<too large>.");
        }
        else {
            if (first_oid_comp) {
                uint8_t smallval = cur_oid_comp % 40;
                if (cur_oid_comp < 40) {
                    g_string_append_printf(str, "0.%d.", smallval);
                }
                else if (cur_oid_comp < 80) {
                    g_string_append_printf(str, "1.%d.", smallval);
                }
                else {
                    g_string_append_printf(str, "2.%d.", cur_oid_comp - 80);
                }
            }
            else {
                g_string_append_printf(str, "%d.", cur_oid_comp);
            }
        }
        first_oid_comp = 0;
    } while (buf->cur < end);
    add_entry(store, parent, "OBJECT IDENTIFIER", len, str->str);
    g_string_free(str, TRUE);
    buf->cur = end;
}                               /* }}} */

static void decode_utctime(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {   /* {{{ */
    /* 
       UTCTime -> YYMMDD(hhmm|hhmmss)(Z|[+-]hhmm)
       base: 6
       additional:
       hhmmZ -> 5
       hhmm[+-]hhmm -> 9
       hhmmssZ -> 7
       hhmmss[+-]hhmm -> 11
     */
    DEC_ERROR e;
    uint32_t len;
    const unsigned char *end;
    char tmp[16];
    int yy, mon, dd, hh, mm, ss, ofshh, ofsmm;
    char sign;

    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    if ((len != 11) && (len != 15) && (len != 13) && (len != 17)) {
        add_error_entry(store, parent,
                        "UTCTime bad length (%d is not 11, 13, 15, or 17)",
                        len);
        return;
    }
    end = buf->cur + len;
    /* get the 6 char YYMMDD first */
    memcpy(tmp, buf->cur, 2);
    advance(buf, 2);
    tmp[3] = '\0';
    /* 
       X.509 p.12 -> 
       YY is 00..49 -> 2000 + YY
       YY is 50..99 -> 1900 + YY
     */
    yy = atoi(tmp);
    if (yy < 50)
        yy += 2000;
    else
        yy += 1900;
    memcpy(tmp, buf->cur, 2);
    advance(buf, 2);
    tmp[3] = '\0';
    mon = atoi(tmp);
    memcpy(tmp, buf->cur, 2);
    advance(buf, 2);
    tmp[3] = '\0';
    dd = atoi(tmp);

    if (len == 11) {            /* hhmmZ */
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        hh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        mm = atoi(tmp);
        add_entry_fmt(store, parent, "UTCTime", len,
                      "%.4d-%.2d-%.2d %.2d:%.2d UTC", yy, mon, dd, hh, mm);
    }
    else if (len == 13) {       /* hhmmssZ */
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        hh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        mm = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ss = atoi(tmp);
        add_entry_fmt(store, parent, "UTCTime", len,
                      "%.4d-%.2d-%.2d %.2d:%.2d:%.2d UTC", yy, mon, dd, hh, mm,
                      ss);
    }
    else if (len == 15) {       /* hhmm[+-]hhmm */
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        hh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        mm = atoi(tmp);
        sign = *(buf->cur);
        advance(buf, 1);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ofshh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ofsmm = atoi(tmp);
        add_entry_fmt(store, parent, "UTCTime", len,
                      "%.4d-%.2d-%.2d %.2d:%.2d %c%.2d:%.2d", yy, mon, dd, hh,
                      mm, sign, ofshh, ofsmm);
    }
    else if (len == 17) {
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        hh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        mm = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ss = atoi(tmp);
        sign = *(buf->cur);
        advance(buf, 1);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ofshh = atoi(tmp);
        memcpy(tmp, buf->cur, 2);
        advance(buf, 2);
        tmp[3] = '\0';
        ofsmm = atoi(tmp);
        add_entry_fmt(store, parent, "UTCTime", len,
                      "%.4d-%.2d-%.2d %.2d:%.2d:%.2d %c%.2d:%.2d", yy, mon, dd,
                      hh, mm, ss, sign, ofshh, ofsmm);
    }
    buf->cur = end;

}                               /* }}} */

static void decode_seq(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent);
static void decode_set(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent);


static int decode_internal(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {   /* {{{ */
    uint8_t tag;
    tag = get_byte(buf);
    if (tag == 0x01) {          /* UNIVERSAL PRIMITIVE 1 -- boolean */
        decode_bool(buf, store, parent);
    }
    else if (tag == 0x02) {     /* UNIVERSAL PRIMITIVE 2 -- integer */
        decode_arb(buf, "INTEGER", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x23) {    /* UNIVERSAL 3 -- bit string */
        decode_arb(buf, "BIT STRING", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x24) {    /* UNIVERSAL 4 -- octet string */
        decode_arb(buf, "OCTET STRING", TRUE, store, parent);
    }
    else if (tag == 0x05) {     /* UNIVERSAL PRIMITIVE 5 -- null */
        decode_null(buf, store, parent);
    }
    else if (tag == 0x06) {     /* UNIVERSAL PRIMITIVE 6 -- object identifier */
        decode_oid(buf, store, parent);
    }
    else if (tag == 0x02) {     /* UNIVERSAL PRIMITIVE 10 -- enumerated */
        decode_arb(buf, "ENUMERATED", FALSE, store, parent);
    }
    else if (tag == 0x30) {     /* UNIVERSAL CONSTRUCTED 16 -- sequence/sequenceof */
        decode_seq(buf, store, parent);
    }
    else if (tag == 0x31) {     /* UNIVERSAL CONSTRUTED 17 -- set / set of */
        decode_set(buf, store, parent);
    }
    /*
       string types cf. x509guide.txt
       IA5String -> ASCII Subset
       VisibleString -> ASCII Subset
       TeletexString/T61String -> WTF
       BMPString -> big endian 2 bytes per char
       UniversalString -> big endian 4 bytes per char

       unknown: 
       GeneralString
       GraphicString
       VideotexString
     */
    else if ((tag | 0x20) == 0x2C) {    /* UNIVERSAL 12 -- UTF8String */
        decode_utf8(buf, store, parent);
    }
    else if ((tag | 0x20) == 0x32) {    /* UNIVERSAL 18 -- NumericString */
        decode_asc(buf, "NumericString", store, parent);
    }
    else if ((tag | 0x20) == 0x33) {    /* UNIVERSAL 19 -- PrintableString */
        decode_asc(buf, "PrintableString", store, parent);
    }
    else if ((tag | 0x20) == 0x34) {    /* UNIVERSAL 20 -- TeletexString/T61String */
        decode_arb(buf, "T61String", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x35) {    /* UNIVERSAL 21 -- VideotexString */
        decode_arb(buf, "VideotexString", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x36) {    /* UNIVERSAL 22 -- IA5String */
        decode_asc(buf, "IA5String", store, parent);
    }
    else if ((tag | 0x20) == 0x37) {    /* UNIVERSAL 23 -- UTCTime */
        decode_utctime(buf, store, parent);
    }
    else if ((tag | 0x20) == 0x38) {    /* UNIVERSAL 24 -- GeneralizedTime */
        decode_asc(buf, "GeneralizedTime", store, parent);
    }
    else if ((tag | 0x20) == 0x39) {    /* UNIVERSAL 25 -- GraphicString */
        decode_arb(buf, "GraphicString", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x3A) {    /* UNIVERSAL 26 -- VisibleString */
        decode_asc(buf, "VisibleString", store, parent);
    }
    else if ((tag | 0x20) == 0x3B) {    /* UNIVERSAL 27 -- GraphicString */
        decode_arb(buf, "GraphicString", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x3C) {    /* UNIVERSAL 28 -- UniversalString */
        decode_arb(buf, "UniversalString", FALSE, store, parent);
    }
    else if ((tag | 0x20) == 0x3E) {    /* UNIVERSAL 30 -- BMPString */
        decode_arb(buf, "BMPString", FALSE, store, parent);
    }
    else {
        return DEC_UNKNOWN;
    }
    return DEC_OK;
}                               /* }}} */

static void decode(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {   /* {{{ */
    if (decode_internal(buf, store, parent) == DEC_UNKNOWN) {
        decode_unknown(buf, store, parent);
    }
}                               /* }}} */


/* caller restricts buf to specified area */
static int try_decode(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {
    /* ASSUMING that we are now pointing at a tag, does this value encompass 
       the WHOLE LENGTH of this octet string? */
    DEC_ERROR e;
    uint8_t tag_num;
    uint32_t len;
    const unsigned char *old_cur = buf->cur;


    tag_num = get_byte(buf) & 0x1F;
    if (tag_num == 0x1F) {      /* long tag number */
        uint8_t b;
        tag_num = 0;
        do {
            e = advance(buf, 1);
            if (e != DEC_OK) {
                return DEC_UNKNOWN;
            }
            b = get_byte(buf);
        } while (b & 0x80);
    }
    /* skip last tag byte / only tag byte for short tag */
    e = advance(buf, 1);
    if (e != DEC_OK) {
        return DEC_UNKNOWN;
    }
    /* get length */
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        return DEC_UNKNOWN;
    }
    if ((buf->cur + len) != buf->end) {
        return DEC_UNKNOWN;
    }
    buf->cur = old_cur;
    e = decode_internal(buf, store, parent);
    if (e != DEC_OK) {
        return DEC_UNKNOWN;
    }
    return DEC_OK;
}


static void decode_seq(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {       /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    GtkTreeIter new_row;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    gtk_tree_store_append(store, &new_row, parent);
    gtk_tree_store_set(store, &new_row,
                       TAG_COLUMN, "SEQUENCE",
                       LENGTH_COLUMN, len, CONTENTS_COLUMN, "", -1);
    if (len == 0) {
        return;
    }
    else {
        const unsigned char *end = buf->cur + len;
        while (buf->cur < end) {
            decode(buf, store, &new_row);
        }
        buf->cur = end;
    }
}                               /* }}} */

static void decode_set(buf_t * buf, GtkTreeStore * store, GtkTreeIter * parent) {       /* {{{ */
    DEC_ERROR e;
    uint32_t len;
    GtkTreeIter new_row;
    advance(buf, 1);
    e = get_len(buf, &len);
    if (e != DEC_OK) {
        add_error_entry(store, parent, "decode error %d", e);
        return;
    }
    gtk_tree_store_append(store, &new_row, parent);
    gtk_tree_store_set(store, &new_row,
                       TAG_COLUMN, "SET",
                       LENGTH_COLUMN, len, CONTENTS_COLUMN, "", -1);
    if (len == 0) {
        return;
    }
    else {
        const unsigned char *end = buf->cur + len;
        while (buf->cur < end) {
            decode(buf, store, &new_row);
        }
        buf->cur = end;
    }
}                               /* }}} */

void show_view_cert_dialog(FRONTEND * fe, int id) {
    /* view dialog -> vbox(label("Attributes")--hsep, attrs, label("ASN.1 Details")--hsep, asn1tree), OK button only  */
    GtkWidget *dlg;
    GtkBox *box;
    int status;
    CRYPT_CERTIFICATE cert;
    buf_t buf;
    void *data;
    int data_len;
    GtkWidget *treeview;
    GtkScrolledWindow *sw;
    GtkTreeStore *store;
    GtkLabel *lbl;

    /* export it to DER and set up a buf_t for it */
    status = lmz_ca_get_cert(fe->db, id, &cert);
    if (!cryptStatusOK(status)) {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Failed getting cert (Cryptlib error %d)", status);
        return;
    }
    status =
        lmz_export_cert(cert, CRYPT_CERTFORMAT_CERTIFICATE, &data, &data_len);
    cryptDestroyCert(cert);
    if (!cryptStatusOK(status)) {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Failed exporting cert (Cryptlib error %d)", status);
        return;
    }
    buf.start = data;
    buf.cur = buf.start;
    buf.end = buf.start + data_len;

    dlg =
        gtk_dialog_new_with_buttons("View Certificate Details",
                                    GTK_WINDOW(fe->mainWindow),
                                    GTK_DIALOG_MODAL |
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dlg)->vbox), 5);

    /* label & infobox */
    box = GTK_BOX(gtk_hbox_new(0, 2));
    lbl = GTK_LABEL(gtk_label_new("Attributes"));
    gtk_label_set_markup(lbl, "<b>Attributes</b>");
    gtk_label_set_use_markup(lbl, TRUE);
    gtk_box_pack_start(box, GTK_WIDGET(lbl), FALSE, FALSE, 0);
    gtk_box_pack_start(box, gtk_hseparator_new(), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box), FALSE,
                       FALSE, 3);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox),
                       make_cert_infobox(fe, id), TRUE, TRUE, 0);

    /* label & asn.1 details */
    box = GTK_BOX(gtk_hbox_new(0, 2));
    lbl = GTK_LABEL(gtk_label_new("ASN.1 Details"));
    gtk_label_set_markup(lbl, "<b>ASN.1 Details</b>");
    gtk_label_set_use_markup(lbl, TRUE);
    gtk_box_pack_start(box, GTK_WIDGET(lbl), FALSE, FALSE, 3);
    gtk_box_pack_start(box, gtk_hseparator_new(), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box), FALSE,
                       FALSE, 0);


    treeview = gtk_tree_view_new();
    sw = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
    gtk_container_add(GTK_CONTAINER(sw), treeview);
    store =
        gtk_tree_store_new(N_COLUMNS, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
    decode(&buf, store, NULL);
    gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
    {
        GtkCellRenderer *renderer;
        GtkTreeViewColumn *column;
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Tag", renderer, "text",
                                                     TAG_COLUMN, NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Length", renderer, "text",
                                                     LENGTH_COLUMN, NULL);
        g_object_set(G_OBJECT(renderer), "xalign", 1.0f, NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, "alignment", 1.0f,
                     NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Contents", renderer,
                                                     "text", CONTENTS_COLUMN,
                                                     NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
    }

    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(sw), TRUE,
                       TRUE, 0);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 640, 480);
    gtk_widget_show_all(GTK_WIDGET(GTK_DIALOG(dlg)->vbox));
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
    free(data);
}


/* main for testing {{{ */
#if 0

static void destroy(GtkWidget * widget, gpointer data) {
    gtk_main_quit();
}

int main(int argc, char **argv) {
    GtkWidget *window;
    GtkWidget *treeview;
    gtk_init(&argc, &argv);
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(destroy), NULL);
    treeview = gtk_tree_view_new();
    {
        GtkScrolledWindow *sw =
            GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
        gtk_container_add(GTK_CONTAINER(sw), treeview);
        gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(sw));
    }
    {
        GtkTreeStore *store;
        buf_t buf;
        int i;
        store =
            gtk_tree_store_new(N_COLUMNS, G_TYPE_STRING, G_TYPE_INT,
                               G_TYPE_STRING);
        gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
        if (argc > 1) {
            for (i = 1; i < argc; i++) {
                void *data;
                int data_len;
                data = lmz_file_read_full(argv[i], &data_len);
                if (data) {
                    buf.start = data;
                    buf.end = buf.start + data_len;
                    buf.cur = buf.start;
                    decode(&buf, store, NULL);
                    free(data);
                }
            }
        }
        else {
            for (i = 0; i < N_TESTS; i++) {
                buf.start = test_encodings[i].data;
                buf.end = test_encodings[i].data + test_encodings[i].len;
                buf.cur = buf.start;
                decode(&buf, store, NULL);
            }
        }
#if 0
        GtkTreeIter iter;
        gtk_tree_store_append(store, &iter, NULL);      /* Acquire an iterator */
        gtk_tree_store_set(store, &iter, TAG_COLUMN, "APPLICATION 0",
                           LENGTH_COLUMN, 20, CONTENTS_COLUMN, "AB CD EF 01 23",
                           -1);
#endif
    }
    {
        GtkCellRenderer *renderer;
        GtkTreeViewColumn *column;
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Tag", renderer, "text",
                                                     TAG_COLUMN, NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Length", renderer, "text",
                                                     LENGTH_COLUMN, NULL);
        g_object_set(G_OBJECT(renderer), "xalign", 1.0f, NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, "alignment", 1.0f,
                     NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Contents", renderer,
                                                     "text", CONTENTS_COLUMN,
                                                     NULL);
        g_object_set(G_OBJECT(column), "resizable", TRUE, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
    }
    {
    }
    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}

#endif
/* }}} */
/* vim: set sw=4 et: */
