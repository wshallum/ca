/* Infobox for GUI, containing fingerprints and attributes
 */
#include <stdlib.h>
#include <time.h>
#include <gtk/gtk.h>
#include "cryptlib.h"
#include "frontend.h"
#include "certinfo.h"

static void enum_simple_cert_attr_callback(int, int, void *, int, void *);
struct enum_attr_context {
    FRONTEND *fe;
    GtkListStore *store;
    int in_attr;
    int first_attr;
    GString *str;
};

GtkWidget *make_cert_infobox(FRONTEND * fe, int id) {
    /* an infobox is a vbox w/ 3 parts: md5 fp, sha1 fp, and a GtkTreeView of k/v attr pairs */
    CRYPT_CERTIFICATE cert;
    GtkWidget *vbox;
    int status;
    struct enum_attr_context enum_ctx;
    status = lmz_ca_get_cert(fe->db, id, &cert);
    if (!cryptStatusOK(status)) {
        return gtk_label_new("Error getting cert");
    }

    vbox = gtk_vbox_new(0, 0);
    {
        GtkWidget *md5fp, *sha1fp;
        unsigned char fp[CRYPT_MAX_HASHSIZE];
        int fingerprintSize;
        md5fp = NULL;
        sha1fp = NULL;
        status =
            cryptGetAttributeString(cert, CRYPT_CERTINFO_FINGERPRINT_MD5, &fp,
                                    &fingerprintSize);
        if (cryptStatusOK(status) && (fingerprintSize == 16)) { /* MD5 -> 128 bits */
            gchar *md5_text;
            md5_text =
                g_strdup_printf
                ("MD5 Fingerprint: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                 fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7], fp[8],
                 fp[9], fp[10], fp[11], fp[12], fp[13], fp[14], fp[15]);
            md5fp = gtk_label_new(md5_text);
            gtk_label_set_selectable(GTK_LABEL(md5fp), TRUE);
            g_free(md5_text);
        }
        status =
            cryptGetAttributeString(cert, CRYPT_CERTINFO_FINGERPRINT_SHA1, &fp,
                                    &fingerprintSize);
        if (cryptStatusOK(status) && (fingerprintSize == 20)) { /* SHA1 -> 160 bits */
            gchar *sha1_text;
            sha1_text =
                g_strdup_printf
                ("SHA1 Fingerprint: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                 fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7], fp[8],
                 fp[9], fp[10], fp[11], fp[12], fp[13], fp[14], fp[15], fp[16],
                 fp[17], fp[18], fp[19]);
            sha1fp = gtk_label_new(sha1_text);
            gtk_label_set_selectable(GTK_LABEL(sha1fp), TRUE);
            g_free(sha1_text);
        }
        if (md5fp != NULL) {
            gtk_box_pack_start(GTK_BOX(vbox), md5fp, FALSE, FALSE, 0);
        }
        if (sha1fp != NULL) {
            gtk_box_pack_start(GTK_BOX(vbox), sha1fp, FALSE, FALSE, 0);
        }
    }
    enum_ctx.fe = fe;
    enum_ctx.store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    enum_ctx.in_attr = 0;
    enum_ctx.first_attr = 1;
    enum_ctx.str = NULL;
    lmz_certinfo_enum_simple_cert_attributes(cert,
                                             enum_simple_cert_attr_callback,
                                             &enum_ctx);
    if (enum_ctx.str) {
        g_string_free(enum_ctx.str, TRUE);
    }

    {
        GtkTreeView *tv;
        GtkCellRenderer *renderer;
        GtkTreeViewColumn *column;
        GtkScrolledWindow *sw;

        tv = GTK_TREE_VIEW(gtk_tree_view_new_with_model
                           (GTK_TREE_MODEL(enum_ctx.store)));
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Attribute", renderer,
                                                     "text", 0, NULL);
        gtk_tree_view_append_column(tv, column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Value", renderer, "text",
                                                     1, NULL);
        gtk_tree_view_append_column(tv, column);
        sw = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
        gtk_scrolled_window_set_policy(sw, GTK_POLICY_AUTOMATIC,
                                       GTK_POLICY_AUTOMATIC);
        gtk_container_add(GTK_CONTAINER(sw), GTK_WIDGET(tv));
        gtk_box_pack_start(GTK_BOX(vbox), GTK_WIDGET(sw), TRUE, TRUE, 0);
    }

    cryptDestroyCert(cert);

    return vbox;
}

GtkWidget *make_request_infobox_direct(FRONTEND * fe, CRYPT_CERTIFICATE cert,
                                       char *notes) {
    GtkWidget *vbox;
    struct enum_attr_context enum_ctx;
    vbox = gtk_vbox_new(0, 0);
    enum_ctx.fe = fe;
    enum_ctx.store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    enum_ctx.in_attr = 0;
    enum_ctx.first_attr = 1;
    enum_ctx.str = NULL;
    lmz_certinfo_enum_simple_cert_attributes(cert,
                                             enum_simple_cert_attr_callback,
                                             &enum_ctx);
    if (enum_ctx.str) {
        g_string_free(enum_ctx.str, TRUE);
    }

    {
        GtkTreeView *tv;
        GtkCellRenderer *renderer;
        GtkTreeViewColumn *column;
        GtkScrolledWindow *sw;

        tv = GTK_TREE_VIEW(gtk_tree_view_new_with_model
                           (GTK_TREE_MODEL(enum_ctx.store)));
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Attribute", renderer,
                                                     "text", 0, NULL);
        gtk_tree_view_append_column(tv, column);
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes("Value", renderer, "text",
                                                     1, NULL);
        gtk_tree_view_append_column(tv, column);
        sw = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
        gtk_scrolled_window_set_policy(sw, GTK_POLICY_AUTOMATIC,
                                       GTK_POLICY_AUTOMATIC);
        gtk_container_add(GTK_CONTAINER(sw), GTK_WIDGET(tv));
        gtk_box_pack_start(GTK_BOX(vbox), GTK_WIDGET(sw), TRUE, TRUE, 0);
        if (notes) {
            GtkExpander *expander;
            GtkTextBuffer *buf;
            GtkTextView *textview;
            expander = GTK_EXPANDER(gtk_expander_new("Notes"));
            gtk_expander_set_expanded(expander, FALSE);
            textview = GTK_TEXT_VIEW(gtk_text_view_new());
            buf = gtk_text_view_get_buffer(textview);
            gtk_text_buffer_set_text(buf, notes, -1);
            gtk_container_add(GTK_CONTAINER(expander), GTK_WIDGET(textview));
            gtk_widget_hide(GTK_WIDGET(textview));
            gtk_box_pack_start(GTK_BOX(vbox), GTK_WIDGET(expander), FALSE,
                               FALSE, 0);
        }
    }
    return vbox;
}

GtkWidget *make_request_infobox(FRONTEND * fe, int id) {
    /* an infobox is a vbox contains GtkTreeView of k/v attr pairs */
    CRYPT_CERTIFICATE cert;
    GtkWidget *vbox;
    int status;
    int handled;
    char *notes;
    status = lmz_ca_get_request(fe->db, id, &cert, &handled, &notes);
    if (!cryptStatusOK(status)) {
        return gtk_label_new("Error getting request");
    }
    vbox = make_request_infobox_direct(fe, cert, notes);
    if (notes)
        free(notes);
    cryptDestroyCert(cert);
    return vbox;

}


/* returns new string -- free with g_free */
static char *str_repr(int attr_type, void *data, int data_len) {
    if (attr_type == LMZ_ATTR_TYPE_PRINTABLE) {
        return g_strdup(data);
    }
    else if (attr_type == LMZ_ATTR_TYPE_NUMERIC) {
        return g_strdup_printf("%d", *((int *) data));
    }
    else if (attr_type == LMZ_ATTR_TYPE_TIME) {
        char buf[256];
        struct tm *tmp;
        tmp = gmtime((time_t *) data);
        strftime(buf, 255, "%d-%m-%Y %H:%M:%S UTC", tmp);
        buf[255] = '\0';
        return g_strdup(buf);
    }
    else if (attr_type == LMZ_ATTR_TYPE_BINARY) {
        GString *str;
        int i;
        str = g_string_sized_new(data_len * 3 + 16);
        for (i = 0; i < data_len; i++) {
            const char *colon = (i == 0 ? "" : ":");
            unsigned char byte = ((unsigned char *) data)[i];
            g_string_append_printf(str, "%s%.2X", colon, byte);
        }
        return g_string_free(str, FALSE);
    }
    return g_strdup("XXX TODO");
}

/* returns new string -- free with g_free */
static char *keyusage_str_repr(int keyusage_bits) {
    GString *s;
    int notfirst = 0;
    s = g_string_new("");
    if (keyusage_bits == 0) {
        g_string_append(s, "<no bits set>");
        return g_string_free(s, FALSE);
    }
    else {
#define OPT_COMMA (notfirst++ ? ", " : "")
        if (keyusage_bits & CRYPT_KEYUSAGE_DIGITALSIGNATURE) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Digital Signature");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_NONREPUDIATION) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Non-repudiation");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_KEYENCIPHERMENT) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Key Encipherment");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_DATAENCIPHERMENT) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Data Encipherment");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_KEYAGREEMENT) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Key Agreement");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_KEYCERTSIGN) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Certificate Signing");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_CRLSIGN) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "CRL Signing");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_ENCIPHERONLY) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Encipher Only");
        }
        if (keyusage_bits & CRYPT_KEYUSAGE_DECIPHERONLY) {
            g_string_append_printf(s, "%s%s", OPT_COMMA, "Decipher Only");
        }
#undef OPT_COMMA
        return g_string_free(s, FALSE);
    }

}

static void enum_simple_cert_attr_callback(int attr, int attr_type, void *data,
                                           int data_len, void *user_data) {
    struct enum_attr_context *ctx = (struct enum_attr_context *) user_data;
    if ((attr == CRYPT_CERTINFO_BASICCONSTRAINTS) || (attr == CRYPT_CERTINFO_EXTKEYUSAGE)) {    /* compound attrs */
        int entering = *((int *) data);
        if (entering) {
            ctx->in_attr = attr;
            ctx->first_attr = 1;
            ctx->str = g_string_new("");
        }
        else {                  /* exiting */
            ctx->in_attr = 0;
            ctx->first_attr = 1;
            if (ctx->str) {
                GtkTreeIter new_row;
                const char *attr_name;
                int unused;
                lmz_certinfo_get_description(attr, &attr_name, &unused);
                gtk_list_store_append(ctx->store, &new_row);
                gtk_list_store_set(ctx->store, &new_row, 0, attr_name, 1,
                                   ctx->str->str, -1);
                g_string_free(ctx->str, TRUE);
                ctx->str = NULL;
            }
        }
        return;
    }

    /* OK, this is not a group-type attr */
    if (ctx->in_attr) {
        /* are we inside a group? */
        if (!ctx->first_attr) {
            g_string_append(ctx->str, ", ");
        }
        {
            /* print the attr name */
            const char *attr_name;
            int unused;
            lmz_certinfo_get_description(attr, &attr_name, &unused);
            g_string_append(ctx->str, attr_name);
        }
        if (attr_type != LMZ_ATTR_TYPE_EXISTENCE) {
            char *val;
            g_string_append(ctx->str, ": ");
            val = str_repr(attr_type, data, data_len);
            g_string_append_printf(ctx->str, "%s", val);
            g_free(val);
        }
        ctx->first_attr = 0;
    }
    else {
        /* not inside a group -- just add to the store */
        const char *attr_name;
        int unused;
        char *val;
        GtkTreeIter new_row;
        lmz_certinfo_get_description(attr, &attr_name, &unused);
        if (attr == CRYPT_CERTINFO_KEYUSAGE) {
            val = keyusage_str_repr(*((int *) data));
        }
        else {
            val = str_repr(attr_type, data, data_len);
        }
        gtk_list_store_append(ctx->store, &new_row);
        gtk_list_store_set(ctx->store, &new_row, 0, attr_name, 1, val, -1);
        g_free(val);
    }
}
/* vim: set sw=4 et: */
