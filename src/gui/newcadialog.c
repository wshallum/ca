/* GUI "new CA" dialog including self-signed CA cert generation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include "frontend.h"

#include "countrycodes.inc"

static int make_cert(const char *dn_c, const char *dn_sp, const char *dn_l,
                     const char *dn_o, const char *dn_ou, const char *dn_cn,
                     const char *crl_dp_uri, int valid_days,
                     CRYPT_CONTEXT ca_key_pair, CRYPT_CERTIFICATE * pCert);

static int make_key_pair(int bits, const char *label, CRYPT_CONTEXT * pKey);

static GtkTreeModel *make_countrycode_model() {
    int i;
    GtkListStore *store;
    int num = sizeof(country_codes) / sizeof(country_codes[0]);
    store = gtk_list_store_new(2, G_TYPE_STRING,        /* code */
                               G_TYPE_STRING /* name */ );
    for (i = 0; i < num; i += 2) {
        GtkTreeIter new_row;
        gtk_list_store_append(store, &new_row);
        gtk_list_store_set(store, &new_row, 0, country_codes[i], 1,
                           country_codes[i + 1], -1);
    }
    return GTK_TREE_MODEL(store);
}

gboolean show_ca_dialog(FRONTEND * fe, const char *filename) {
    GladeXML *xml;
    GtkWidget *dlg;
    GtkWidget *cbx_bits;
    GtkWidget *sb_days;
    GtkWidget *cbx_c;

    /* load sign dlg */
    xml = glade_xml_new(LMZ_UI_ROOT "/newca.glade", NULL, NULL);
    dlg = glade_xml_get_widget(xml, "newCaDialog");

    /* fill in key bits combobox and pick 4096 bits as default */
    cbx_bits = glade_xml_get_widget(xml, "cbx_bits");
    gtk_combo_box_append_text(GTK_COMBO_BOX(cbx_bits), "2048");
    gtk_combo_box_append_text(GTK_COMBO_BOX(cbx_bits), "4096");
    gtk_combo_box_set_active(GTK_COMBO_BOX(cbx_bits), 0);

    /* fill country combobox from model */
    cbx_c = glade_xml_get_widget(xml, "cb_c");
    gtk_combo_box_set_model(GTK_COMBO_BOX(cbx_c), make_countrycode_model());
    {
        GtkCellRenderer *renderer;
        renderer = gtk_cell_renderer_text_new();
        gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(cbx_c), renderer, TRUE);
        gtk_cell_layout_add_attribute(GTK_CELL_LAYOUT(cbx_c), renderer, "text",
                                      1);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(cbx_c), 0);


    /* set spinbutton defaults and set default validity period 5 years */
    sb_days = glade_xml_get_widget(xml, "sb_days");
    gtk_spin_button_set_range(GTK_SPIN_BUTTON(sb_days), 365 * 2, 365 * 10);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb_days), 365 * 5);

    gtk_window_set_modal(GTK_WINDOW(dlg), TRUE);
    {
        gint result;
      show_again:
        result = gtk_dialog_run(GTK_DIALOG(dlg));
        if (result == GTK_RESPONSE_OK) {
            gchar *ca_name = NULL;
            gchar *dn_c = NULL, *dn_sp = NULL, *dn_l = NULL, *dn_o =
                NULL, *dn_ou = NULL, *dn_cn = NULL;
            gchar *crl_dp_uri = NULL;
            gchar *pw = NULL, *pw_again = NULL;
            int valid_days;
            int key_size;
            gboolean show_again = TRUE;

            /*
               verify mandatory names
             */
            ca_name =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_shortname"))));
            g_strstrip(ca_name);
            if (strlen(ca_name) == 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The Short Name field must be filled");
                goto skip_checks;
            }
            /* verify name exists */
            {
                int err;
                char **names;
                int i;
                err = lmz_ca_get_existing_names(filename, &names);
                if (err == SQLITE_OK) {
                    for (i = 0; names[i] != NULL; i++) {
                        if (strcmp(ca_name, names[i]) == 0) {
                            show_error_dialog(GTK_WINDOW(dlg),
                                              "The Short Name is already used, pick a different one");
                            lmz_ca_free_names(names);
                            goto skip_checks;
                        }
                    }
                    lmz_ca_free_names(names);
                }
                else if (err == SQLITE_NOTFOUND) {
                    /* do nothing */
                }
                else {
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error getting existing names to compare (SQLite error %d)",
                                      err);
                }
            }
            {
                GValue countrycode_value;
                GtkTreeIter selected_row;
                GtkTreeModel *model;
                gtk_combo_box_get_active_iter(GTK_COMBO_BOX
                                              (glade_xml_get_widget
                                               (xml, "cb_c")), &selected_row);
                model =
                    gtk_combo_box_get_model(GTK_COMBO_BOX
                                            (glade_xml_get_widget
                                             (xml, "cb_c")));
                memset(&countrycode_value, 0, sizeof(GValue));
                gtk_tree_model_get_value(model, &selected_row, 0,
                                         &countrycode_value);
                dn_c = g_value_dup_string(&countrycode_value);
                g_value_unset(&countrycode_value);
                g_strstrip(dn_c);
                if (strlen(dn_c) == 0) {
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "The Country field must be filled");
                    goto skip_checks;
                }
            }
            dn_o =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_o"))));
            g_strstrip(dn_o);
            if (strlen(dn_o) == 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The Organization field must be filled");
                goto skip_checks;
            }
            dn_cn =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_cn"))));
            g_strstrip(dn_cn);
            if (strlen(dn_cn) == 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The Common Name field must be filled");
                goto skip_checks;
            }
            pw = g_strdup(gtk_entry_get_text
                          (GTK_ENTRY(glade_xml_get_widget(xml, "e_password"))));
            g_strstrip(pw);
            if (strlen(pw) == 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The Password field must be filled");
                goto skip_checks;
            }
            pw_again =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY
                          (glade_xml_get_widget(xml, "e_password_repeat"))));
            g_strstrip(pw_again);
            if (strlen(pw_again) == 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The Password (Repeat) field must be filled");
                goto skip_checks;
            }

            /*
               verify passwords
             */
            if (strcmp(pw, pw_again) != 0) {
                show_error_dialog(GTK_WINDOW(dlg),
                                  "The passwords don't match. Please check again.");
                goto skip_checks;
            }

            /* ok done */
            show_again = FALSE;

            /*
               get the rest of the fields (the non-mandatory ones), mapping empty fields to NULL
             */
            dn_sp =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_sp"))));
            g_strstrip(dn_sp);
            if (strlen(dn_sp) == 0) {
                g_free(dn_sp);
                dn_sp = NULL;
            }
            dn_l =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_l"))));
            g_strstrip(dn_l);
            if (strlen(dn_l) == 0) {
                g_free(dn_l);
                dn_l = NULL;
            }
            dn_ou =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_ou"))));
            g_strstrip(dn_ou);
            if (strlen(dn_ou) == 0) {
                g_free(dn_ou);
                dn_ou = NULL;
            }
            crl_dp_uri =
                g_strdup(gtk_entry_get_text
                         (GTK_ENTRY(glade_xml_get_widget(xml, "e_cdp_uri"))));
            g_strstrip(crl_dp_uri);
            if (strlen(crl_dp_uri) == 0) {
                g_free(crl_dp_uri);
                crl_dp_uri = NULL;
            }

            if (gtk_combo_box_get_active(GTK_COMBO_BOX(cbx_bits)) == 0) {
                key_size = 2048;
            }
            else {
                key_size = 4096;
            }

            valid_days =
                gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(sb_days));

            {
                CRYPT_CONTEXT key;
                int status;
                CRYPT_CERTIFICATE cert;
                /*
                   make key pair
                 */
                status = make_key_pair(key_size, ca_name, &key);
                if (!cryptStatusOK(status)) {
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error creating key (cl err %d)", status);
                    show_again = TRUE;
                    goto skip_checks;
                }
                /*
                   make cert
                 */
                status =
                    make_cert(dn_c, dn_sp, dn_l, dn_o, dn_ou, dn_cn, crl_dp_uri,
                              valid_days, key, &cert);
                if (!cryptStatusOK(status)) {
                    cryptDestroyContext(key);
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error creating cert (cl err %d)",
                                      status);
                    show_again = TRUE;
                    goto skip_checks;
                }
                /*
                   save them
                 */
                status = lmz_ca_create(&fe->db, filename, key, cert, pw);
                if (!cryptStatusOK(status)) {
                    cryptDestroyContext(key);
                    cryptDestroyCert(cert);
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error creating CA (cl err %d)", status);
                    show_again = FALSE;
                    goto skip_checks;
                }
                cryptDestroyContext(key);
                cryptDestroyCert(cert);
            }
          skip_checks:         /* g_free of NULL is OK */
            g_free(ca_name);
            g_free(dn_c);
            g_free(dn_sp);
            g_free(dn_l);
            g_free(dn_o);
            g_free(dn_ou);
            g_free(dn_cn);
            g_free(crl_dp_uri);
            g_free(pw);
            g_free(pw_again);
            if (show_again)
                goto show_again;
            gtk_widget_destroy(dlg);
            g_object_unref(G_OBJECT(xml));

            return TRUE;
        }
        else {
            gtk_widget_destroy(dlg);
            g_object_unref(G_OBJECT(xml));

            return FALSE;
        }
    }
}


static int make_key_pair(int bits, const char *label, CRYPT_CONTEXT * pKey) {
    int status;
    CRYPT_CONTEXT local_context;

    /* create the RSA context */
    status = cryptCreateContext(&local_context, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while creating keypair context\n",
                status);
        return status;
    }

    /* set key label */
    status =
        cryptSetAttributeString(local_context, CRYPT_CTXINFO_LABEL, label,
                                strlen(label));
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while setting privkey label\n",
                status);
        goto err_ctx_exit;
    }

    status = cryptSetAttribute(local_context, CRYPT_CTXINFO_KEYSIZE, bits / 8);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while setting keysize\n", status);
        goto err_ctx_exit;
    }

    /* generate key */
    status = cryptGenerateKey(local_context);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while generating CA keypair\n",
                status);
        goto err_ctx_exit;
    }

    /* normal (OK) exit */
    *pKey = local_context;
    return CRYPT_OK;
  err_ctx_exit:
    cryptDestroyContext(local_context);
    return status;
}

static int make_cert(const char *dn_c, const char *dn_sp, const char *dn_l,
                     const char *dn_o, const char *dn_ou, const char *dn_cn,
                     const char *crl_dp_uri, int valid_days,
                     CRYPT_CONTEXT ca_key_pair, CRYPT_CERTIFICATE * pCert) {
    CRYPT_CERTIFICATE result_certificate;
    int status;
    time_t now, then;

    /* create the certificate and associate it with the CA's pubkey */
    status =
        cryptCreateCert(&result_certificate, CRYPT_UNUSED,
                        CRYPT_CERTTYPE_CERTIFICATE);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while creating CA selfsigned cert\n",
                status);
        return status;
    }

    status =
        cryptSetAttribute(result_certificate,
                          CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, ca_key_pair);
    if (!cryptStatusOK(status)) {
        fprintf(stderr,
                "cryptlib error %d while associating CA cert with key\n",
                status);
        goto err_cert_exit;
    }

#define setdncmp(attr,var) \
  if (var != NULL) { \
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

    status =
        cryptSetAttribute(result_certificate, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CERTINFO_CRLDIST_FULLNAME);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while setting CRYPT_ATTRIBUTE\n",
                status);
        goto err_cert_exit;
    }
    setdncmp(CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, crl_dp_uri);
    status =
        cryptSetAttribute(result_certificate, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CERTINFO_SUBJECTNAME);
    if (!cryptStatusOK(status)) {
        fprintf(stderr,
                "cryptlib error %d while selecting  CRYPT_CERTINFO_SUBJECTNAME\n",
                status);
        goto err_cert_exit;
    }
#undef setdncmp

    now = time(NULL);
    then = now + (valid_days * 86400);
    status =
        cryptSetAttributeString(result_certificate, CRYPT_CERTINFO_VALIDFROM,
                                &now, sizeof(time_t));
    if (!cryptStatusOK(status)) {
        fprintf(stderr,
                "cryptlib error %d while setting CRYPT_CERTINFO_VALIDFROM\n",
                status);
        goto err_cert_exit;
    }
    status =
        cryptSetAttributeString(result_certificate, CRYPT_CERTINFO_VALIDTO,
                                &then, sizeof(time_t));
    if (!cryptStatusOK(status)) {
        fprintf(stderr,
                "cryptlib error %d while setting CRYPT_CERTINFO_VALIDTO\n",
                status);
        goto err_cert_exit;
    }

    /* set self-signed and CA bits */
    status =
        cryptSetAttribute(result_certificate, CRYPT_CERTINFO_SELFSIGNED, 1);
    if (!cryptStatusOK(status)) {
        fprintf(stderr,
                "cryptlib error %d while setting CA cert selfsigned bit\n",
                status);
        goto err_cert_exit;
    }

    status = cryptSetAttribute(result_certificate, CRYPT_CERTINFO_CA, 1);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cryptlib error %d while setting CA cert CA bit\n",
                status);
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
        fprintf(stderr, "cryptlib error %d while self-signing CA cert\n",
                status);
        goto err_cert_exit;
    }

    *pCert = result_certificate;
    return CRYPT_OK;
  err_cert_exit:
    cryptDestroyCert(result_certificate);
    return status;

}
/* vim: set sw=4 et: */
