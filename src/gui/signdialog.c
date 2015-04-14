/* GUI dialog: sign request. 
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#include "frontend.h"
#include "cadb.h"

static LMZ_CL_ERROR do_create_tbscert(CRYPT_CERTIFICATE csr, PLMZ_SIGN_OPT sign_opt,
                                      /* OUT */ CRYPT_CERTIFICATE * tbsCert);
static void do_apply_preset(GtkWidget * widget, gpointer data);
static void do_save_preset(GtkWidget * widget, gpointer data);
static void do_delete_preset(GtkWidget * widget, gpointer data);
static void apply_preset_to_sign_dlg(GtkDialog * dlg,
                                     const PLMZ_SIGN_OPT sign_opt);
static void make_preset_from_sign_dlg(GtkDialog * dlg, PLMZ_SIGN_OPT sign_opt);
static void do_update_signopt_model(FRONTEND * fe, GtkComboBox * combo,
                                    const gchar * new_selection);
static gchar *get_signopt_name(GtkWindow * parentWindow,
                               const char *default_name);




void show_sign_dialog(FRONTEND * fe, int id) {
    GladeXML *xml;
    GtkWidget *dlg;
    CRYPT_CERTIFICATE csr;
    int status;
    int handled;
    int has_eku, has_ku;
    struct {
        GtkCheckButton *cb;
        int ku_bit;
    } pairings[8], *pairptr;
    char *notes;


    /* get from db */
    status = lmz_ca_get_request(fe->db, id, &csr, &handled, &notes);
    if (!cryptStatusOK(status)) {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Error getting request from database (cryptlib error %d)",
                          status);
        return;
    }

    /* load sign dlg */

    xml = glade_xml_new(LMZ_UI_ROOT "/sign.glade", NULL, NULL);
    dlg = glade_xml_get_widget(xml, "signDialog");

    /* wire up events */
    g_signal_connect(G_OBJECT(glade_xml_get_widget(xml, "btn_apply_preset")),
                     "clicked", G_CALLBACK(do_apply_preset), fe);
    g_signal_connect(G_OBJECT(glade_xml_get_widget(xml, "btn_save_preset")),
                     "clicked", G_CALLBACK(do_save_preset), fe);
    g_signal_connect(G_OBJECT(glade_xml_get_widget(xml, "btn_delete_preset")),
                     "clicked", G_CALLBACK(do_delete_preset), fe);

    /* set infobox */
    {
        GtkWidget *tv, *parent;
        tv = glade_xml_get_widget(xml, "sw_infobox");
        parent = gtk_widget_get_parent(tv);
        gtk_widget_destroy(tv);
        tv = make_request_infobox_direct(fe, csr, notes);
        if (notes)
            free(notes);
        gtk_box_pack_start(GTK_BOX(parent), tv, TRUE, TRUE, 0); /* parent is a vbox */
        gtk_widget_show_all(parent);
    }

    /* check KU checkboxes */
    {
        int keyusage;
        pairings[0].ku_bit = CRYPT_KEYUSAGE_DIGITALSIGNATURE;
        pairings[1].ku_bit = CRYPT_KEYUSAGE_NONREPUDIATION;
        pairings[2].ku_bit = CRYPT_KEYUSAGE_KEYENCIPHERMENT;
        pairings[3].ku_bit = CRYPT_KEYUSAGE_DATAENCIPHERMENT;
        pairings[4].ku_bit = CRYPT_KEYUSAGE_KEYAGREEMENT;
        pairings[5].ku_bit = CRYPT_KEYUSAGE_ENCIPHERONLY;
        pairings[6].ku_bit = CRYPT_KEYUSAGE_DECIPHERONLY;
        pairings[7].ku_bit = 0;
        pairings[0].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_ds"));
        pairings[1].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_nr"));
        pairings[2].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_ke"));
        pairings[3].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_de"));
        pairings[4].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_ka"));
        pairings[5].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_eo"));
        pairings[6].cb =
            GTK_CHECK_BUTTON(glade_xml_get_widget(xml, "cb_ku_do"));
        pairings[7].cb = NULL;

        status = cryptGetAttribute(csr, CRYPT_CERTINFO_KEYUSAGE, &keyusage);
        if (cryptStatusOK(status)) {
            has_ku = TRUE;
            for (pairptr = pairings; pairptr->cb; ++pairptr) {
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pairptr->cb),
                                             (keyusage & pairptr->ku_bit) != 0);
            }
        }
        else {
            has_ku = FALSE;
        }
    }

    /* check EKU checkboxes */
    {
        int dummy;
        status = cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEYUSAGE, &dummy);
        if (cryptStatusOK(status)) {
            /* get one by one */
            has_eku = TRUE;
            status =
                cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
                                  &dummy);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_svr")),
                                         cryptStatusOK(status));
            status =
                cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
                                  &dummy);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_cli")),
                                         cryptStatusOK(status));
            status =
                cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEY_CODESIGNING,
                                  &dummy);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_cs")),
                                         cryptStatusOK(status));
            status =
                cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
                                  &dummy);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_ep")),
                                         cryptStatusOK(status));
            status =
                cryptGetAttribute(csr, CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
                                  &dummy);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_ts")),
                                         cryptStatusOK(status));
        }
        else {
            has_eku = FALSE;
        }
    }

    /* if it's a cert w/o KU & w/o EKU, then check the default server flags
       (digitalSignature, nonRepudiation, keyEncipherment) & serverAuth
     */
    if (!has_ku && !has_eku) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                     (glade_xml_get_widget(xml, "cb_ku_ds")),
                                     TRUE);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                     (glade_xml_get_widget(xml, "cb_ku_nr")),
                                     TRUE);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                     (glade_xml_get_widget(xml, "cb_ku_ke")),
                                     TRUE);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                     (glade_xml_get_widget(xml, "cb_eku_svr")),
                                     TRUE);
    }

    /* set preset combobox */
    {
        GtkComboBox *combo;
        GtkCellRenderer *renderer;
        combo = GTK_COMBO_BOX(glade_xml_get_widget(xml, "cmb_presets"));
        gtk_combo_box_set_model(combo,
                                GTK_TREE_MODEL(make_signopt_list_model(fe)));
        renderer = gtk_cell_renderer_text_new();
        gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo), renderer, TRUE);
        gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo), renderer, "text",
                                       0, NULL);
    }


    gtk_window_set_modal(GTK_WINDOW(dlg), TRUE);
    {
        gint result = gtk_dialog_run(GTK_DIALOG(dlg));
        if (result == GTK_RESPONSE_OK) {
            LMZ_SIGN_OPT sign_opt;
            make_preset_from_sign_dlg(GTK_DIALOG(dlg), &sign_opt);

            /* handle cert signing */
            {
                CRYPT_CERTIFICATE tbsCert;
                status = do_create_tbscert(csr, &sign_opt, &tbsCert);
                if (!cryptStatusOK(status)) {
                    show_error_dialog(GTK_WINDOW(fe->mainWindow),
                                      "Error creating tbs-cert (cryptlib error %d)",
                                      status);
                    goto cleanup;
                }
                else {
                    CRYPT_CONTEXT key;
                    gchar *password;
                    /* get password */
                    password = do_get_password(GTK_WINDOW(dlg));
                    if (password == NULL) {
                        /* cancelled? */
                        cryptDestroyCert(tbsCert);
                        goto cleanup;
                    }
                    /* sign */
                    status = lmz_ca_get_signing_key(fe->db, password, &key);
                    g_free(password);   /* dynamic */
                    if (status == CRYPT_ERROR_WRONGKEY) {
                        show_error_dialog(GTK_WINDOW(dlg), "Wrong password");
                        cryptDestroyCert(tbsCert);
                        goto cleanup;
                    }
                    else if (!cryptStatusOK(status)) {
                        show_error_dialog(GTK_WINDOW(dlg),
                                          "Error getting signing key (cryptlib error %d)",
                                          status);
                        cryptDestroyCert(tbsCert);
                        goto cleanup;
                    }
                    /* copy CRLDP URI */
                    {
                        char *uri;
                        int uri_len;
                        /* does it have CRLDIST_FULLNAME? */
                        status =
                            cryptSetAttribute(fe->db->ca_cert,
                                              CRYPT_ATTRIBUTE_CURRENT,
                                              CRYPT_CERTINFO_CRLDIST_FULLNAME);
                        if (cryptStatusOK(status)) {
                            /* OK, automatically selected */
                            uri =
                                lmz_cl_get_attribute_string(fe->db->ca_cert,
                                                            CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
                                                            &uri_len);
                            if (uri != NULL) {
                                int fail = 0;
                                /* select the attr inside the new cert */
                                status =
                                    cryptSetAttribute(tbsCert,
                                                      CRYPT_ATTRIBUTE_CURRENT,
                                                      CRYPT_CERTINFO_CRLDIST_FULLNAME);
                                if (!cryptStatusOK(status)) {
                                    fail = 1;
                                    goto set_fail;
                                }
                                status =
                                    cryptSetAttributeString(tbsCert,
                                                            CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
                                                            uri, uri_len);
                                if (!cryptStatusOK(status)) {
                                    fail = 1;
                                    goto set_fail;
                                }
                              set_fail:
                                if (fail)
                                    cryptDeleteAttribute(tbsCert,
                                                         CRYPT_CERTINFO_CRLDIST_FULLNAME);
                                status =
                                    cryptSetAttribute(tbsCert,
                                                      CRYPT_ATTRIBUTE_CURRENT,
                                                      CRYPT_CERTINFO_SUBJECTNAME);
                                free(uri);
                            }
                            else {
                                fprintf(stderr,
                                        "getting crldist-fullname-uri failed\n");
                            }
                            status =
                                cryptSetAttribute(fe->db->ca_cert,
                                                  CRYPT_ATTRIBUTE_CURRENT,
                                                  CRYPT_CERTINFO_SUBJECTNAME);
                        }
                        else {
                            fprintf(stderr,
                                    "getting crldist-fullname failed w/ %d\n",
                                    status);
                        }
                    }
                    status = cryptSignCert(tbsCert, key);
                    cryptDestroyContext(key);
                    if (!cryptStatusOK(status)) {
                        show_error_dialog(GTK_WINDOW(dlg),
                                          "Error signing cert (cryptlib error %d)",
                                          status);
                        cryptDestroyCert(tbsCert);
                        goto cleanup;
                    }
                    status = lmz_ca_save_cert(fe->db, id, tbsCert);
                    if (!cryptStatusOK(status)) {
                        show_error_dialog(GTK_WINDOW(dlg),
                                          "Error saving signed cert (cryptlib error %d)",
                                          status);
                        cryptDestroyCert(tbsCert);
                        goto cleanup;
                    }
                    cryptDestroyCert(tbsCert);
                    /* yay, it worked */
                    {
                        GtkTreeView *mainwin_req_tv, *mainwin_cert_tv;
                        mainwin_req_tv =
                            GTK_TREE_VIEW(g_object_get_data
                                          (G_OBJECT(fe->mainWindow),
                                           "request-list"));
                        mainwin_cert_tv =
                            GTK_TREE_VIEW(g_object_get_data
                                          (G_OBJECT(fe->mainWindow),
                                           "certificate-list"));
                        refresh_request_tree_view(mainwin_req_tv, fe);
                        refresh_cert_tree_view(mainwin_cert_tv, fe);
                    }
                }
            }
        }
        else {
            /* not accepted */
        }
    }

  cleanup:
    gtk_widget_destroy(dlg);
    g_object_unref(xml);
    cryptDestroyCert(csr);
}

static LMZ_CL_ERROR do_create_tbscert(CRYPT_CERTIFICATE csr,
                                      PLMZ_SIGN_OPT sign_opt,
                                      CRYPT_CERTIFICATE * tbsCert) {
    CRYPT_CERTIFICATE cert;
    void *dn_elt;
    int dn_elt_len;
    int status;
    int attrs[] =
        { CRYPT_CERTINFO_COUNTRYNAME, CRYPT_CERTINFO_STATEORPROVINCENAME,
        CRYPT_CERTINFO_LOCALITYNAME,
        CRYPT_CERTINFO_ORGANIZATIONNAME, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
        CRYPT_CERTINFO_COMMONNAME,
        CRYPT_CERTINFO_EMAIL
    };
    int n_attrs;
    int i;

    n_attrs = sizeof(attrs) / sizeof(attrs[0]);

    *tbsCert = CRYPT_ERROR_NOTINITED;
    /* create local tbs-cert */
    status = cryptCreateCert(&cert, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE);
    if (!cryptStatusOK(status)) {
        return status;
    }
    /* select subject dn in csr */
    status =
        cryptSetAttribute(csr, CRYPT_ATTRIBUTE_CURRENT,
                          CRYPT_CERTINFO_SUBJECTNAME);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(cert);
        return status;
    }
    /* copy dn elts if exists : C, SP, L, O, OU, CN, EMAIL */
    for (i = 0; i < n_attrs; i++) {
        dn_elt = lmz_cl_get_attribute_string(csr, attrs[i], &dn_elt_len);
        if (dn_elt) {
            status =
                cryptSetAttributeString(cert, attrs[i], dn_elt, dn_elt_len);
            free(dn_elt);
            if (!cryptStatusOK(status)) {
                cryptDestroyCert(cert);
                return status;
            }
        }
    }
    /* copy pub key */
    status = cryptSetAttribute(cert, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, csr);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(cert);
        return status;
    }
    /* use apply func */
    status = lmz_ca_apply_sign_opt(sign_opt, cert);
    if (!cryptStatusOK(status)) {
        cryptDestroyCert(cert);
        return status;
    }

    /* OK, done */
    *tbsCert = cert;
    return CRYPT_OK;

}

static void do_apply_preset(GtkWidget * widget, gpointer data) {
    GladeXML *xml;
    GtkComboBox *combo;
    GtkTreeModel *lst;
    GtkTreeIter iter;
    FRONTEND *fe = (FRONTEND *) data;
    xml = glade_get_widget_tree(widget);
    combo = GTK_COMBO_BOX(glade_xml_get_widget(xml, "cmb_presets"));
    lst = GTK_TREE_MODEL(gtk_combo_box_get_model(combo));
    if (gtk_combo_box_get_active_iter(combo, &iter)) {
        GValue name, builtin_p, builtin_id;
        const gchar *nm;
        gboolean builtin;
        gint id;
        memset(&name, 0, sizeof(GValue));
        memset(&builtin_p, 0, sizeof(GValue));
        memset(&builtin_id, 0, sizeof(GValue));
        gtk_tree_model_get_value(lst, &iter, 0, &name);
        gtk_tree_model_get_value(lst, &iter, 1, &builtin_p);
        gtk_tree_model_get_value(lst, &iter, 2, &builtin_id);
        nm = g_value_get_string(&name);
        builtin = g_value_get_boolean(&builtin_p);
        if (builtin) {
            id = g_value_get_int(&builtin_id);
            apply_preset_to_sign_dlg(GTK_DIALOG
                                     (glade_xml_get_widget(xml, "signDialog")),
                                     get_builtin_signopt(id));
        }
        else {
            LMZ_SIGN_OPT opt;
            lmz_ca_get_signopt(fe->db, nm, &opt);
            apply_preset_to_sign_dlg(GTK_DIALOG
                                     (glade_xml_get_widget(xml, "signDialog")),
                                     &opt);
        }

        g_value_unset(&name);
        g_value_unset(&builtin_p);
        g_value_unset(&builtin_id);
    }
}
static void do_save_preset(GtkWidget * widget, gpointer data) {
    LMZ_SIGN_OPT opts;
    GladeXML *xml;
    FRONTEND *fe = (FRONTEND *) data;
    gchar *name;
    GtkTreeIter iter;
    GtkComboBox *combo;
    GtkTreeModel *lst;

    xml = glade_get_widget_tree(widget);
    make_preset_from_sign_dlg(GTK_DIALOG
                              (glade_xml_get_widget(xml, "signDialog")), &opts);
    combo = GTK_COMBO_BOX(glade_xml_get_widget(xml, "cmb_presets"));
    lst = GTK_TREE_MODEL(gtk_combo_box_get_model(combo));

    /* get name - defaulting to current selected preset */
    if (gtk_combo_box_get_active_iter(combo, &iter)) {
        GValue name_value;
        const gchar *default_name;
        memset(&name_value, 0, sizeof(GValue));
        gtk_tree_model_get_value(lst, &iter, 0, &name_value);
        default_name = g_value_get_string(&name_value);
        name =
            get_signopt_name(GTK_WINDOW
                             (glade_xml_get_widget(xml, "signDialog")),
                             default_name);
        g_value_unset(&name_value);
    }
    else {
        name =
            get_signopt_name(GTK_WINDOW
                             (glade_xml_get_widget(xml, "signDialog")), NULL);
    }
    if (name != NULL) {
        int status = lmz_ca_save_signopt(fe->db, name, &opts);
        if (!cryptStatusOK(status)) {
            show_error_dialog(GTK_WINDOW
                              (glade_xml_get_widget(xml, "signDialog")),
                              "Error saving preset: cryptlib error %d", status);
        }
        else {
            do_update_signopt_model(fe, combo, name);
        }
        g_free(name);
    }
    else {
    }
}
static void do_delete_preset(GtkWidget * widget, gpointer data) {
    GladeXML *xml;
    FRONTEND *fe = (FRONTEND *) data;
    GtkTreeIter iter;
    GtkComboBox *combo;
    GtkTreeModel *lst;

    xml = glade_get_widget_tree(widget);
    combo = GTK_COMBO_BOX(glade_xml_get_widget(xml, "cmb_presets"));
    lst = GTK_TREE_MODEL(gtk_combo_box_get_model(combo));

    if (gtk_combo_box_get_active_iter(combo, &iter)) {
        GValue name_value, builtin_value;
        memset(&name_value, 0, sizeof(GValue));
        memset(&builtin_value, 0, sizeof(GValue));
        gtk_tree_model_get_value(lst, &iter, 0, &name_value);
        gtk_tree_model_get_value(lst, &iter, 1, &builtin_value);
        if (g_value_get_boolean(&builtin_value)) {
            show_error_dialog(GTK_WINDOW
                              (glade_xml_get_widget(xml, "signDialog")),
                              "Cannot delete a builtin preset");
        }
        else {
            int status =
                lmz_ca_delete_signopt(fe->db, g_value_get_string(&name_value));
            if (!cryptStatusOK(status)) {
                show_error_dialog(GTK_WINDOW
                                  (glade_xml_get_widget(xml, "signDialog")),
                                  "Error deleting preset: cryptlib error %d",
                                  status);
            }
            else {
                do_update_signopt_model(fe, combo, NULL);
            }
        }
        g_value_unset(&name_value);
        g_value_unset(&builtin_value);
    }
    else {
        show_error_dialog(GTK_WINDOW(glade_xml_get_widget(xml, "signDialog")),
                          "Please select a preset first");
    }
}

static void apply_preset_to_sign_dlg(GtkDialog * dlg,
                                     const PLMZ_SIGN_OPT sign_opt) {
    const char *names[] =
        { "cb_eku_svr", "cb_eku_cli", "cb_eku_cs", "cb_eku_ep", "cb_eku_ts",
        NULL
    };
    const char **tmp;
    int i;
    GladeXML *xml = glade_get_widget_tree(GTK_WIDGET(dlg));

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_ka")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_KEYAGREEMENT));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_nr")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_NONREPUDIATION));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_eo")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_ENCIPHERONLY));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_ke")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_KEYENCIPHERMENT));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_do")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_DECIPHERONLY));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_de")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_DATAENCIPHERMENT));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                 (glade_xml_get_widget(xml, "cb_ku_ds")),
                                 (sign_opt->ku_bits &
                                  CRYPT_KEYUSAGE_DIGITALSIGNATURE));

    /* turn off all eku checkboxes, then turn on selectively */
    for (tmp = names; *tmp != NULL; tmp++) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                     (glade_xml_get_widget(xml, *tmp)), FALSE);
    }
    for (i = 0; i < sign_opt->eku_num; i++) {
        switch (sign_opt->eku_flags[i]) {
        case CRYPT_CERTINFO_EXTKEY_SERVERAUTH:
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_svr")), TRUE);
            break;
        case CRYPT_CERTINFO_EXTKEY_CLIENTAUTH:
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_cli")), TRUE);
            break;
        case CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION:
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_ep")), TRUE);
            break;
        case CRYPT_CERTINFO_EXTKEY_CODESIGNING:
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_cs")), TRUE);
            break;
        case CRYPT_CERTINFO_EXTKEY_TIMESTAMPING:
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "cb_eku_ts")), TRUE);
            break;
        default:
            break;
        }
    }
    gtk_spin_button_set_value(GTK_SPIN_BUTTON
                              (glade_xml_get_widget(xml, "sb_valid_days")),
                              sign_opt->valid_days);
}

static void make_preset_from_sign_dlg(GtkDialog * dlg, PLMZ_SIGN_OPT sign_opt) {
    int num_eku = 0;
    GladeXML *xml = glade_get_widget_tree(GTK_WIDGET(dlg));

    /* turn on the ku bits based on the checkboxes */
    sign_opt->ku_bits = 0;
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_ka")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_KEYAGREEMENT;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_nr")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_NONREPUDIATION;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_eo")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_ENCIPHERONLY;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_ke")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_KEYENCIPHERMENT;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_do")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_DECIPHERONLY;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_de")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_DATAENCIPHERMENT;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_ku_ds")))) {
        sign_opt->ku_bits = sign_opt->ku_bits | CRYPT_KEYUSAGE_DIGITALSIGNATURE;
    }
    /* add eku */
    num_eku = 0;
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_eku_svr")))) {
        sign_opt->eku_flags[num_eku++] = CRYPT_CERTINFO_EXTKEY_SERVERAUTH;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_eku_cli")))) {
        sign_opt->eku_flags[num_eku++] = CRYPT_CERTINFO_EXTKEY_CLIENTAUTH;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_eku_cs")))) {
        sign_opt->eku_flags[num_eku++] = CRYPT_CERTINFO_EXTKEY_CODESIGNING;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_eku_ep")))) {
        sign_opt->eku_flags[num_eku++] = CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION;
    }
    if (gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "cb_eku_ts")))) {
        sign_opt->eku_flags[num_eku++] = CRYPT_CERTINFO_EXTKEY_TIMESTAMPING;
    }
    sign_opt->eku_num = num_eku;
    sign_opt->valid_days =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON
                                         (glade_xml_get_widget
                                          (xml, "sb_valid_days")));
}

static gchar *get_signopt_name(GtkWindow * parentWindow,
                               const char *default_name) {
    GtkDialog *dialog;
    GtkEntry *entry;
    gchar *result;

    dialog =
        GTK_DIALOG(gtk_dialog_new_with_buttons
                   ("Enter a name", parentWindow, GTK_DIALOG_MODAL,
                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, GTK_STOCK_SAVE,
                    GTK_RESPONSE_ACCEPT, NULL));
    entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_max_length(entry, 50);
    gtk_entry_set_text(entry, default_name);
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_box_pack_start(GTK_BOX(dialog->vbox), GTK_WIDGET(entry), TRUE, TRUE, 5);
    gtk_widget_show(GTK_WIDGET(entry));
    {
        gint dlgresult = gtk_dialog_run(dialog);
        if (dlgresult == GTK_RESPONSE_ACCEPT) {
            result = g_strdup(gtk_entry_get_text(entry));
            g_strstrip(result);
        }
        else {
            result = NULL;
        }
    }
    gtk_widget_destroy(GTK_WIDGET(dialog));
    return result;
}

static void do_update_signopt_model(FRONTEND * fe, GtkComboBox * combo,
                                    const gchar * new_selection) {
    GtkTreeModel *model = GTK_TREE_MODEL(make_signopt_list_model(fe));
    gtk_combo_box_set_model(combo, model);      /* old one unref'd */
    if (new_selection != NULL) {
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter_first(model, &iter)) {
            do {
                GValue name_value;
                memset(&name_value, 0, sizeof(GValue));
                gtk_tree_model_get_value(model, &iter, 0, &name_value);
                if (strcmp(g_value_get_string(&name_value), new_selection) == 0) {
                    /* found it */
                    gtk_combo_box_set_active_iter(combo, &iter);
                    g_value_unset(&name_value);
                    return;
                }
                g_value_unset(&name_value);
            } while (gtk_tree_model_iter_next(model, &iter));
        }
    }
}
/* vim: set sw=4 et: */
