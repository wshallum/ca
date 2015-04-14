/* GUI dialog: export CRL
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "frontend.h"


static void on_browse_button_clicked(GtkWidget * widget, gpointer data) {
    GtkWidget *file_chooser;
    GtkFileFilter *filter;
    /* Create the selector */

    file_chooser = gtk_file_chooser_dialog_new("Choose exported CRL filename",
                                               GTK_WINDOW(data),
                                               GTK_FILE_CHOOSER_ACTION_SAVE,
                                               GTK_STOCK_CANCEL,
                                               GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_SAVE,
                                               GTK_RESPONSE_ACCEPT, NULL);
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*.crl");
    gtk_file_filter_set_name(filter, "*.crl files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    filter = NULL;
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_filter_set_name(filter, "All files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    filter = NULL;

    /* Display that dialog */
    {
        gint result = gtk_dialog_run(GTK_DIALOG(file_chooser));
        if (result == GTK_RESPONSE_ACCEPT) {
            gchar *filename;
            filename =
                gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
            gtk_entry_set_text(GTK_ENTRY
                               (g_object_get_data(G_OBJECT(widget), "entry")),
                               filename);
            gtk_widget_destroy(file_chooser);
            g_free(filename);
        }
        else {
            gtk_widget_destroy(file_chooser);
        }
    }
}

void show_export_crl_dialog(FRONTEND * fe) {
    /* export dialog -> 
     * dialog (OK, cancel), 
     * filename entry & browse, 
     * format choice (DER, text)
     */
    GtkWidget *dlg;
    GtkEntry *filename_entry;
    GtkButton *browse_button;
    GtkRadioButton *rb_text, *rb_der;
    GtkBox *box;
    gint result;

    dlg =
        gtk_dialog_new_with_buttons("Export CRL", GTK_WINDOW(fe->mainWindow),
                                    GTK_DIALOG_MODAL |
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                                    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    box = GTK_BOX(gtk_hbox_new(0, 5));

    gtk_box_pack_start(box, gtk_label_new("Export to"), FALSE, FALSE, 0);
    filename_entry = GTK_ENTRY(gtk_entry_new());
    gtk_box_pack_start(box, GTK_WIDGET(filename_entry), FALSE, FALSE, 0);
    browse_button = GTK_BUTTON(gtk_button_new_with_mnemonic("_Browse..."));
    gtk_box_pack_start(box, GTK_WIDGET(browse_button), FALSE, FALSE, 0);
    g_signal_connect(G_OBJECT(browse_button), "clicked",
                     G_CALLBACK(on_browse_button_clicked), dlg);
    /* don't ref the entry -- same lifetime */
    g_object_set_data_full(G_OBJECT(browse_button), "entry", filename_entry, NULL);     
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box), FALSE,
                       FALSE, 0);

    rb_der =
        GTK_RADIO_BUTTON(gtk_radio_button_new_with_mnemonic
                         (NULL, "_DER (Binary)"));
    rb_text =
        GTK_RADIO_BUTTON(gtk_radio_button_new_with_mnemonic_from_widget
                         (rb_der, "_PEM (Text)"));
    box = GTK_BOX(gtk_hbox_new(0, 5));
    gtk_box_pack_start(box, gtk_label_new("Format:"), FALSE, FALSE, 0);
    gtk_box_pack_start(box, GTK_WIDGET(rb_der), FALSE, FALSE, 0);
    gtk_box_pack_start(box, GTK_WIDGET(rb_text), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box), FALSE,
                       FALSE, 0);

    gtk_widget_show_all(GTK_WIDGET(GTK_DIALOG(dlg)->vbox));
    result = gtk_dialog_run(GTK_DIALOG(dlg));
    if (result == GTK_RESPONSE_ACCEPT) {
        void *buf;
        int status;
        int len;
        gboolean text_format;
        CRYPT_CERTFORMAT_TYPE fmt;
        FILE *f;
        gchar *filename;
        CRYPT_CERTIFICATE crl;
        CRYPT_CONTEXT key;
        gchar *password;
        /* get password */
        password = do_get_password(GTK_WINDOW(dlg));
        if (password == NULL) {
            /* cancelled? */
            goto cleanup;
        }
        /* sign */
        status = lmz_ca_get_signing_key(fe->db, password, &key);
        g_free(password); /* dynamic */
        if (status == CRYPT_ERROR_WRONGKEY) {
            show_error_dialog(GTK_WINDOW(dlg), "Wrong password");
            goto cleanup;
        }
        else if (!cryptStatusOK(status)) {
            show_error_dialog(GTK_WINDOW(dlg),
                              "Error getting signing key (cryptlib error %d)",
                              status);
            goto cleanup;
        }
        status = lmz_ca_gen_crl(fe->db, &crl);
        if (cryptStatusOK(status)) {
            /* sign it */
            status = cryptSignCert(crl, key);
            if (cryptStatusOK(status)) {
                text_format =
                    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb_text));
                fmt =
                    text_format ? CRYPT_CERTFORMAT_TEXT_CERTIFICATE :
                    CRYPT_CERTFORMAT_CERTIFICATE;
                status = cryptExportCert(NULL, 0, &len, fmt, crl);
                buf = malloc(len);
                status = cryptExportCert(buf, len, &len, fmt, crl);
                if (cryptStatusOK(status)) {
                    filename =
                        g_filename_from_utf8(gtk_entry_get_text(filename_entry),
                                             -1, NULL, NULL, NULL);
                    if (filename != NULL) {
                        f = fopen(filename, "w");
                        if (f != NULL) {
                            if (fwrite(buf, len, 1, f) != 1) {
                                show_error_dialog(NULL,
                                                  "error fully writing data");
                            }
                            fclose(f);
                        }
                        else {
                            show_error_dialog(NULL,
                                              "error opening file for writing");
                        }
                        g_free(filename);
                    }
                    else {
                        show_error_dialog(NULL, "filename conversion error");
                    }
                    free(buf);
                }
            }
            else {
                show_error_dialog(NULL, "error signing crl (cl error %d)",
                                  status);
            }
            cryptDestroyCert(crl);
        }
        else {
            show_error_dialog(NULL, "error generating crl (cl error %d)",
                              status);
        }
        cryptDestroyContext(key);
    }
  cleanup:
    gtk_widget_destroy(dlg);
}
/* vim: set sw=4 et: */
