/* GUI dialog: import certificate request
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gtk/gtk.h>
#include "frontend.h"

static void on_browse_button_clicked(GtkWidget * widget, gpointer data) {
    GtkWidget *file_chooser;
    GtkFileFilter *filter;
    /* Create the selector */

    file_chooser = gtk_file_chooser_dialog_new("Import Certificate Request",
                                               GTK_WINDOW(data),
                                               GTK_FILE_CHOOSER_ACTION_OPEN,
                                               GTK_STOCK_CANCEL,
                                               GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_OPEN,
                                               GTK_RESPONSE_ACCEPT, NULL);
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_filter_set_name(filter, "All files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    filter = NULL;

    /* Display that dialog */
    {
        gint result = gtk_dialog_run(GTK_DIALOG(file_chooser));
        if (result == GTK_RESPONSE_ACCEPT) {
            gchar *filename, *utf_filename;
            filename =
                gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
            utf_filename = g_filename_to_utf8(filename, -1, NULL, NULL, NULL);
            g_free(filename);
            gtk_entry_set_text(GTK_ENTRY
                               (g_object_get_data(G_OBJECT(widget), "entry")),
                               utf_filename);
            g_free(utf_filename);
            gtk_widget_destroy(file_chooser);
        }
        else {
            gtk_widget_destroy(file_chooser);
        }
    }
}

void show_import_request_dialog(FRONTEND * fe) {
    /* import dialog -> dialog (OK, cancel), filename entry & browse */
    GtkWidget *dlg;
    GtkEntry *filename_entry;
    GtkButton *browse_button;
    GtkBox *box;
    int status;
    gint result;

    dlg =
        gtk_dialog_new_with_buttons("Import Request",
                                    GTK_WINDOW(fe->mainWindow),
                                    GTK_DIALOG_MODAL |
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                                    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    box = GTK_BOX(gtk_hbox_new(0, 5));

    gtk_box_pack_start(box, gtk_label_new("Import from"), FALSE, FALSE, 0);
    filename_entry = GTK_ENTRY(gtk_entry_new());
    gtk_box_pack_start(box, GTK_WIDGET(filename_entry), FALSE, FALSE, 0);
    browse_button = GTK_BUTTON(gtk_button_new_with_mnemonic("_Browse..."));
    gtk_box_pack_start(box, GTK_WIDGET(browse_button), FALSE, FALSE, 0);
    g_signal_connect(G_OBJECT(browse_button), "clicked",
                     G_CALLBACK(on_browse_button_clicked), dlg);
    g_object_set_data_full(G_OBJECT(browse_button), "entry", filename_entry, NULL);     /* don't ref the entry -- same lifetime */
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box), FALSE,
                       FALSE, 0);

    gtk_widget_show_all(GTK_WIDGET(GTK_DIALOG(dlg)->vbox));
    result = gtk_dialog_run(GTK_DIALOG(dlg));
    if (result == GTK_RESPONSE_ACCEPT) {
        CRYPT_CERTIFICATE request;
        gchar *filename;

        filename =
            g_filename_from_utf8(gtk_entry_get_text(filename_entry), -1, NULL,
                                 NULL, NULL);
        if (filename != NULL) {
            void *data;
            int data_len;
            data = lmz_file_read_full(filename, &data_len);
            if (data != NULL) {
                status =
                    cryptImportCert(data, data_len, CRYPT_UNUSED, &request);
                if (cryptStatusOK(status)) {
                    int id;
                    status = lmz_ca_add_request(fe->db, request, &id);
                    if (!cryptStatusOK(status)) {
                        show_error_dialog(NULL,
                                          "error adding request to db (cl err %d)",
                                          status);
                    }
                    else {
                        /* yay, it worked */
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
                    cryptDestroyCert(request);
                }
                else {
                    show_error_dialog(NULL,
                                      "error importing request (cl err %d)",
                                      status);
                }
                free(data);
            }
            else {
                show_error_dialog(NULL, "error reading file");
            }
            g_free(filename);
        }
        else {
        }
    }
    gtk_widget_destroy(dlg);
}
/* vim: set sw=4 et: */
