/* GUI dialog: renew certificate
 */
#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>
#include "frontend.h"

void show_renew_dialog(FRONTEND * fe, int cert_id) {
    /* renew dialog -> dialog (OK, cancel) & valid days spin */
    GtkWidget *dlg;
    GtkSpinButton *spin;
    GtkBox *box;
    int status;
    gint result;
    dlg =
        gtk_dialog_new_with_buttons("Renew Certificate (same key)",
                                    GTK_WINDOW(fe->mainWindow),
                                    GTK_DIALOG_MODAL |
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                                    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    box = GTK_BOX(gtk_hbox_new(0, 5));
    gtk_box_pack_start(box, gtk_label_new("Valid for"), FALSE, FALSE, 0);
    spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(180, 3650, 30));
    gtk_spin_button_set_digits(spin, 0);
    gtk_spin_button_set_increments(spin, 1, 10);
    gtk_spin_button_set_numeric(spin, TRUE);
    gtk_spin_button_set_snap_to_ticks(spin, TRUE);
    gtk_box_pack_start(box, GTK_WIDGET(spin), FALSE, FALSE, 0);
    gtk_box_pack_start(box, gtk_label_new("days"), FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dlg)->vbox), GTK_WIDGET(box));
    gtk_widget_show_all(GTK_WIDGET(box));
    result = gtk_dialog_run(GTK_DIALOG(dlg));
    if (result == GTK_RESPONSE_ACCEPT) {
        GtkTreeView *mainwin_req_tv, *mainwin_cert_tv;
        CRYPT_CONTEXT key;
        gchar *password;
        int valid_days;
        valid_days = gtk_spin_button_get_value_as_int(spin);
        /* get password */
        password = do_get_password(GTK_WINDOW(dlg));
        if (password == NULL) {
            goto cleanup;
        }
        /* get key */
        status = lmz_ca_get_signing_key(fe->db, password, &key);
        g_free(password);       /* dynamic */
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
        status = lmz_ca_renew_cert(fe->db, cert_id, valid_days, key);
        if (!cryptStatusOK(status)) {
            show_error_dialog(GTK_WINDOW(dlg),
                              "Error renewing (cryptlib error %d)", status);
            cryptDestroyContext(key);
            goto cleanup;
        }
        cryptDestroyContext(key);
        mainwin_req_tv =
            GTK_TREE_VIEW(g_object_get_data
                          (G_OBJECT(fe->mainWindow), "request-list"));
        mainwin_cert_tv =
            GTK_TREE_VIEW(g_object_get_data
                          (G_OBJECT(fe->mainWindow), "certificate-list"));
        refresh_request_tree_view(mainwin_req_tv, fe);
        refresh_cert_tree_view(mainwin_cert_tv, fe);
    }
    else {
        /* not accepted */
    }
  cleanup:
    gtk_widget_destroy(dlg);
}
/* vim: set sw=4 et: */
