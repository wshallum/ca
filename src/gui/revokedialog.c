/* GUI dialog: revoke certificate
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include "cryptlib.h"
#include "frontend.h"

void show_revoke_dialog(FRONTEND * fe, int cert_id) {
    GladeXML *xml;
    GtkWidget *dlg;
    int status;
    int reason;


    /* load revoke dlg */

    xml = glade_xml_new(LMZ_UI_ROOT "/revoke.glade", NULL, NULL);
    dlg = glade_xml_get_widget(xml, "revokeDialog");
    gtk_window_set_modal(GTK_WINDOW(dlg), TRUE);
    {
        gint result = gtk_dialog_run(GTK_DIALOG(dlg));
        if (result == GTK_RESPONSE_OK) {
            gchar *password;
            /* get correct flag */
            if (gtk_toggle_button_get_active
                (GTK_TOGGLE_BUTTON
                 (glade_xml_get_widget(xml, "rb_unspecified")))) {
                reason = CRYPT_CRLREASON_UNSPECIFIED;
            }
            else if (gtk_toggle_button_get_active
                     (GTK_TOGGLE_BUTTON
                      (glade_xml_get_widget(xml, "rb_superseded")))) {
                reason = CRYPT_CRLREASON_SUPERSEDED;
            }
            else if (gtk_toggle_button_get_active
                     (GTK_TOGGLE_BUTTON
                      (glade_xml_get_widget(xml, "rb_affiliationchanged")))) {
                reason = CRYPT_CRLREASON_AFFILIATIONCHANGED;
            }
            else if (gtk_toggle_button_get_active
                     (GTK_TOGGLE_BUTTON
                      (glade_xml_get_widget(xml, "rb_cessationofoperation")))) {
                reason = CRYPT_CRLREASON_CESSATIONOFOPERATION;
            }
            else if (gtk_toggle_button_get_active
                     (GTK_TOGGLE_BUTTON
                      (glade_xml_get_widget(xml, "rb_keycompromise")))) {
                reason = CRYPT_CRLREASON_KEYCOMPROMISE;
            }
            else if (gtk_toggle_button_get_active
                     (GTK_TOGGLE_BUTTON
                      (glade_xml_get_widget(xml, "rb_cacompromise")))) {
                reason = CRYPT_CRLREASON_CACOMPROMISE;
            }
            else {              /* o rly ? */
                reason = CRYPT_CRLREASON_UNSPECIFIED;
            }
            /* get password */
            password = do_get_password(GTK_WINDOW(dlg));
            if (password != NULL) {
                CRYPT_CONTEXT key;
                /* sign revocation */
                status = lmz_ca_get_signing_key(fe->db, password, &key);
                g_free(password);       /* dynamic */
                if (status == CRYPT_ERROR_WRONGKEY) {
                    show_error_dialog(GTK_WINDOW(dlg), "Wrong password");
                    goto cleanup;
                }
                else if (!cryptStatusOK(status)) {
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error while getting key (CL error %d)",
                                      status);
                }
                status = lmz_ca_revoke_cert(fe->db, cert_id, reason, key);
                if (!cryptStatusOK(status)) {
                    show_error_dialog(GTK_WINDOW(dlg),
                                      "Error while revoking (CL error %d)",
                                      status);
                }
                cryptDestroyContext(key);
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
        else {
        }
    }
  cleanup:
    gtk_widget_destroy(GTK_WIDGET(dlg));
    g_object_unref(xml);
}
/* vim: set sw=4 et: */
