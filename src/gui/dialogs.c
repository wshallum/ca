/* Generic GUI dialogs: get password, error dialog, about box
 */
#include <gtk/gtk.h>
#include "auto_config.h"

char *do_get_password(GtkWindow * parent_window) {
    GtkDialog *dialog;
    GtkEntry *pw_entry;
    gchar *result;

    dialog =
        GTK_DIALOG(gtk_dialog_new_with_buttons
                   ("Enter Password", parent_window, GTK_DIALOG_MODAL,
                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, GTK_STOCK_OK,
                    GTK_RESPONSE_ACCEPT, NULL));
    pw_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_visibility(pw_entry, FALSE);
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_box_pack_start(GTK_BOX(dialog->vbox),
                       gtk_label_new("Enter the signing password"), TRUE, TRUE,
                       5);
    gtk_box_pack_start(GTK_BOX(dialog->vbox), GTK_WIDGET(pw_entry), TRUE, TRUE,
                       5);
    gtk_widget_show_all(GTK_WIDGET(dialog->vbox));
    {
        gint dlgresult = gtk_dialog_run(dialog);
        if (dlgresult == GTK_RESPONSE_ACCEPT) {
            result = g_strdup(gtk_entry_get_text(pw_entry));
        }
        else {
            result = NULL;
        }
    }
    gtk_widget_destroy(GTK_WIDGET(dialog));
    return result;
}

void show_error_dialog(GtkWindow * parent, gchar * format, ...) {
    va_list ap;
    gchar *fmt_message;
    GtkWidget *msg;

    va_start(ap, format);
    fmt_message = g_strdup_vprintf(format, ap);
    msg = gtk_message_dialog_new(parent,
                                 GTK_DIALOG_MODAL |
                                 GTK_DIALOG_DESTROY_WITH_PARENT,
                                 GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s",
                                 fmt_message);
    gtk_dialog_run(GTK_DIALOG(msg));
    gtk_widget_destroy(msg);
    g_free(fmt_message);
    va_end(ap);
}

void show_about_dialog(GtkWindow * parent) {
    GtkAboutDialog *dlg;
    const char *authors[] = { "William Shallum", NULL };
    dlg = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_about_dialog_set_version(dlg, PACKAGE_VERSION);
    gtk_about_dialog_set_copyright(dlg, "Copyright 2007, 2015 William Shallum");
    gtk_about_dialog_set_authors(dlg, authors);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(GTK_WIDGET(dlg));
}
/* vim: set sw=4 et: */
