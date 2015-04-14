/* GUI dialog: choose / create new CA database
 */
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <stdio.h>
#include "frontend.h"

static void on_selectDBcancelButton_clicked(GtkWidget * widget, gpointer data) {
    gtk_main_quit();
}

static void show_appwindow(FRONTEND * fe, const gchar * fn) {
    GtkWidget *w = make_appwindow(fe, fn);
    if (fe->chooseDbWindow != NULL) {
        gtk_widget_hide(fe->chooseDbWindow);
    }
    gtk_window_set_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
    gtk_widget_show_all(w);
}

static gchar *select_ca_from_list(GtkWindow * parentWindow, char **names) {
    GtkDialog *dialog;
    GtkComboBox *combo;
    char **temp;
    gchar *result;

    dialog =
        GTK_DIALOG(gtk_dialog_new_with_buttons
                   ("Select a CA", parentWindow, GTK_DIALOG_MODAL,
                    GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, GTK_STOCK_OPEN,
                    GTK_RESPONSE_ACCEPT, NULL));
    combo = GTK_COMBO_BOX(gtk_combo_box_new_text());
    temp = names;
    for (; *temp != NULL; temp++) {
        gtk_combo_box_append_text(combo, *temp);
    }
    gtk_combo_box_set_active(combo, 0);
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_box_pack_start(GTK_BOX(dialog->vbox), GTK_WIDGET(combo), TRUE, TRUE, 5);
    gtk_widget_show(GTK_WIDGET(combo));
    {
        gint dlgresult = gtk_dialog_run(dialog);
        if (dlgresult == GTK_RESPONSE_ACCEPT) {
            result = gtk_combo_box_get_active_text(combo);
        }
        else {
            result = NULL;
        }
    }
    gtk_widget_destroy(GTK_WIDGET(dialog));
    return result;
}

static void on_browseNewButton_clicked(GtkWidget * widget, gpointer data) {
    GtkWidget *file_chooser;
    GtkFileFilter *filter;
    /* Create the selector */

    file_chooser = gtk_file_chooser_dialog_new("Choose the new database name",
                                               GTK_WINDOW(((FRONTEND *)
                                                           data)->chooseDbWindow),
                                               GTK_FILE_CHOOSER_ACTION_SAVE,
                                               GTK_STOCK_CANCEL,
                                               GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_OPEN,
                                               GTK_RESPONSE_ACCEPT, NULL);
    /* adding filters to chooser transfers ownership 
     * so we do not need to unref */
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*.db");
    gtk_file_filter_set_name(filter, "*.db files");
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
            gtk_widget_destroy(file_chooser);
            do_new_ca((FRONTEND *) data, filename);
            g_free(filename);
        }
        else {
            gtk_widget_destroy(file_chooser);
        }
    }
}

static void on_browseExistingButton_clicked(GtkWidget * widget, gpointer data) {
    GtkWidget *file_chooser;
    GtkFileFilter *filter;
    gint result;
    int do_show = 0;
    /* Create the selector */

    file_chooser = gtk_file_chooser_dialog_new("Select an existing database",
                                               GTK_WINDOW(((FRONTEND *)
                                                           data)->chooseDbWindow),
                                               GTK_FILE_CHOOSER_ACTION_OPEN,
                                               GTK_STOCK_CANCEL,
                                               GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_OPEN,
                                               GTK_RESPONSE_ACCEPT, NULL);
    /* adding filters to chooser transfers ownership 
     * so we do not need to unref */
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*.db");
    gtk_file_filter_set_name(filter, "*.db files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    filter = NULL;
    filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_filter_set_name(filter, "All files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    filter = NULL;

    /* Display that dialog */

    result = gtk_dialog_run(GTK_DIALOG(file_chooser));
    if (result == GTK_RESPONSE_ACCEPT) {
        gchar *filename;
        PLMZ_CA_DB db;
        int status;
        int err;
        char **names;
        filename =
            gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
        err = lmz_ca_get_existing_names(filename, &names);
        if (err == SQLITE_OK) {
            gchar *selected_ca;
            selected_ca =
                select_ca_from_list(GTK_WINDOW
                                    (((FRONTEND *) data)->chooseDbWindow),
                                    names);
            lmz_ca_free_names(names);
            if (selected_ca != NULL) {
                status = lmz_ca_open(&db, filename, selected_ca);
                g_free(selected_ca);
                if (db == NULL) {
                    fprintf(stderr, "Error opening db (%s) -> status %d\n",
                            filename, status);
                }
                else {
                    ((FRONTEND *) data)->db = db;
                    do_show = 1;
                }
            }
        }
        else {
            fprintf(stderr, "Error getting names (%s) -> status %d\n", filename,
                    err);
        }
        gtk_widget_destroy(file_chooser);
        if (do_show)
            show_appwindow((FRONTEND *) data, filename);
        g_free(filename);
    }
    else {
        gtk_widget_destroy(file_chooser);
    }
}

static void on_createButton_clicked(GtkWidget * widget, gpointer data) {
    GladeXML *xml;
    const gchar *filename;
    gchar *native_fn;
    gsize bytes_read, bytes_written;

    xml = glade_get_widget_tree(widget);
    filename =
        gtk_entry_get_text(GTK_ENTRY(glade_xml_get_widget(xml, "newDbEntry")));
    native_fn =
        g_filename_from_utf8(filename, -1, &bytes_read, &bytes_written, NULL);
    do_new_ca((FRONTEND *) data, native_fn);
    g_free(native_fn);
}

gboolean do_open_db_file(FRONTEND * fe, char *filename) {
    int err, status;
    PLMZ_CA_DB db;
    GtkWindow *parent;
    char **names;
    gboolean retval = TRUE;

    if (fe->chooseDbWindow != NULL) {
        parent = GTK_WINDOW(fe->chooseDbWindow);
    }
    else {
        parent = NULL;
    }
    err = lmz_ca_get_existing_names(filename, &names);
    if (err == SQLITE_OK) {
        gchar *selected_ca;
        selected_ca = select_ca_from_list(parent, names);
        lmz_ca_free_names(names);
        if (selected_ca != NULL) {
            status = lmz_ca_open(&db, filename, selected_ca);
            g_free(selected_ca);
            if (db == NULL) {
                show_error_dialog(parent, "Error opening db -> status %d\n",
                                  status);
                retval = FALSE;
            }
            else {
                fe->db = db;
                show_appwindow(fe, filename);
                g_free(filename);
            }
        }
    }
    else {
        if (err == SQLITE_NOTFOUND) {
            show_error_dialog(parent,
                              "File not found (error while getting names -- SQLite error %d)\n",
                              err);
        }
        else if (err == SQLITE_NOTADB) {
            show_error_dialog(parent,
                              "File is not a database (error while getting names -- SQLite error %d)\n",
                              err);
        }
        else {
            show_error_dialog(parent,
                              "Error while getting names -- SQLite error %d\n",
                              err);
        }
        retval = FALSE;
    }
    return retval;
}

static void on_openButton_clicked(GtkWidget * widget, gpointer data) {
    const gchar *filename;
    GladeXML *xml;
    gchar *native_fn;
    gsize bytes_read, bytes_written;

    xml = glade_get_widget_tree(widget);
    filename =
        gtk_entry_get_text(GTK_ENTRY
                           (glade_xml_get_widget(xml, "existingDbEntry")));
    native_fn =
        g_filename_from_utf8(filename, -1, &bytes_read, &bytes_written, NULL);
    do_open_db_file((FRONTEND *) data, native_fn);
    /* show_appwindow((FRONTEND *)data); */
}

gboolean do_new_ca(FRONTEND * fe, const char *filename) {
    int err;
    char **names = NULL;
    GtkWindow *parent;
    gboolean retval = TRUE;
    if (fe->chooseDbWindow != NULL) {
        parent = GTK_WINDOW(fe->chooseDbWindow);
    }
    else {
        parent = NULL;
    }
    /* check whether it exists -- if it exists make sure it's a DB
       by fetching the list of existing names (we need it for confirmation) */
    err = lmz_ca_get_existing_names(filename, &names);
    if (err == SQLITE_NOTADB) {
        show_error_dialog(parent,
                          "File %s exists, but it is not a database file",
                          filename);
        return FALSE;
    }
    else if (err == SQLITE_NOTFOUND) {
        /* do nothing */
        names = NULL;
    }
    else if (err != SQLITE_OK) {
        show_error_dialog(parent,
                          "Failed getting existing CA names (sqlite3 err %d)",
                          err);
        retval = FALSE;
        return retval;
    }
    if (show_ca_dialog(fe, filename)) {
        if (names != NULL)
            lmz_ca_free_names(names);
        show_appwindow(fe, filename);
        retval = TRUE;
    }
    else {
        if (names != NULL)
            lmz_ca_free_names(names);
        retval = FALSE;
    }
    return retval;
}

static void on_openExistingRadio_toggled(GtkToggleButton * widget,
                                         gpointer data) {
    if (gtk_toggle_button_get_active(widget)) {
        GladeXML *tree;
        GtkWidget *buttonbox, *entry;
        tree = glade_get_widget_tree(GTK_WIDGET(widget));       /* not a new ref */
        buttonbox = glade_xml_get_widget(tree, "existingButtonBox");    /* not a new ref */
        gtk_widget_set_sensitive(buttonbox, TRUE);
        buttonbox = glade_xml_get_widget(tree, "newButtonBox"); /* not a new ref */
        gtk_widget_set_sensitive(buttonbox, FALSE);
        entry = glade_xml_get_widget(tree, "newDbEntry");
        gtk_widget_set_sensitive(entry, FALSE);
        entry = glade_xml_get_widget(tree, "existingDbEntry");
        gtk_widget_set_sensitive(entry, TRUE);
    }
}

static void on_createNewRadio_toggled(GtkToggleButton * widget, gpointer data) {
    if (gtk_toggle_button_get_active(widget)) {
        GladeXML *tree;
        GtkWidget *buttonbox, *entry;
        tree = glade_get_widget_tree(GTK_WIDGET(widget));       /* not a new ref */
        buttonbox = glade_xml_get_widget(tree, "existingButtonBox");    /* not a new ref */
        gtk_widget_set_sensitive(buttonbox, FALSE);
        buttonbox = glade_xml_get_widget(tree, "newButtonBox"); /* not a new ref */
        gtk_widget_set_sensitive(buttonbox, TRUE);
        entry = glade_xml_get_widget(tree, "newDbEntry");
        gtk_widget_set_sensitive(entry, TRUE);
        entry = glade_xml_get_widget(tree, "existingDbEntry");
        gtk_widget_set_sensitive(entry, FALSE);
    }
}

static void on_choosedb_window_destroyed(GtkWidget * widget, gpointer data) {
    gtk_main_quit();
}

GtkWidget *lmz_fe_create_choose_db_window(FRONTEND * fe) {
    GladeXML *xml;
    GtkWidget *chooseDbWindow;

    xml = glade_xml_new(LMZ_UI_ROOT "/choosedb.glade", NULL, NULL);
    glade_xml_signal_connect_data(xml, "on_cancelButton_clicked",
                                  G_CALLBACK(on_selectDBcancelButton_clicked),
                                  fe);
    glade_xml_signal_connect_data(xml, "on_browseNewButton_clicked",
                                  G_CALLBACK(on_browseNewButton_clicked), fe);
    glade_xml_signal_connect_data(xml, "on_createNewButton_clicked",
                                  G_CALLBACK(on_createButton_clicked), fe);
    glade_xml_signal_connect_data(xml, "on_browseExistingButton_clicked",
                                  G_CALLBACK(on_browseExistingButton_clicked),
                                  fe);
    glade_xml_signal_connect_data(xml, "on_openExistingButton_clicked",
                                  G_CALLBACK(on_openButton_clicked), fe);


    glade_xml_signal_connect_data(xml, "on_openExistingRadio_toggled",
                                  G_CALLBACK(on_openExistingRadio_toggled), fe);
    glade_xml_signal_connect_data(xml, "on_createNewRadio_toggled",
                                  G_CALLBACK(on_createNewRadio_toggled), fe);

    chooseDbWindow = glade_xml_get_widget(xml, "chooseDatabaseWindow");
    g_signal_connect(G_OBJECT(chooseDbWindow), "destroy",
                     G_CALLBACK(on_choosedb_window_destroyed), NULL);

    /* XXX should not unref? g_object_unref(G_OBJECT(xml)); xml = NULL; */
    return chooseDbWindow;
}
/* vim: set sw=4 et: */
