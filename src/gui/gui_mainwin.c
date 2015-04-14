/* Main window for GUI.
 */
#include <string.h>
#include <gtk/gtk.h>
#include "frontend.h"

static void do_about(GtkAction * action, gpointer data) {
    show_about_dialog(GTK_WINDOW(((FRONTEND *) data)->mainWindow));
}

static void do_sync_webdb(GtkAction * action, gpointer data) {
    show_sync_webdb_dialog((FRONTEND *) data);
}

static void do_create_webdb(GtkAction * action, gpointer data) {
    show_new_webdb_dialog((FRONTEND *) data);
}


static void do_sign_request(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value, handled_value;
    GtkTreeView *list;
    GtkTreeSelection *selection;
    fe = (FRONTEND *) data;
    /* TODO check not handled */
    list =
        GTK_TREE_VIEW(g_object_get_data
                      (G_OBJECT(fe->mainWindow), "request-list"));
    selection = gtk_tree_view_get_selection(list);
    memset(&id_value, 0, sizeof(GValue));
    memset(&handled_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gboolean handled;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        gtk_tree_model_get_value(model, &iter, 8, &handled_value);
        handled = g_value_get_boolean(&handled_value);
        if (handled) {
            show_error_dialog(GTK_WINDOW(fe->mainWindow),
                              "That request is already handled, please select a different one");
        }
        else {
            show_sign_dialog(fe, id);
        }
    }
    else {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Please select a request first");
    }
}

static void do_revoke_cert(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    GtkTreeView *list;
    GtkTreeSelection *selection;
    /* TODO check not revoked */
    fe = (FRONTEND *) data;
    list =
        GTK_TREE_VIEW(g_object_get_data
                      (G_OBJECT(fe->mainWindow), "certificate-list"));
    selection = gtk_tree_view_get_selection(list);
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        show_revoke_dialog(fe, id);
    }
    else {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Please select a certificate first");
    }
}

static void do_renew_cert(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    GtkTreeView *list;
    GtkTreeSelection *selection;
    /* TODO check not revoked */
    fe = (FRONTEND *) data;
    list =
        GTK_TREE_VIEW(g_object_get_data
                      (G_OBJECT(fe->mainWindow), "certificate-list"));
    selection = gtk_tree_view_get_selection(list);
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        show_renew_dialog(fe, id);
    }
    else {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Please select a certificate first");
    }
}

static void do_export_ca_cert(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    fe = (FRONTEND *) data;
    show_export_ca_cert_dialog(fe);
}

static void do_import_cert_req(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    fe = (FRONTEND *) data;
    show_import_request_dialog(fe);
}

static void do_export_crl(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    fe = (FRONTEND *) data;
    show_export_crl_dialog(fe);
}

static void do_export_cert(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    GtkTreeView *list;
    GtkTreeSelection *selection;
    /* TODO check not revoked */
    fe = (FRONTEND *) data;
    list =
        GTK_TREE_VIEW(g_object_get_data
                      (G_OBJECT(fe->mainWindow), "certificate-list"));
    selection = gtk_tree_view_get_selection(list);
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        show_export_cert_dialog(fe, id);
    }
    else {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Please select a certificate first");
    }
}

static void do_view_certdetails(GtkAction * action, gpointer data) {
    FRONTEND *fe;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    GtkTreeView *list;
    GtkTreeSelection *selection;
    /* TODO check not revoked */
    fe = (FRONTEND *) data;
    list =
        GTK_TREE_VIEW(g_object_get_data
                      (G_OBJECT(fe->mainWindow), "certificate-list"));
    selection = gtk_tree_view_get_selection(list);
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        show_view_cert_dialog(fe, id);
    }
    else {
        show_error_dialog(GTK_WINDOW(fe->mainWindow),
                          "Please select a certificate first");
    }

}


static void do_quit(GtkAction * action, gpointer data) {
    gtk_main_quit();
}


static GtkActionEntry entries[] = {
    {"FileMenu", NULL, "_File"},        /* name, stock id, label */
    {"WebMenu", GTK_STOCK_NETWORK, "_Web", ""}, /* name, stock id, label */
    {"ActionMenu", NULL, "_Action"},    /* name, stock id, label */
    {"HelpMenu", NULL, "_Help"},        /* name, stock id, label */
    {"About", GTK_STOCK_ABOUT,  /* name, stock id */
     "_About", NULL,            /* label, accelerator */
     "About",                   /* tooltip */
     G_CALLBACK(do_about)},
/* ca ops */
    {"CAMenu", NULL, "_CA"},
    {"ExportCACert", GTK_STOCK_SAVE,    /* name, stock id */
     "_Export CA Certificate", "",      /* label, accelerator */
     "Export CA Certificate",   /* tooltip */
     G_CALLBACK(do_export_ca_cert)},
    {"ExportCRL", GTK_STOCK_SAVE,       /* name, stock id */
     "Export _CRL", "",         /* label, accelerator */
     "Export CRL",              /* tooltip */
     G_CALLBACK(do_export_crl)},
    {"ImportRequest", GTK_STOCK_ADD,    /* name, stock id */
     "_Import Certificate Request", "", /* label, accelerator */
     "Import Certificate Request",      /* tooltip */
     G_CALLBACK(do_import_cert_req)},
    {"CreateWebDb", GTK_STOCK_NEW,
     "_Create Web Database", "",
     "Create Web Database",
     G_CALLBACK(do_create_webdb)},
    {"SyncWebDb", GTK_STOCK_REFRESH,
     "_Synchronize Web Database", "",
     "Synchronize Web Database",
     G_CALLBACK(do_sync_webdb)},
    {"Quit", GTK_STOCK_QUIT,    /* name, stock id */
     "_Quit", NULL,             /* label, accelerator */
     "Quit",                    /* tooltip */
     G_CALLBACK(do_quit)},
/* request ops */
    {"SignRequest", GTK_STOCK_EDIT,     /* name, stock id */
     "_Sign Request", "",       /* label, accelerator */
     "Sign Request",            /* tooltip */
     G_CALLBACK(do_sign_request)},
/* cert ops */
    {"ViewCertDetails", GTK_STOCK_ZOOM_IN,      /* name, stock id */
     "_View Details", "",       /* label, accelerator */
     "View Details",            /* tooltip */
     G_CALLBACK(do_view_certdetails)},
    {"ExportCert", GTK_STOCK_SAVE,      /* name, stock id */
     "_Export Certificate", "", /* label, accelerator */
     "Export Certificate",      /* tooltip */
     G_CALLBACK(do_export_cert)},
    {"RevokeCert", GTK_STOCK_STOP,      /* name, stock id */
     "_Revoke Certificate", "", /* label, accelerator */
     "Revoke Certificate",      /* tooltip */
     G_CALLBACK(do_revoke_cert)},
    {"RenewCert", GTK_STOCK_REFRESH,    /* name, stock id */
     "Re_new Certificate", "",  /* label, accelerator */
     "Renew Certificate",       /* tooltip */
     G_CALLBACK(do_renew_cert)},
};

static guint n_entries = G_N_ELEMENTS(entries);


static const gchar *ui_info =
    "<ui>"
    "  <menubar name='MenuBar'>"
    "    <menu action='CAMenu'>"
    "      <menuitem action='ExportCACert'/>"
    "      <menuitem action='ExportCRL'/>"
    "      <menuitem action='ImportRequest'/>"
    "      <separator/>"
    "      <menu action='WebMenu'>"
    "        <menuitem action='CreateWebDb'/>"
    "        <menuitem action='SyncWebDb'/>"
    "      </menu>"
    "      <separator/>"
    "      <menuitem action='Quit'/>"
    "    </menu>"
    "    <menu action='ActionMenu'/>"
    "    <menu action='HelpMenu'>"
    "      <menuitem action='About'/>"
    "    </menu>"
    "  </menubar>"
    "  <toolbar  name='ToolBar'>"
    "  </toolbar>" 
    "  <popup name='ListContextPopup' />" 
    "</ui>";

static const gchar *request_ui_defs =
    "<ui>"
    "  <menubar name='MenuBar'>"
    "    <menu action='ActionMenu'>"
    "      <menuitem action='SignRequest' />"
    "    </menu>"
    "  </menubar>"
    "  <toolbar  name='ToolBar'>"
    "    <toolitem action='SignRequest'/>"
    "  </toolbar>"
    "  <popup name='ListContextPopup'>"
    "    <menuitem action='SignRequest' />" 
    "  </popup>" 
    "</ui>";

static const gchar *cert_ui_defs =
    "<ui>"
    "  <menubar name='MenuBar'>"
    "    <menu action='ActionMenu'>"
    "      <menuitem action='ExportCert' />"
    "      <menuitem action='ViewCertDetails' />"
    "      <menuitem action='RevokeCert' />"
    "      <menuitem action='RenewCert' />"
    "    </menu>"
    "  </menubar>"
    "  <toolbar  name='ToolBar'>"
    "    <toolitem action='ExportCert' />"
    "    <toolitem action='ViewCertDetails' />"
    "    <toolitem action='RevokeCert' />"
    "    <toolitem action='RenewCert' />"
    "  </toolbar>"
    "  <popup name='ListContextPopup'>"
    "    <menuitem action='ExportCert' />"
    "    <menuitem action='ViewCertDetails' />"
    "    <menuitem action='RevokeCert' />"
    "    <menuitem action='RenewCert' />" 
    "  </popup>" 
    "</ui>";


static void
update_resize_grip(GtkWidget * widget,
                   GdkEventWindowState * event, GtkStatusbar * statusbar) {
    if (event->changed_mask & (GDK_WINDOW_STATE_MAXIMIZED |
                               GDK_WINDOW_STATE_FULLSCREEN))
        gtk_statusbar_set_has_resize_grip(statusbar,
                                          !(event->new_window_state &
                                            (GDK_WINDOW_STATE_MAXIMIZED |
                                             GDK_WINDOW_STATE_FULLSCREEN)));
}


static int on_switch_page(GtkNotebook * notebook, GtkNotebookPage * page,
                          guint page_num, gpointer user_data) {
    return 1;
}

static int on_mainwin_destroyed(GtkWidget * widget, gpointer data) {
    gtk_main_quit();
    return 1;
}

static int sync_actions(GtkNotebook * notebook, GtkNotebookPage * page,
                        guint page_num, gpointer user_data) {
    GObject *window_object = G_OBJECT(((FRONTEND *) user_data)->mainWindow);
    guint mergeid;
    gpointer old_mergeid;
    GtkUIManager *manager;
    manager = GTK_UI_MANAGER(g_object_get_data(window_object, "ui-manager"));
    old_mergeid = g_object_get_data(window_object, "current-merge-id");
    if (old_mergeid != NULL) {
        gtk_ui_manager_remove_ui(manager, GPOINTER_TO_UINT(old_mergeid));
    }
    if (page_num == 0) {        /* requests */
        mergeid =
            gtk_ui_manager_add_ui_from_string(manager, request_ui_defs, -1,
                                              NULL);
        g_object_set_data(window_object, "current-merge-id",
                          GUINT_TO_POINTER(mergeid));

    }
    else if (page_num == 1) {   /* certificates */
        mergeid =
            gtk_ui_manager_add_ui_from_string(manager, cert_ui_defs, -1, NULL);
        g_object_set_data(window_object, "current-merge-id",
                          GUINT_TO_POINTER(mergeid));
    }
    else {
        g_object_set_data(window_object, "current-merge-id", NULL);
    }
    return 1;
}

static gboolean display_context_menu(GtkWidget * widget, GdkEventButton * event,
                                     gpointer user_data) {
    if (event->button == 3) {   /* right click */

        GObject *window_object = G_OBJECT(((FRONTEND *) user_data)->mainWindow);
        GtkUIManager *manager =
            GTK_UI_MANAGER(g_object_get_data(window_object, "ui-manager"));
        GtkWidget *menu =
            gtk_ui_manager_get_widget(manager, "/ListContextPopup");
        gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, event->button,
                       event->time);
        /* gtk_widget_destroy(menu); -- not needed owned by uimanager */
    }
    return FALSE;
}

static void update_cert_details(GtkTreeSelection * selection, gpointer data) {
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        {
            GtkWidget *pane =
                g_object_get_data(G_OBJECT(((FRONTEND *) data)->mainWindow),
                                  "certificate-pane");
            GtkWidget *vbox = gtk_paned_get_child2(GTK_PANED(pane));
            if (vbox != NULL) {
                GtkWidget *infobox;
                gtk_widget_destroy(vbox);
                /* get infobox for cert id #id and pack it then show */
                infobox = make_cert_infobox((FRONTEND *) data, id);
                gtk_paned_pack2(GTK_PANED(pane), infobox, TRUE, FALSE);
                gtk_widget_show_all(pane);
            }
        }
    }
}

static void update_request_details(GtkTreeSelection * selection, gpointer data) {
    GtkTreeModel *model;
    GtkTreeIter iter;
    GValue id_value;
    memset(&id_value, 0, sizeof(GValue));
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint id;
        gtk_tree_model_get_value(model, &iter, 0, &id_value);
        id = g_value_get_int(&id_value);
        {
            GtkWidget *pane =
                g_object_get_data(G_OBJECT(((FRONTEND *) data)->mainWindow),
                                  "request-pane");
            GtkWidget *vbox = gtk_paned_get_child2(GTK_PANED(pane));
            if (vbox != NULL) {
                GtkWidget *infobox;
                gtk_widget_destroy(vbox);
                /* get infobox for request id #id and pack it then show */
                infobox = make_request_infobox((FRONTEND *) data, id);
                gtk_paned_pack2(GTK_PANED(pane), infobox, TRUE, FALSE);
                gtk_widget_show_all(pane);
            }
        }
    }
}

static void fixup_short_labels(GtkActionGroup * action_group) {
    GtkAction *act;
#define SETLABEL(actnm, lbl) \
  do { \
  act = gtk_action_group_get_action(action_group, actnm); \
  if (act) { \
    g_object_set(G_OBJECT(act), "short-label", lbl, NULL); \
  } \
  } while (0)

    SETLABEL("ExportCert", "Export");
    SETLABEL("ViewCertDetails", "Details");
    SETLABEL("RenewCert", "Renew");
    SETLABEL("RevokeCert", "Revoke");
    SETLABEL("SignRequest", "Sign");

#undef SETLABEL
}

GtkWidget *make_appwindow(FRONTEND * fe, const gchar * filename) {
    GtkWidget *window = NULL;
    GtkWidget *table;
    GtkWidget *statusbar;
    GtkWidget *tabs;
    GtkWidget *sw;
    GtkWidget *bar;
    GtkActionGroup *action_group;
    GtkUIManager *merge;
    GtkWidget *list;
    GError *error = NULL;



    /* Create the toplevel window
     */

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    fe->mainWindow = GTK_WIDGET(window);

    {
        gchar *shortname;
        GString *s;
        shortname = g_filename_display_name(filename);
        s = g_string_new("Lmz CA - ");
        g_string_append(s, shortname);
        gtk_window_set_title(GTK_WINDOW(window), s->str);
        g_string_free(s, TRUE);
        g_free(shortname);
    }
    /* NULL window variable when window is closed */
    g_signal_connect(window, "destroy",
                     G_CALLBACK(gtk_widget_destroyed), &window);

    table = gtk_table_new(1, 4, FALSE);

    gtk_container_add(GTK_CONTAINER(window), table);

    /* Create the menubar and toolbar
     */

    action_group = gtk_action_group_new("AppWindowActions");
    gtk_action_group_add_actions(action_group, entries, n_entries, fe);
    fixup_short_labels(action_group);

    merge = gtk_ui_manager_new();
    g_object_set_data_full(G_OBJECT(window), "ui-manager", merge,
                           g_object_unref);
    gtk_ui_manager_insert_action_group(merge, action_group, 0);
    gtk_window_add_accel_group(GTK_WINDOW(window),
                               gtk_ui_manager_get_accel_group(merge));

    if (!gtk_ui_manager_add_ui_from_string(merge, ui_info, -1, &error)) {
        g_message("building menus failed: %s", error->message);
        g_error_free(error);
    }

    bar = gtk_ui_manager_get_widget(merge, "/MenuBar");
    gtk_widget_show(bar);
    gtk_table_attach(GTK_TABLE(table), bar,
                     /* X direction *//* Y direction */
                     0, 1, 0, 1, GTK_EXPAND | GTK_FILL, 0, 0, 0);

    bar = gtk_ui_manager_get_widget(merge, "/ToolBar");
    gtk_toolbar_set_tooltips(GTK_TOOLBAR(bar), TRUE);
    gtk_widget_show(bar);
    gtk_table_attach(GTK_TABLE(table), bar,
                     /* X direction *//* Y direction */
                     0, 1, 1, 2, GTK_EXPAND | GTK_FILL, 0, 0, 0);


    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

    tabs = gtk_notebook_new();

    /* request list */
    list = GTK_WIDGET(make_request_tree_view());
    sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), list);
    {
        GtkWidget *pane = gtk_vpaned_new();
        g_object_ref(pane);
        g_object_set_data_full(G_OBJECT(window), "request-pane", pane,
                               g_object_unref);
        gtk_paned_pack1(GTK_PANED(pane), sw, TRUE, TRUE);
        gtk_paned_pack2(GTK_PANED(pane),
                        gtk_label_new("Please select a request"), TRUE, FALSE);
        gtk_notebook_append_page(GTK_NOTEBOOK(tabs), pane,
                                 gtk_label_new("Requests"));
    }
    g_object_ref(list);
    g_object_set_data_full(G_OBJECT(window), "request-list", list,
                           g_object_unref);
    g_signal_connect(G_OBJECT(list), "button_press_event",
                     G_CALLBACK(display_context_menu), fe);
    g_signal_connect(G_OBJECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(list))),
                     "changed", G_CALLBACK(update_request_details), fe);
    refresh_request_tree_view(GTK_TREE_VIEW(list), fe);

    /* cert list */
    list = GTK_WIDGET(make_cert_tree_view());
    sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), list);
    {
        GtkWidget *pane;
        GtkWidget *filler;
        pane = gtk_vpaned_new();
        g_object_ref(pane);
        g_object_set_data_full(G_OBJECT(window), "certificate-pane", pane,
                               g_object_unref);
        filler = gtk_label_new("Please select a certificate");
        gtk_paned_pack1(GTK_PANED(pane), sw, TRUE, TRUE);
        gtk_paned_pack2(GTK_PANED(pane), filler, TRUE, FALSE);
        gtk_notebook_append_page(GTK_NOTEBOOK(tabs), pane,
                                 gtk_label_new("Certificates"));
    }
    g_object_ref(list);
    g_object_set_data_full(G_OBJECT(window), "certificate-list", list,
                           g_object_unref);
    g_signal_connect(G_OBJECT(list), "button_press_event",
                     G_CALLBACK(display_context_menu), fe);
    g_signal_connect(G_OBJECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(list))),
                     "changed", G_CALLBACK(update_cert_details), fe);
    refresh_cert_tree_view(GTK_TREE_VIEW(list), fe);

    /* sync on page switch */
    g_signal_connect(G_OBJECT(tabs), "switch-page", G_CALLBACK(on_switch_page),
                     fe);
    g_signal_connect_after(G_OBJECT(tabs), "switch-page",
                           G_CALLBACK(sync_actions), fe);


    gtk_table_attach(GTK_TABLE(table), tabs,
                     /* X direction *//* Y direction */
                     0, 1, 2, 3,
                     GTK_EXPAND | GTK_FILL, GTK_EXPAND | GTK_FILL, 0, 0);

    /* Create statusbar */

    statusbar = gtk_statusbar_new();
    gtk_table_attach(GTK_TABLE(table), statusbar,
                     /* X direction *//* Y direction */
                     0, 1, 3, 4, GTK_EXPAND | GTK_FILL, 0, 0, 0);


    g_signal_connect_object(window,
                            "window_state_event",
                            G_CALLBACK(update_resize_grip), statusbar, 0);

    g_signal_connect(G_OBJECT(window), "destroy",
                     G_CALLBACK(on_mainwin_destroyed), NULL);


    return window;
}
/* vim: set sw=4 et: */
