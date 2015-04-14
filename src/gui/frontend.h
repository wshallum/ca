#ifndef LMZ_FRONTEND_H_INCLUDED
#define LMZ_FRONTEND_H_INCLUDED
#include "cadb.h"
#include <gtk/gtk.h>
typedef struct TAGfrontend {
  PLMZ_CA_DB db;
  GtkWidget *chooseDbWindow;
  GtkWidget *mainWindow;
} FRONTEND;

/* choosedb.c */
gboolean do_new_ca(FRONTEND * /*fe*/, const char * /*filename*/);
gboolean do_open_db_file(FRONTEND * /*fe*/, char * /*filename*/);
GtkWidget *lmz_fe_create_choose_db_window(FRONTEND * /* fe */);
/* gui_mainwin.c */
GtkWidget *make_appwindow (FRONTEND * /* fe */, const gchar * /* filename */);
/* listmodels.c */
GtkListStore *make_request_list_model();
GtkListStore *make_cert_list_model();
GtkTreeView *make_request_tree_view();
GtkTreeView *make_cert_tree_view();
void refresh_request_tree_view(GtkTreeView * /* list */, FRONTEND * /* fe */);
void refresh_cert_tree_view(GtkTreeView * /* list */, FRONTEND * /* fe */);
GtkListStore *make_signopt_list_model(FRONTEND * /* fe */);
const PLMZ_SIGN_OPT get_builtin_signopt(int /* id */);
/* infobox.c */
GtkWidget *make_cert_infobox(FRONTEND * /* fe */, int /* id */);
GtkWidget *make_request_infobox(FRONTEND * /* fe */, int /* id */);
GtkWidget *make_request_infobox_direct(FRONTEND * /* fe */, CRYPT_CERTIFICATE /* cert */, char * /* notes */);
/* signdialog.c */
void show_sign_dialog(FRONTEND * /* fe */, int /* req_id */);
/* revokedialog.c */
void show_revoke_dialog(FRONTEND * /* fe */, int /* cert_id */);
/* renewdialog.c */
void show_renew_dialog(FRONTEND * /* fe */, int /* cert_id */);
/* newcadialog.c */
gboolean show_ca_dialog(FRONTEND * /* fe */, const gchar * /* filename */);
/* exportcacertdialog.c */
void show_export_ca_cert_dialog(FRONTEND * /* fe */);
void show_export_cert_dialog(FRONTEND * /* fe */, int /* id */);
/* importrequestdialog.c */
void show_import_request_dialog(FRONTEND * /*fe */);
/* exportcrldialog.c */
void show_export_crl_dialog(FRONTEND * /* fe */);
/* dialogs.c */
char *do_get_password(GtkWindow * /*parent_window*/);
void show_error_dialog(GtkWindow * /*parent*/, gchar * /*format*/, ...);
void show_about_dialog(GtkWindow * /*parent*/);
/* gui_asn1tree.c */
void show_view_cert_dialog(FRONTEND * /* fe */, int /* id */);
/* webdb.c */
void show_new_webdb_dialog(FRONTEND * /* fe */);
void show_sync_webdb_dialog(FRONTEND * /* fe */);
#endif
