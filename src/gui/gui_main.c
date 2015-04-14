/* Contains main() for the app.
 */
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <stdio.h>
#include <stdlib.h>
#include "cryptlib.h"
#include "frontend.h"
#include "cadb.h"

static gboolean new = FALSE;

static GOptionEntry entries[] = {
    {"new", 'n', 0, G_OPTION_ARG_NONE, &new,
     "Create new CA (must specify filename)", NULL},
    {NULL}
};

int main(int argc, char **argv) {
    GError *error = NULL;
    FRONTEND fe;
    int status;
    gboolean init_ok = TRUE;

    fe.chooseDbWindow = NULL;
    fe.mainWindow = NULL;
    fe.db = NULL;

    /* put this before cryptlib initialization -- 
       if it finds --help it will call exit(0);
     */
    if (!gtk_init_with_args
        (&argc, &argv, "[CA_DB_FILE] - lmz CA Application", entries, NULL,
         &error)) {
        if (error != NULL) {
            fprintf(stderr, "Initialization failed: %s\n", error->message);
            g_error_free(error);
        }
        exit(1);
    }

    g_set_application_name("Lmz CA");
    status = cryptInit();
    /* start random number polling -- if you don't, cryptlib
       can take FOREVER to generate a 4096 bit key */
    cryptAddRandom(NULL, CRYPT_RANDOM_SLOWPOLL);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "Error initializing cryptlib (cl err %d), exiting!\n",
                status);
        exit(1);
    }


    if (argc > 1) {
        if (new) {
            init_ok = do_new_ca(&fe, argv[1]);
        }
        else {
            gchar *tmp = g_strdup(argv[1]);
            init_ok = do_open_db_file(&fe, tmp);
        }
    }
    else {
        fe.chooseDbWindow = lmz_fe_create_choose_db_window(&fe);
        gtk_widget_show(fe.chooseDbWindow);
    }
    if (init_ok) {
        gtk_main();
    }
    if (fe.db != NULL)
        lmz_ca_close(fe.db);
    status = cryptEnd();
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "Error ending cryptlib (cl err %d), exiting!\n",
                status);
        exit(1);
    }
    return 0;
}
/* vim: set sw=4 et: */
