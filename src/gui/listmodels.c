/* GUI list models and views for certificates, requests, and signing options.
 */
#include <stdlib.h> 
#include <string.h> 
#include <gtk/gtk.h> 
#include <sqlite3.h> 
#include "cryptlib.h" 
#include "cadb.h" 
#include "frontend.h"

static void render_date_to_string(GtkTreeViewColumn * column,
                                  GtkCellRenderer * renderer,
                                  GtkTreeModel * model, GtkTreeIter * iter,
                                  gpointer data);

GtkListStore *make_request_list_model() {
    GtkListStore *store;
    store = gtk_list_store_new(9, G_TYPE_INT,   /* id */
                               G_TYPE_STRING,   /* CN */
                               G_TYPE_STRING,   /* EMAIL */
                               G_TYPE_STRING,   /* OU */
                               G_TYPE_STRING,   /* O */
                               G_TYPE_STRING,   /* L */
                               G_TYPE_STRING,   /* SP */
                               G_TYPE_STRING,   /* C */
                               G_TYPE_BOOLEAN   /* handled */
        );
    return store;
}

GtkListStore *make_cert_list_model() {
    GtkListStore *store;
    store = gtk_list_store_new(10, G_TYPE_INT,  /* id */
                               G_TYPE_STRING,   /* CN */
                               G_TYPE_STRING,   /* EMAIL */
                               G_TYPE_STRING,   /* OU */
                               G_TYPE_STRING,   /* O */
                               G_TYPE_STRING,   /* L */
                               G_TYPE_STRING,   /* SP */
                               G_TYPE_STRING,   /* C */
                               G_TYPE_INT,      /* VALIDTO */
                               G_TYPE_STRING    /* status */
        );
    return store;
}

GtkTreeView *make_request_tree_view() {
    GtkTreeView *list;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    char *titles[] =
        { "Common Name", "Email", "Org. Unit", "Organization", "Locality",
        "State/Province", "Country", NULL
    };
    char **p_title;
    int i;
    list =
        GTK_TREE_VIEW(gtk_tree_view_new_with_model
                      (GTK_TREE_MODEL(make_request_list_model())));
    renderer = gtk_cell_renderer_text_new();
    column =
        gtk_tree_view_column_new_with_attributes("Id", renderer, "text", 0,
                                                 NULL);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column(list, column);

    i = 1;
    for (p_title = titles; *p_title != NULL; p_title++) {
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes(*p_title, renderer, "text",
                                                     i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(list, column);
        /* gtk_tree_view_column_set_expand(column, TRUE); / * only DN column expands */
        i++;
    }

    /* handled? */
    renderer = gtk_cell_renderer_toggle_new();
    g_object_set(G_OBJECT(renderer), "radio", FALSE, "activatable", FALSE,
                 NULL);
    column =
        gtk_tree_view_column_new_with_attributes("Handled?", renderer, "active",
                                                 i, NULL);
    gtk_tree_view_column_set_sort_column_id(column, i);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column(list, column);

    return list;
}

GtkTreeView *make_cert_tree_view() {
    GtkTreeView *list;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    char *titles[] =
        { "Common Name", "Email", "Org. Unit", "Organization", "Locality",
        "State/Province", "Country", NULL
    };
    char **p_title;
    int i;

    list =
        GTK_TREE_VIEW(gtk_tree_view_new_with_model
                      (GTK_TREE_MODEL(make_cert_list_model())));
    renderer = gtk_cell_renderer_text_new();
    column =
        gtk_tree_view_column_new_with_attributes("Id", renderer, "text", 0,
                                                 NULL);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column(list, column);

    i = 1;
    for (p_title = titles; *p_title != NULL; p_title++) {
        renderer = gtk_cell_renderer_text_new();
        column =
            gtk_tree_view_column_new_with_attributes(*p_title, renderer, "text",
                                                     i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(list, column);
        i++;
    }

    /* validto */
    renderer = gtk_cell_renderer_text_new();
    column =
        gtk_tree_view_column_new_with_attributes("Valid To", renderer, NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer,
                                            render_date_to_string, NULL, NULL);
    gtk_tree_view_column_set_sort_column_id(column, i++);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column(list, column);

    renderer = gtk_cell_renderer_text_new();
    column =
        gtk_tree_view_column_new_with_attributes("Status", renderer, "text", i,
                                                 NULL);
    gtk_tree_view_append_column(list, column);
    return list;
}

void refresh_request_tree_view(GtkTreeView * list, FRONTEND * fe) {
    GtkListStore *store;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    int attrs[] = { CRYPT_CERTINFO_COMMONNAME, CRYPT_CERTINFO_EMAIL,
        CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, CRYPT_CERTINFO_ORGANIZATIONNAME,
        CRYPT_CERTINFO_LOCALITYNAME, CRYPT_CERTINFO_STATEORPROVINCENAME,
        CRYPT_CERTINFO_COUNTRYNAME, 0
    };
    int *p_attr;

    store = GTK_LIST_STORE(gtk_tree_view_get_model(list));
    gtk_list_store_clear(store);
    /* XXX hack, encapsulate */
    db = fe->db->db;
    err =
        sqlite3_prepare(db,
                        "SELECT id, request_data, handled FROM requests WHERE recipient = ? ORDER BY id ASC",
                        -1, &stmt, &tail);
    if (err != SQLITE_OK)
        return;
    err = sqlite3_bind_text(stmt, 1, fe->db->ca_name, -1, SQLITE_TRANSIENT);
    if (err != SQLITE_OK) {
        fprintf(stderr, "sqlite3 error binding: %d\n", err);
        sqlite3_finalize(stmt);
        return;
    }
    err = sqlite3_step(stmt);
    while (err == SQLITE_ROW) {
        GtkTreeIter iter;
        const void *cert_blob;
        CRYPT_CERTIFICATE cert;
        char *dncomp;
        int dncomp_len;
        int status;
        int i;

        gtk_list_store_append(store, &iter);
        /* blob, get DN */
        cert_blob = sqlite3_column_blob(stmt, 1);
        status =
            cryptImportCert(cert_blob, sqlite3_column_bytes(stmt, 1),
                            CRYPT_UNUSED, &cert);
        if (!cryptStatusOK(status)) {
            fprintf(stderr, "cl error import: %d\n", err);
            goto finalize;
        }

        i = 1;
        for (p_attr = attrs; *p_attr != 0; p_attr++) {
            dncomp = lmz_cl_get_attribute_string(cert, *p_attr, &dncomp_len);
            gtk_list_store_set(store, &iter, i, dncomp, -1);    /* NULL dncomp -> blank cell */
            if (dncomp != NULL)
                free(dncomp);
            i++;
        }

        gtk_list_store_set(store, &iter, 0, sqlite3_column_int(stmt, 0), i, sqlite3_column_int(stmt, 2), -1);   /* string copied */
        cryptDestroyCert(cert);
        err = sqlite3_step(stmt);
    }
    if (err != SQLITE_DONE) {
        fprintf(stderr, "sqlite3 error stepping: %d\n", err);
        /* finalize anyway */
    }
  finalize:
    err = sqlite3_finalize(stmt);
    if (err != SQLITE_OK) {
        fprintf(stderr, "sqlite3 error finalizing: %d\n", err);
    }
}
void refresh_cert_tree_view(GtkTreeView * list, FRONTEND * fe) {
    GtkListStore *store;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *tail;
    int err;
    int attrs[] = { CRYPT_CERTINFO_COMMONNAME, CRYPT_CERTINFO_EMAIL,
        CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, CRYPT_CERTINFO_ORGANIZATIONNAME,
        CRYPT_CERTINFO_LOCALITYNAME, CRYPT_CERTINFO_STATEORPROVINCENAME,
        CRYPT_CERTINFO_COUNTRYNAME, 0
    };
    int *p_attr;
    time_t now;

    now = time(NULL);
    store = GTK_LIST_STORE(gtk_tree_view_get_model(list));
    gtk_list_store_clear(store);
    /* XXX hack, encapsulate */
    db = fe->db->db;
    err =
        sqlite3_prepare(db,
                        "SELECT id, cert_data, validTo, revoked FROM certificates WHERE issuer = ? ORDER BY id ASC",
                        -1, &stmt, &tail);
    if (err != SQLITE_OK)
        return;
    err = sqlite3_bind_text(stmt, 1, fe->db->ca_name, -1, SQLITE_TRANSIENT);
    if (err != SQLITE_OK) {
        fprintf(stderr, "sqlite3 error binding: %d\n", err);
        sqlite3_finalize(stmt);
        return;
    }
    err = sqlite3_step(stmt);
    while (err == SQLITE_ROW) {
        GtkTreeIter iter;
        const void *cert_blob;
        CRYPT_CERTIFICATE cert;
        char *dncomp;
        int dncomp_len;
        int status;
        int validto;
        int i;

        gtk_list_store_append(store, &iter);
        /* blob, get DN */
        cert_blob = sqlite3_column_blob(stmt, 1);
        status =
            cryptImportCert(cert_blob, sqlite3_column_bytes(stmt, 1),
                            CRYPT_UNUSED, &cert);
        if (!cryptStatusOK(status)) {
            fprintf(stderr, "cl error import: %d\n", err);
            goto finalize;
        }


        /* id */
        gtk_list_store_set(store, &iter, 0, sqlite3_column_int(stmt, 0), -1);

        i = 1;
        for (p_attr = attrs; *p_attr != 0; p_attr++) {
            dncomp = lmz_cl_get_attribute_string(cert, *p_attr, &dncomp_len);
            gtk_list_store_set(store, &iter, i, dncomp, -1);    /* NULL dncomp -> blank cell */
            if (dncomp != NULL)
                free(dncomp);
            i++;
        }

        /* validto */
        validto = sqlite3_column_int(stmt, 2);
        gtk_list_store_set(store, &iter, i, validto, -1);
        i++;

        /* status */
        if (validto < now) {
            gtk_list_store_set(store, &iter, i, "EXPIRED", -1);
        }
        else {
            if ((validto - (14 * 86400)) < now) {
                gtk_list_store_set(store, &iter, i, "EXP. WARNING", -1);
            }
            else if (sqlite3_column_int(stmt, 3) == 0) {
                gtk_list_store_set(store, &iter, i, "VALID", -1);
            }
            else {
                gtk_list_store_set(store, &iter, i, "REVOKED", -1);
            }
        }

        cryptDestroyCert(cert);
        err = sqlite3_step(stmt);
    }
    if (err != SQLITE_DONE) {
        fprintf(stderr, "sqlite3 error stepping: %d\n", err);
        /* finalize anyway */
    }
  finalize:
    err = sqlite3_finalize(stmt);
    if (err != SQLITE_OK) {
        fprintf(stderr, "sqlite3 error finalizing: %d\n", err);
    }
}

static struct {
    const char *name;
    LMZ_SIGN_OPT sign_opt;
} builtin_signopts[] = {
    {
        "Server Certificate [built-in]", {
            CRYPT_KEYUSAGE_NONREPUDIATION | CRYPT_KEYUSAGE_KEYENCIPHERMENT | CRYPT_KEYUSAGE_DIGITALSIGNATURE,   /* ku_bits */
                365,            /* valid_days */
                1,              /* eku_num */
            {
            CRYPT_CERTINFO_EXTKEY_SERVERAUTH}   /* eku_flags */
        }
    }, {
        "Client Certificate [built-in]", {
            CRYPT_KEYUSAGE_NONREPUDIATION | CRYPT_KEYUSAGE_KEYENCIPHERMENT | CRYPT_KEYUSAGE_DIGITALSIGNATURE,   /* ku_bits */
                365,            /* valid_days */
                1,              /* eku_num */
            {
            CRYPT_CERTINFO_EXTKEY_CLIENTAUTH}   /* eku_flags */
        }
    }, {
        NULL, {
            0, 0, 0, {
    0}}}
};

GtkListStore *make_signopt_list_model(FRONTEND * fe) {
    char **names, **tmp;
    int status;
    GtkListStore *store;
    GtkTreeIter iter;
    int i;
    status = lmz_ca_enum_signopts(fe->db, &names);
    if (!cryptStatusOK(status)) {
        fprintf(stderr, "cl error enumerate signopts: %d\n", status);
        return NULL;
    }
    store = gtk_list_store_new(3, G_TYPE_STRING /* name */ ,
                               G_TYPE_BOOLEAN /* builtin */ ,
                               G_TYPE_INT /* builtin-id */ );
    /* add builtin types */
    for (i = 0; builtin_signopts[i].name != NULL; i++) {
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter, 0, builtin_signopts[i].name, 1, TRUE,
                           2, i + 1, -1);
    }
    for (tmp = names; *tmp != NULL; tmp++) {
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter, 0, *tmp, 1, FALSE, 2, 0, -1);
    }
    lmz_ca_free_enum_signopts(names);
    return store;
}

const PLMZ_SIGN_OPT get_builtin_signopt(int id) {

    if ((id >= 1) && (id <= 2)) {
        return &(builtin_signopts[id - 1].sign_opt);
    }
    else {
        return NULL;
    }
}

static void render_date_to_string(GtkTreeViewColumn * column,
                                  GtkCellRenderer * renderer,
                                  GtkTreeModel * model, GtkTreeIter * iter,
                                  gpointer data) {
    GValue val;
    time_t time;
    struct tm utctm, *result;
    char buf[256];

    memset(&val, 0, sizeof(GValue));
    gtk_tree_model_get_value(model, iter, 8, &val);
    time = g_value_get_int(&val);
    result = gmtime(&time);
    memcpy(&utctm, result, sizeof(struct tm));
    strftime(buf, 255, "%d-%m-%Y %H:%M:%S UTC", &utctm);
    buf[255] = '\0';
    g_object_set(G_OBJECT(renderer), "text", buf, NULL);
    g_value_unset(&val);
}
/* vim: set sw=4 et: */
