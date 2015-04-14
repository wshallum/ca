AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I aclocal



AM_CFLAGS=
# 700 / 200809L is only required for mkdtemp. except for mkdtemp
# we can use 600 / 200112L
AM_CPPFLAGS=-D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
AM_CPPFLAGS+=-Icryptlib/include -Isrc
LDADD = cryptlib/lib/libcl.a -lresolv -ldl -lpthread 

if CC_IS_GCC
  AM_CFLAGS+=-Wall -std=c89 -pedantic -Wno-overlength-strings
endif

if LMZ_DEVELOPMENT
LMZ_UI_ROOT=src/gui
else
LMZ_UI_ROOT=$(pkgdatadir)
endif

# no other executables are built anyways
AM_CFLAGS += $(GTKGLADE_CFLAGS)
AM_CPPFLAGS+="-DLMZ_UI_ROOT=\"$(LMZ_UI_ROOT)\""

# noinst_PROGRAMS = newca cmpca csr $(SSLDEPENDENTS) hello
bin_PROGRAMS = lmzca
pkgdata_DATA = src/gui/choosedb.glade src/gui/sign.glade src/gui/revoke.glade src/gui/newca.glade


lmzca_SOURCES = src/gui/gui_main.c src/gui/choosedb.c src/gui/gui_mainwin.c \
		src/gui/listmodels.c src/gui/infobox.c src/gui/signdialog.c \
		src/gui/revokedialog.c src/gui/dialogs.c src/gui/renewdialog.c \
		src/gui/newcadialog.c src/gui/exportcacertdialog.c \
		src/gui/importrequestdialog.c src/gui/exportcrldialog.c \
		src/gui/gui_asn1tree.c src/gui/webdb.c src/cadb.c src/certinfo.c
lmzca_LDADD = $(LDADD) $(GTKGLADE_LIBS)
# newca_SOURCES = src/newca.c src/cadb.c src/certinfo.c
# cmpca_SOURCES = src/ca-cmdln.c
# csr_SOURCES = src/csr.c
# hello_SOURCES = src/hello.c
# trans_SOURCES = src/trans.c
# trans_CFLAGS = $(OPENSSL_CFLAGS)
# trans_LDADD = $(LDADD) $(OPENSSL_LIBS)

