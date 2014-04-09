AM_CFLAGS = @GLIB_CFLAGS@
AM_CXXFLAGS = @GLIB_CFLAGS@

bookmarksdir = $(libdir)/dillo/dpi/bookmarks
downloadsdir = $(libdir)/dillo/dpi/downloads
ftpdir = $(libdir)/dillo/dpi/ftp
httpsdir = $(libdir)/dillo/dpi/https
hellodir = $(libdir)/dillo/dpi/hello
filedir = $(libdir)/dillo/dpi/file
cookiesdir = $(libdir)/dillo/dpi/cookies
datauridir = $(libdir)/dillo/dpi/datauri
bookmarks_PROGRAMS = bookmarks.dpi
downloads_PROGRAMS = downloads.dpi
ftp_PROGRAMS = ftp.filter.dpi
https_PROGRAMS = https.filter.dpi
hello_PROGRAMS = hello.filter.dpi
file_PROGRAMS = file.dpi
cookies_PROGRAMS = cookies.dpi
datauri_PROGRAMS = datauri.filter.dpi

bookmarks_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a
if DLGUI
downloads_dpi_LDADD = @GLIB_LIBS@ @LIBFLTK_LIBS@ ../dpip/libDpip.a
else
downloads_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a
endif
ftp_filter_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a
https_filter_dpi_LDADD = @GLIB_LIBS@ @LIBSSL_LIBS@ ../dpip/libDpip.a
hello_filter_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a
file_dpi_LDADD = @GLIB_LIBS@ @LIBPTHREAD_LIBS@ ../dpip/libDpip.a
cookies_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a
datauri_filter_dpi_LDADD = @GLIB_LIBS@ ../dpip/libDpip.a

file_dpi_LDFLAGS = @LIBPTHREAD_LDFLAGS@

bookmarks_dpi_SOURCES = bookmarks.c dpiutil.c dpiutil.h
if DLGUI
downloads_dpi_SOURCES = downloads.cc dpiutil.c dpiutil.h
else
downloads_dpi_SOURCES = downloads-old.c dpiutil.c dpiutil.h
endif
ftp_filter_dpi_SOURCES = ftp.c dpiutil.c dpiutil.h
https_filter_dpi_SOURCES = https.c dpiutil.c dpiutil.h
hello_filter_dpi_SOURCES = hello.c dpiutil.c dpiutil.h
file_dpi_SOURCES = file.c dpiutil.c dpiutil.h
cookies_dpi_SOURCES = cookies.c dpiutil.c dpiutil.h
datauri_filter_dpi_SOURCES = datauri.c dpiutil.c dpiutil.h

