/*
 * File: cookies.c
 * Cookies server.
 *
 * Copyright 2001 Lars Clausen   <lrclause@cs.uiuc.edu>
 *                Jörgen Viksell <jorgen.viksell@telia.com>
 * Copyright 2002-2005 Jorge Arellano Cid <jcid@dillo.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/* Handling of cookies takes place here.
 * This implementation aims to follow RFC 2965:
 * http://www.cis.ohio-state.edu/cs/Services/rfc/rfc-text/rfc2965.txt
 */

/* Todo: this server is not assembling the received packets.
 * This means it currently expects dillo to send full dpi tags
 * within the socket; if that fails, everything stops.
 * This is not hard to fix, mainly is a matter of expecting the
 * final '>' of a tag.
 */

#ifdef DISABLE_COOKIES

int main(void)
{
   return 0; /* never called */
}

#else


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>       /* for time() and time_t */
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include "dpiutil.h"
#include "../dpip/dpip.h"


#include <glib.h>

/* This one is tricky, some sources state it should include the byte
 * for the terminating NULL, and others say it shouldn't. */
# define D_SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
                        + strlen ((ptr)->sun_path))

/* Debugging macros
 */
#define _MSG(fmt...)
#define MSG(fmt...)  g_print("[cookies dpi]: " fmt)


/*
 * a_List_add()
 *
 * Make sure there's space for 'num_items' items within the list
 * (First, allocate an 'alloc_step' sized chunk, after that, double the
 *  list size --to make it faster)
 */
#define a_List_add(list,num_items,alloc_step) \
   if ( !list ) { \
      list = g_malloc(alloc_step * sizeof((*list))); \
   } \
   if ( num_items >= alloc_step ){ \
      while ( num_items >= alloc_step ) \
         alloc_step <<= 1; \
      list = g_realloc(list, alloc_step * sizeof((*list))); \
   }

/* The maximum length of a line in the cookie file */
#define LINE_MAXLEN 4096

typedef enum {
   COOKIE_ACCEPT,
   COOKIE_ACCEPT_SESSION,
   COOKIE_DENY
} CookieControlAction;

typedef struct {
   CookieControlAction action;
   char *domain;
} CookieControl;

typedef struct {
   char *name;
   char *value;
   char *domain;
   char *path;
   time_t expires_at;
   guint version;
   char *comment;
   char *comment_url;
   gboolean secure;
   gboolean session_only;
   GList *ports;
} CookieData_t;

/*
 * Local data
 */

/* Hashtable indexed by domain, each value is a set of cookies for
 * that domain. */
static GHashTable *cookies;

/* Variables for access control */
static CookieControl *ccontrol = NULL;
static int num_ccontrol = 0;
static int num_ccontrol_max = 1;
static CookieControlAction default_action = COOKIE_DENY;

static gboolean disabled;
static FILE *file_stream;
static char *cookies_txt_header_str =
"# HTTP Cookie File\n"
"# http://www.netscape.com/newsref/std/cookie_spec.html\n"
"# This is a generated file!  Do not edit.\n\n";


/*
 * Forward declarations
 */

static gchar *d_strsep(char **orig, const char *delim);
static FILE *Cookies_fopen(const char *file, gchar *init_str);
static CookieControlAction Cookies_control_check_domain(const char *domain);
static int Cookie_control_init(void);
static void Cookies_parse_ports(gint url_port, CookieData_t *cookie,
                                const char *port_str);
static char *Cookies_build_ports_str(CookieData_t *cookie);
static char *Cookies_strip_path(const char *path);
static void Cookies_add_cookie(CookieData_t *cookie);
static void Cookies_remove_cookie(CookieData_t *cookie);
static gint Cookies_equals(gconstpointer a, gconstpointer b);

/*
 * strsep implementation
 */
gchar *d_strsep(char **orig, const char *delim)
{
   gchar *str, *p;

   if (!(str = *orig))
      return NULL;

   p = strpbrk(str, delim);
   if (p) {
      *p++ = 0;
      *orig = p;
   } else {
      *orig = NULL;
   }
   return str;
}

/*
 * Return a file pointer. If the file doesn't exist, try to create it,
 * with the optional 'init_str' as its content.
 */
static FILE *Cookies_fopen(const char *filename, gchar *init_str)
{
   FILE *F_in;
   int fd;

   if ((F_in = fopen(filename, "r+")) == NULL) {
      /* Create the file */
      fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      if (fd != -1) {
         if (init_str)
            write(fd, init_str, strlen(init_str));
         close(fd);

         MSG("Created file: %s\n", filename);
         F_in = Cookies_fopen(filename, NULL);
      } else {
         MSG("Could not create file: %s!\n", filename);
      }
   }

   /* set close on exec */
   fcntl(fileno(F_in), F_SETFD, FD_CLOEXEC | fcntl(fileno(F_in), F_GETFD));

   return F_in;
}

static void Cookies_free_cookie(CookieData_t *cookie)
{
   g_free(cookie->name);
   g_free(cookie->value);
   g_free(cookie->domain);
   g_free(cookie->path);
   g_free(cookie->comment);
   g_free(cookie->comment_url);
   g_list_free(cookie->ports);
   g_free(cookie);
}

/*
 * Initialize the cookies module
 * (The 'disabled' variable is writable only within Cookies_init)
 */
void Cookies_init()
{
   CookieData_t *cookie;
   char *filename;
   char line[LINE_MAXLEN];
#ifndef HAVE_LOCKF
   struct flock lck;
#endif
   FILE *old_cookies_file_stream;

   /* Default setting */
   disabled = TRUE;

   /* Read and parse the cookie control file (cookiesrc) */
   if (Cookie_control_init() != 0) {
      MSG("Disabling cookies.\n");
      return;
   }

   /* Get a stream for the cookies file */
   filename = g_strconcat(g_get_home_dir(), "/.dillo/cookies.txt", NULL);
   file_stream = Cookies_fopen(filename, cookies_txt_header_str);

   g_free(filename);

   if (!file_stream) {
      MSG("ERROR: Can't open ~/.dillo/cookies.txt, disabling cookies\n");
      return;
   }

   /* Try to get a lock from the file descriptor */
#ifdef HAVE_LOCKF
   disabled = (lockf(fileno(file_stream), F_TLOCK, 0) == -1);
#else /* POSIX lock */
   lck.l_start = 0; /* start at beginning of file */
   lck.l_len = 0;  /* lock entire file */
   lck.l_type = F_WRLCK;
   lck.l_whence = SEEK_SET;  /* absolute offset */

   disabled = (fcntl(fileno(file_stream), F_SETLK, &lck) == -1);
#endif
   if (disabled) {
      MSG("The cookies file has a file lock: disabling cookies!\n");
      fclose(file_stream);
      return;
   }

   MSG("Enabling cookies as from cookiesrc...\n");

   cookies = g_hash_table_new(g_str_hash, g_str_equal);

   /* Get all lines in the file */
   while (!feof(file_stream)) {
      line[0] = '\0';
      fgets(line, LINE_MAXLEN, file_stream);

      /* Remove leading and trailing whitespaces */
      g_strstrip(line);

      if ((line[0] != '\0') && (line[0] != '#')) {
         /* Would use g_strsplit, but it doesn't give empty trailing pieces.
          */
         /* Split the row into pieces using a tab as the delimiter.
          * pieces[0] The domain name
          * pieces[1] TRUE/FALSE: is the domain a suffix, or a full domain?
          * pieces[2] The path
          * pieces[3] Is the cookie unsecure or secure (TRUE/FALSE)
          * pieces[4] Timestamp of expire date
          * pieces[5] Name of the cookie
          * pieces[6] Value of the cookie
          */
         CookieControlAction action;
         char *piece;
         char *line_marker = line;

         cookie = g_new0(CookieData_t, 1);

         cookie->session_only = FALSE;
         cookie->version = 0;
         cookie->domain = g_strdup(d_strsep(&line_marker, "\t"));
         d_strsep(&line_marker, "\t"); /* we use domain always as sufix */
         cookie->path = g_strdup(d_strsep(&line_marker, "\t"));
         piece = d_strsep(&line_marker, "\t");
         if (piece != NULL && piece[0] == 'T')
            cookie->secure = TRUE;
         piece = d_strsep(&line_marker, "\t");
         if (piece != NULL)
            cookie->expires_at = (time_t) strtol(piece, NULL, 10);
         cookie->name = g_strdup(d_strsep(&line_marker, "\t"));
         cookie->value = g_strdup(d_strsep(&line_marker, "\t"));

         if (!cookie->domain || cookie->domain[0] == '\0' ||
             !cookie->path || cookie->path[0] != '/' ||
             !cookie->name || cookie->name[0] == '\0' ||
             !cookie->value) {
            MSG("Malformed line in cookies.txt file!\n");
            Cookies_free_cookie(cookie);
            continue;
         }

         action = Cookies_control_check_domain(cookie->domain);
         if (action == COOKIE_DENY) {
            Cookies_free_cookie(cookie);
            continue;
         } else if (action == COOKIE_ACCEPT_SESSION) {
            cookie->session_only = TRUE;
         }

         /* Save cookie in memory */
         Cookies_add_cookie(cookie);
      }
   }

   filename = g_strconcat(g_get_home_dir(), "/.dillo/cookies", NULL);
   if ((old_cookies_file_stream = fopen(filename, "r")) != NULL) {
      g_free(filename);
      MSG("WARNING: Reading old cookies file ~/.dillo/cookies too\n");

      /* Get all lines in the file */
      while (!feof(old_cookies_file_stream)) {
         line[0] = '\0';
         fgets(line, LINE_MAXLEN, old_cookies_file_stream);

         /* Remove leading and trailing whitespaces */
         g_strstrip(line);

         if (line[0] != '\0') {
            /* Would use g_strsplit, but it doesn't give empty trailing pieces.
             */
            /* Split the row into pieces using a tab as the delimiter.
             * pieces[0] The version this cookie was set as (0 / 1)
             * pieces[1] The domain name
             * pieces[2] A comma separated list of accepted ports
             * pieces[3] The path
             * pieces[4] Is the cookie unsecure or secure (0 / 1)
             * pieces[5] Timestamp of expire date
             * pieces[6] Name of the cookie
             * pieces[7] Value of the cookie
             * pieces[8] Comment
             * pieces[9] Comment url
             */
            CookieControlAction action;
            char *piece;
            char *line_marker = line;

            cookie = g_new0(CookieData_t, 1);

            cookie->session_only = FALSE;
            piece = d_strsep(&line_marker, "\t");
            if (piece != NULL)
            cookie->version = strtol(piece, NULL, 10);
            cookie->domain  = g_strdup(d_strsep(&line_marker, "\t"));
            Cookies_parse_ports(0, cookie, d_strsep(&line_marker, "\t"));
            cookie->path = g_strdup(d_strsep(&line_marker, "\t"));
            piece = d_strsep(&line_marker, "\t");
            if (piece != NULL && piece[0] == '1')
               cookie->secure = TRUE;
            piece = d_strsep(&line_marker, "\t");
            if (piece != NULL)
               cookie->expires_at = (time_t) strtol(piece, NULL, 10);
            cookie->name = g_strdup(d_strsep(&line_marker, "\t"));
            cookie->value = g_strdup(d_strsep(&line_marker, "\t"));
            cookie->comment = g_strdup(d_strsep(&line_marker, "\t"));
            cookie->comment_url = g_strdup(d_strsep(&line_marker, "\t"));

            if (!cookie->domain || cookie->domain[0] == '\0' ||
                !cookie->path || cookie->path[0] != '/' ||
                !cookie->name || cookie->name[0] == '\0' ||
                !cookie->value) {
               MSG("Malformed line in cookies file!\n");
               Cookies_free_cookie(cookie);
               continue;
            }

            action = Cookies_control_check_domain(cookie->domain);
            if (action == COOKIE_DENY) {
               Cookies_free_cookie(cookie);
               continue;
            } else if (action == COOKIE_ACCEPT_SESSION) {
               cookie->session_only = TRUE;
            }

            /* Save cookie in memory */
            Cookies_add_cookie(cookie);
         }
      }
   fclose(old_cookies_file_stream);
   } else {
      g_free(filename);
   }

}

/*
 * Save the cookies and remove them from the hash table
 */
static gboolean Cookies_freeall_cb(gpointer key,
                                   gpointer value,
                                   gpointer data)
{
   CookieData_t *cookie;
   GList *domain_cookies = value;
/*   char *ports_str; */

   for (; domain_cookies; domain_cookies = g_list_next(domain_cookies)) {
      cookie = domain_cookies->data;

      if (!cookie->session_only) {
/*         ports_str = Cookies_build_ports_str(cookie); */
         fprintf(file_stream, "%s\tTRUE\t%s\t%s\t%ld\t%s\t%s\n",
                 cookie->domain,
                 cookie->path,
                 cookie->secure ? "TRUE" : "FALSE",
                 (long)cookie->expires_at,
                 cookie->name,
                 cookie->value);
/*         g_free(ports_str); */
      }

      Cookies_free_cookie(cookie);
   }
   g_list_free(value);
   g_free(key);

   /* Return TRUE to tell GLIB to free this key from the hash table */
   return TRUE;
}

/*
 * Flush cookies to disk and free all the memory allocated.
 */
void Cookies_freeall()
{
   int fd;
#ifndef HAVE_LOCKF
   struct flock lck;
#endif

   if (disabled)
      return;

   rewind(file_stream);
   fd = fileno(file_stream);
   ftruncate(fd, 0);
   fprintf(file_stream, cookies_txt_header_str);

   g_hash_table_foreach_remove(cookies, Cookies_freeall_cb, NULL);

#ifdef HAVE_LOCKF
   lockf(fd, F_ULOCK, 0);
#else  /* POSIX file lock */
   lck.l_start = 0; /* start at beginning of file */
   lck.l_len = 0;  /* lock entire file */
   lck.l_type = F_UNLCK;
   lck.l_whence = SEEK_SET;  /* absolute offset */

   fcntl(fileno(file_stream), F_SETLKW, &lck);
#endif
   fclose(file_stream);
}

static char *months[] =
{ "",
  "Jan", "Feb", "Mar",
  "Apr", "May", "Jun",
  "Jul", "Aug", "Sep",
  "Oct", "Nov", "Dec"
};

/*
 * Take a months name and return a number between 1-12.
 * E.g. 'April' -> 4
 */
static int Cookies_get_month(const char *month_name)
{
   int i;

   for (i = 1; i <= 12; i++) {
      if (!g_strncasecmp(months[i], month_name, 3))
         return i;
   }
   return 0;
}

/*
 * Return a local timestamp from a GMT date string
 * Accept: RFC-1123 | RFC-850 | ANSI asctime | Old Netscape format.
 *
 *   Wdy, DD-Mon-YY HH:MM:SS GMT
 *   Wdy, DD-Mon-YYYY HH:MM:SS GMT
 *   Weekday, DD-Mon-YY HH:MM:SS GMT
 *   Weekday, DD-Mon-YYYY HH:MM:SS GMT
 *   Tue May 21 13:46:22 1991\n
 *   Tue May 21 13:46:22 1991
 *
 * (return 0 on malformed date string syntax)
 */
static time_t Cookies_create_timestamp(const char *expires)
{
   time_t ret;
   int day, month, year, hour, minutes, seconds;
   gchar *cp;
   gchar *E_msg =
      "Expire date is malformed!\n"
      " (should be RFC-1123 | RFC-850 | ANSI asctime)\n"
      " Ignoring cookie: ";

   cp = strchr(expires, ',');
   if (!cp && (strlen(expires) == 24 || strlen(expires) == 25)) {
      /* Looks like ANSI asctime format... */
      cp = (gchar *)expires;
      day = strtol(cp + 8, NULL, 10);       /* day */
      month = Cookies_get_month(cp + 4);    /* month */
      year = strtol(cp + 20, NULL, 10);     /* year */
      hour = strtol(cp + 11, NULL, 10);     /* hour */
      minutes = strtol(cp + 14, NULL, 10);  /* minutes */
      seconds = strtol(cp + 17, NULL, 10);  /* seconds */

   } else if (cp && (cp - expires == 3 || cp - expires > 5) &&
                    (strlen(cp) == 24 || strlen(cp) == 26)) {
      /* RFC-1123 | RFC-850 format | Old Netscape format */
      day = strtol(cp + 2, NULL, 10);
      month = Cookies_get_month(cp + 5);
      year = strtol(cp + 9, &cp, 10);
      /* todo: tricky, because two digits for year IS ambiguous! */
      year += (year < 70) ? 2000 : ((year < 100) ? 1900 : 0);
      hour = strtol(cp + 1, NULL, 10);
      minutes = strtol(cp + 4, NULL, 10);
      seconds = strtol(cp + 7, NULL, 10);

   } else {
      MSG("%s%s\n", E_msg, expires);
      return (time_t) 0;
   }

   /* Error checks  --this may be overkill */
   if (!(day > 0 && day < 32 && month > 0 && month < 13 && year > 1970 &&
         hour >= 0 && hour < 24 && minutes >= 0 && minutes < 60 &&
         seconds >= 0 && seconds < 60)) {
      MSG("%s%s\n", E_msg, expires);
      return (time_t) 0;
   }

   /* Calculate local timestamp.
    * [stolen from Lynx... (http://lynx.browser.org)] */
   month -= 3;
   if (month < 0) {
      month += 12;
      year--;
   }

   day += (year - 1968) * 1461 / 4;
   day += ((((month * 153) + 2) / 5) - 672);
   ret = (time_t)((day * 60 * 60 * 24) +
                  (hour * 60 * 60) +
                  (minutes * 60) +
                  seconds);

   MSG("Expires in %ld seconds, at %s",
       (long)ret - time(NULL), ctime(&ret));

   return ret;
}

/*
 * Parse a string containing a list of port numbers.
 */
static void Cookies_parse_ports(gint url_port, CookieData_t *cookie,
                                const char *port_str)
{
   if ((!port_str || !port_str[0]) && url_port != 0) {
      /* There was no list, so only the calling urls port should be allowed. */
      cookie->ports = g_list_append(cookie->ports,
                                    GINT_TO_POINTER(url_port));
   } else if (port_str[0] == '"' && port_str[1] != '"') {
      char **tokens, **i;
      int port;

      tokens = g_strsplit(port_str + 1, ",", -1);
      for (i = tokens; *i; ++i) {
         port = strtol(*i, NULL, 10);
         if (port > 0) {
            cookie->ports = g_list_append(cookie->ports,
                                          GINT_TO_POINTER(port));
         }
      }
      g_strfreev(tokens);
   }
}

/*
 * Build a string of the ports in 'cookie'.
 */
static char *Cookies_build_ports_str(CookieData_t *cookie)
{
   GString *gstr;
   GList *list;
   char *ret;

   gstr = g_string_new("\"");
   for (list = cookie->ports; list; list = g_list_next(list))
      g_string_sprintfa(gstr, "%d,", GPOINTER_TO_INT(list->data));

   /* Remove any trailing comma */
   if (gstr->len > 1)
      g_string_erase(gstr, gstr->len - 1, 1);

   g_string_append(gstr, "\"");

   ret = gstr->str;
   g_string_free(gstr, FALSE);

   return ret;
}

/*
 * Used by g_list_insert_sorted() to sort the cookies by most specific path
 */
static gint Cookies_compare(gconstpointer a, gconstpointer b)
{
   const CookieData_t *ca = a, *cb = b;

   return strcmp(ca->path, cb->path);
}

static void Cookies_add_cookie(CookieData_t *cookie)
{
   GList *domain_cookies, *tmp;
   char *domain_str;

   /* Don't add an expired cookie */
   if (!cookie->session_only && cookie->expires_at < time(NULL)) {
      Cookies_free_cookie(cookie);
      return;
   }

   domain_cookies = g_hash_table_lookup(cookies, cookie->domain);

   if (domain_cookies) {
      /* Respect the limit of 20 cookies per domain */
      if (g_list_length(domain_cookies) > 20) {
         MSG("There are too many cookies for this domain (%s)\n",
             cookie->domain);
         Cookies_free_cookie(cookie);
         return;
      }

      /* Remove any cookies with the same name and path */
      while ((tmp = g_list_find_custom(domain_cookies, cookie,
                                       Cookies_equals))) {
         Cookies_remove_cookie(tmp->data);
         domain_cookies = g_hash_table_lookup(cookies, cookie->domain);
      }
   }

   /* Allocate string key when no domain_cookies are left
    * (because remove_cookie has then killed the key, when it was there) */
   domain_str = domain_cookies ? cookie->domain : g_strdup(cookie->domain);

   domain_cookies = g_list_insert_sorted(domain_cookies, cookie,
                                         Cookies_compare);
   g_hash_table_insert(cookies, domain_str, domain_cookies);
}

/*
 * Remove the cookie from the domain list.
 * If the domain list is empty, free the hash table entry.
 * Free the cookie.
 */
static void Cookies_remove_cookie(CookieData_t *cookie)
{
   GList *list;
   gpointer orig_key;
   gpointer orig_val;

   if (g_hash_table_lookup_extended(cookies, cookie->domain,
                                    &orig_key, &orig_val)) {
      list = g_list_remove(orig_val, cookie);

      if (list) {
         /* Make sure that we have the correct start of the list stored */
         g_hash_table_insert(cookies, cookie->domain, list);
      } else {
         g_hash_table_remove(cookies, cookie->domain);
         g_free(orig_key);
      }
   } else {
      MSG("Attempting to remove a cookie that doesn't exist!\n");
   }

   Cookies_free_cookie(cookie);
}

/*
 * Return the attribute that is present at *cookie_str. This function
 * will also attempt to advance cookie_str past any equal-sign.
 */
static char *Cookies_parse_attr(char **cookie_str)
{
   char *str = *cookie_str;
   guint i, end = 0;
   gboolean got_attr = FALSE;

   for (i = 0; ; i++) {
      switch (str[i]) {
      case ' ':
      case '\t':
      case '=':
      case ';':
         got_attr = TRUE;
         if (end == 0)
            end = i;
         break;
      case ',':
         *cookie_str = str + i;
         return g_strndup(str, i);
         break;
      case '\0':
         if (!got_attr) {
            end = i;
            got_attr = TRUE;
         }
         /* fall through! */
      default:
         if (got_attr) {
            *cookie_str = str + i;
            return g_strndup(str, end);
         }
         break;
      }
   }

   return NULL;
}

/*
 * Get the value starting at *cookie_str.
 * broken_syntax: watch out for stupid syntax (comma in unquoted string...)
 */
static char *Cookies_parse_value(char **cookie_str,
                                 gboolean broken_syntax,
                                 gboolean keep_quotes)
{
   guint i, end;
   char *str = *cookie_str;

   for (i = end = 0; !end; ++i) {
      switch (str[i]) {
      case ' ':
      case '\t':
         if (!broken_syntax && str[0] != '\'' && str[0] != '"') {
            *cookie_str = str + i + 1;
            end = 1;
         }
         break;
      case '\'':
      case '"':
         if (i != 0 && str[i] == str[0]) {
            char *tmp = str + i;

            while (*tmp != '\0' && *tmp != ';' && *tmp != ',')
               tmp++;

            *cookie_str = (*tmp == ';') ? tmp + 1 : tmp;

            if (keep_quotes)
               i++;
            end = 1;
         }
         break;
      case '\0':
         *cookie_str = str + i;
         end = 1;
         break;
      case ',':
         if (str[0] != '\'' && str[0] != '"' && !broken_syntax) {
            /* A new cookie starts here! */
            *cookie_str = str + i;
            end = 1;
         }
         break;
      case ';':
         if (str[0] != '\'' && str[0] != '"') {
            *cookie_str = str + i + 1;
            end = 1;
         }
         break;
      default:
         break;
      }
   }
   /* keep i as an index to the last char */
   --i;

   if ((str[0] == '\'' || str[0] == '"') && !keep_quotes) {
      return i > 1 ? g_strndup(str + 1, i - 1) : NULL;
   } else {
      return g_strndup(str, i);
   }
}

/*
 * Parse one cookie...
 */
static CookieData_t *Cookies_parse_one(gint url_port, char **cookie_str)
{
   CookieData_t *cookie;
   char *str = *cookie_str;
   char *attr;
   char *value;
   int num_attr = 0;
   gboolean max_age = FALSE;
   gboolean discard = FALSE;

   cookie = g_new0(CookieData_t, 1);
   cookie->session_only = TRUE;

   /* Iterate until there is nothing left of the string OR we come
    * across a comma representing the start of another cookie */
   while (*str != '\0' && *str != ',') {
      /* Skip whitespace */
      while (isspace(*str))
         str++;

      /* Get attribute */
      attr = Cookies_parse_attr(&str);
      if (!attr) {
         MSG("Failed to parse cookie attribute!\n");
         Cookies_free_cookie(cookie);
         return NULL;
      }

      /* Get the value for the attribute and store it */
      if (num_attr == 0) {
         /* The first attr, which always is the user supplied attr, may
          * have the same name as an ordinary attr. Hence this workaround. */
         cookie->name = g_strdup(attr);
         cookie->value = Cookies_parse_value(&str, FALSE, TRUE);
      } else if (g_strcasecmp(attr, "Path") == 0) {
         value = Cookies_parse_value(&str, FALSE, FALSE);
         cookie->path = value;
      } else if (g_strcasecmp(attr, "Domain") == 0) {
         value = Cookies_parse_value(&str, FALSE, FALSE);
         cookie->domain = value;
      } else if (g_strcasecmp(attr, "Discard") == 0) {
         cookie->session_only = TRUE;
         discard = TRUE;
      } else if (g_strcasecmp(attr, "Max-Age") == 0) {
         if (!discard) {
            value = Cookies_parse_value(&str, FALSE, FALSE);

            if (value) {
               cookie->expires_at = time(NULL) + strtol(value, NULL, 10);
               cookie->session_only = FALSE;
               max_age = TRUE;
               g_free(value);
            } else {
               MSG("Failed to parse cookie value!\n");
               Cookies_free_cookie(cookie);
               return NULL;
            }
         }
      } else if (g_strcasecmp(attr, "Expires") == 0) {
         if (!max_age && !discard) {
            MSG("Old netscape-style cookie...\n");
            value = Cookies_parse_value(&str, TRUE, FALSE);
            if (value) {
               cookie->expires_at = Cookies_create_timestamp(value);
               cookie->session_only = FALSE;
               g_free(value);
            } else {
               MSG("Failed to parse cookie value!\n");
               Cookies_free_cookie(cookie);
               return NULL;
            }
         }
      } else if (g_strcasecmp(attr, "Port") == 0) {
         value = Cookies_parse_value(&str, FALSE, TRUE);
         Cookies_parse_ports(url_port, cookie, value);
         g_free(value);
      } else if (g_strcasecmp(attr, "Comment") == 0) {
         value = Cookies_parse_value(&str, FALSE, FALSE);
         cookie->comment = value;
      } else if (g_strcasecmp(attr, "CommentURL") == 0) {
         value = Cookies_parse_value(&str, FALSE, FALSE);
         cookie->comment_url = value;
      } else if (g_strcasecmp(attr, "Version") == 0) {
         value = Cookies_parse_value(&str, FALSE, FALSE);

         if (value) {
            cookie->version = strtol(value, NULL, 10);
            g_free(value);
         } else {
            MSG("Failed to parse cookie value!\n");
            Cookies_free_cookie(cookie);
            return NULL;
         }
      } else if (g_strcasecmp(attr, "Secure") == 0) {
         cookie->secure = TRUE;
      } else {
         /* Oops! this can't be good... */
         g_free(attr);
         Cookies_free_cookie(cookie);
         MSG("Cookie contains illegal attribute!\n");
         return NULL;
      }

      g_free(attr);
      num_attr++;
   }

   *cookie_str = (*str == ',') ? str + 1 : str;

   if (cookie->name && cookie->value) {
      return cookie;
   } else {
      MSG("Cookie missing name and/or value!\n");
      Cookies_free_cookie(cookie);
      return NULL;
   }
}

/*
 * Iterate the cookie string until we catch all cookies.
 * Return Value: a list with all the cookies! (or NULL upon error)
 */
static GSList *Cookies_parse_string(gint url_port, char *cookie_string)
{
   CookieData_t *cookie;
   GSList *ret = NULL;
   char *str = cookie_string;

   /* The string may contain several cookies separated by comma.
    * We'll iterate until we've catched them all */
   while (*str) {
      cookie = Cookies_parse_one(url_port, &str);

      if (cookie) {
         ret = g_slist_append(ret, cookie);
      } else {
         MSG("Malformed cookie field, ignoring cookie: %s\n", cookie_string);
         return NULL;
      }
   }

   return ret;
}

/*
 * Compare cookies by name and path (return 0 if equal)
 */
static gint Cookies_equals(gconstpointer a, gconstpointer b)
{
   const CookieData_t *ca = a, *cb = b;

   return (strcmp(ca->name, cb->name) || strcmp(ca->path, cb->path));
}

/*
 * Validate cookies domain against some security checks.
 */
static gboolean Cookies_validate_domain(CookieData_t *cookie, gchar *host,
                                         gchar *url_path)
{
   int dots, diff, i;
   gboolean is_ip;

   /* Make sure that the path is set to something */
   if (!cookie->path || cookie->path[0] != '/') {
      g_free(cookie->path);
      cookie->path = Cookies_strip_path(url_path);
   }

   /* If the server never set a domain, or set one without a leading
    * dot (which isn't allowed), we use the calling URL's hostname. */
   if (cookie->domain == NULL || cookie->domain[0] != '.') {
      g_free(cookie->domain);
      cookie->domain = g_strdup(host);
      return TRUE;
   }

   /* Count the number of dots and also find out if it is an IP-address */
   is_ip = TRUE;
   for (i = 0, dots = 0; cookie->domain[i] != '\0'; i++) {
      if (cookie->domain[i] == '.')
         dots++;
      else if (!isdigit(cookie->domain[i]))
         is_ip = FALSE;
   }

   /* A valid domain must have at least two dots in it */
   /* NOTE: this breaks cookies on localhost... */
   if (dots < 2) {
      return FALSE;
   }

   /* Now see if the url matches the domain */
   diff = strlen(host) - i;
   if (diff > 0) {
      if (g_strcasecmp(host + diff, cookie->domain))
         return FALSE;

      if (!is_ip) {
         /* "x.y.test.com" is not allowed to set cookies for ".test.com";
          *  only an url of the form "y.test.com" would be. */
         while ( diff-- )
            if (host[diff] == '.')
               return FALSE;
      }
   }

   return TRUE;
}

/*
 * Strip of the filename from a full path
 */
static char *Cookies_strip_path(const char *path)
{
   char *ret;
   guint len;

   if (path) {
      len = strlen(path);

      while (len && path[len] != '/')
         len--;
      ret = g_strndup(path, len + 1);
   } else {
      ret = g_strdup("/");
   }

   return ret;
}

/*
 * Set the value corresponding to the cookie string
 */
void Cookies_set(gchar *cookie_string, gchar *url_host,
                 gchar *url_path, gint url_port)
{
   CookieControlAction action;
   GSList *list;

   if (disabled)
      return;

   action = Cookies_control_check_domain(url_host);
   if (action == COOKIE_DENY) {
      MSG("denied SET for %s\n", url_host);
      return;
   }

   list = Cookies_parse_string(url_port, cookie_string);

   while (list) {
      CookieData_t *cookie = list->data;

      if (Cookies_validate_domain(cookie, url_host, url_path)) {
         if (action == COOKIE_ACCEPT_SESSION)
            cookie->session_only = TRUE;

         Cookies_add_cookie(cookie);
      } else {
         MSG("Rejecting cookie for %s from host %s path %s\n",
             cookie->domain, url_host, url_path);
         Cookies_free_cookie(cookie);
      }

      list = g_slist_remove(list, list->data);
   }
}

/*
 * Compare the cookie with the supplied data to see if it matches
 */
static gboolean Cookies_match(CookieData_t *cookie, gint port,
                              const char *path, gboolean is_ssl)
{
   /* Insecure cookies matches both secure and insecure urls, secure
      cookies matches only secure urls */
   if (cookie->secure && !is_ssl)
      return FALSE;

   /* Check that the cookie path is a subpath of the current path */
   if (strncmp(cookie->path, path, strlen(cookie->path)) != 0)
      return FALSE;

   /* Check if the port of the request URL matches any
    * of those set in the cookie */
   if (cookie->ports) {
      GList *list;

      for (list = cookie->ports; list; list = g_list_next(list)) {
         if (GPOINTER_TO_INT(list->data) == port)
            return TRUE;
      }

      return FALSE;
   }

   /* It's a match */
   return TRUE;
}

/*
 * Return a string that contains all relevant cookies as headers.
 */
char *Cookies_get(gchar *url_host, gchar *url_path,
                  gchar *url_scheme, gint url_port)
{
   char *domain_string, *q, *str, *path;
   CookieData_t *cookie;
   GList *matching_cookies = NULL;
   GList *domain_cookie;
   gboolean is_ssl;
   GString *cookie_gstring;

   if (disabled)
      return g_strdup("");

   path = Cookies_strip_path(url_path);

   /* Check if the protocol is secure or not */
   is_ssl = (!g_strcasecmp(url_scheme, "https"));

   for (domain_string = (char *) url_host;
        domain_string != NULL && *domain_string;
        domain_string = strchr(domain_string+1, '.')) {
      domain_cookie = g_hash_table_lookup(cookies, domain_string);

      while (domain_cookie) {
         cookie = domain_cookie->data;
         domain_cookie = g_list_next(domain_cookie);

         /* Remove expired cookie. */
         if (!cookie->session_only && cookie->expires_at < time(NULL)) {
            Cookies_remove_cookie(cookie);
            continue;
         }

         /* Check if the cookie matches the requesting URL */
         if (Cookies_match(cookie, url_port, path, is_ssl))
            matching_cookies = g_list_append(matching_cookies, cookie);
      }
   }

   /* Found the cookies, now make the string */
   cookie_gstring = g_string_new("");
   if (matching_cookies != NULL) {
      CookieData_t *first_cookie = matching_cookies->data;

      g_string_sprintfa(cookie_gstring, "Cookie: ");

      if (first_cookie->version != 0)
         g_string_sprintfa(cookie_gstring, "$Version=\"%d\"; ",
                           first_cookie->version);

      while (matching_cookies) {
         cookie = matching_cookies->data;
         q = (cookie->version == 0 ? "" : "\"");

         g_string_sprintfa(cookie_gstring,
                           "%s=%s; $Path=%s%s%s; $Domain=%s%s%s",
                           cookie->name, cookie->value,
                           q, cookie->path, q, q, cookie->domain, q);

         if (cookie->ports) {
            char *ports_str = Cookies_build_ports_str(cookie);
            g_string_sprintfa(cookie_gstring, "; $Port=%s", ports_str);
            g_free(ports_str);
         }

         matching_cookies = g_list_next(matching_cookies);
         g_string_append(cookie_gstring, matching_cookies ? "; " : "\r\n");
      }
   }

   g_free(path);
   str = cookie_gstring->str;
   g_string_free(cookie_gstring, FALSE);
   return str;
}

/* -------------------------------------------------------------
 *                    Access control routines
 * ------------------------------------------------------------- */


/*
 * Get the cookie control rules (from cookiesrc).
 * Return value:
 *   0 = Parsed OK, with cookies enabled
 *   1 = Parsed OK, with cookies disabled
 *   2 = Can't open the control file
 */
static int Cookie_control_init(void)
{
   CookieControl cc;
   FILE *stream;
   char *filename;
   char line[LINE_MAXLEN];
   char domain[LINE_MAXLEN];
   char rule[LINE_MAXLEN];
   int i, j;
   gboolean enabled = FALSE;

   /* Get a file pointer */
   filename = g_strconcat(g_get_home_dir(), "/", ".dillo/cookiesrc", NULL);
   stream = Cookies_fopen(filename, "DEFAULT DENY\n");
   g_free(filename);

   if (!stream)
      return 2;

   /* Get all lines in the file */
   while (!feof(stream)) {
      line[0] = '\0';
      fgets(line, LINE_MAXLEN, stream);

      /* Remove leading and trailing whitespaces */
      g_strstrip(line);

      if (line[0] != '\0' && line[0] != '#') {
         i = 0;
         j = 0;

         /* Get the domain */
         while (!isspace(line[i]))
            domain[j++] = line[i++];
         domain[j] = '\0';

         /* Skip past whitespaces */
         i++;
         while (isspace(line[i]))
            i++;

         /* Get the rule */
         j = 0;
         while (line[i] != '\0' && !isspace(line[i]))
            rule[j++] = line[i++];
         rule[j] = '\0';

         if (g_strcasecmp(rule, "ACCEPT") == 0)
            cc.action = COOKIE_ACCEPT;
         else if (g_strcasecmp(rule, "ACCEPT_SESSION") == 0)
            cc.action = COOKIE_ACCEPT_SESSION;
         else if (g_strcasecmp(rule, "DENY") == 0)
            cc.action = COOKIE_DENY;
         else {
            MSG("Cookies: rule '%s' for domain '%s' is not recognised.\n",
                rule, domain);
            continue;
         }

         cc.domain = g_strdup(domain);
         if (g_strcasecmp(cc.domain, "DEFAULT") == 0) {
            /* Set the default action */
            default_action = cc.action;
            g_free(cc.domain);
         } else {
            a_List_add(ccontrol, num_ccontrol, num_ccontrol_max);
            ccontrol[num_ccontrol++] = cc;
         }

         if (cc.action != COOKIE_DENY)
            enabled = TRUE;
      }
   }

   fclose(stream);

   return (enabled ? 0 : 1);
}

/*
 * Check the rules for an appropriate action for this domain
 */
static CookieControlAction Cookies_control_check_domain(const char *domain)
{
   int i, diff;

   for (i = 0; i < num_ccontrol; i++) {
      if (ccontrol[i].domain[0] == '.') {
         diff = strlen(domain) - strlen(ccontrol[i].domain);
         if (diff >= 0) {
            if (g_strcasecmp(domain + diff, ccontrol[i].domain) != 0)
               continue;
         } else {
            continue;
         }
      } else {
         if (g_strcasecmp(domain, ccontrol[i].domain) != 0)
            continue;
      }

      /* If we got here we have a match */
      return( ccontrol[i].action );
   }

   return default_action;
}

/* -- Dpi parser ----------------------------------------------------------- */

/*
 * Parse a data stream (dpi protocol)
 * Note: Buf is a zero terminated string
 * Return code: { 0:OK, 1:Abort, 2:Close }
 */
static int srv_parse_buf(SockHandler *sh, char *Buf, size_t BufSize)
{
   char *p, *cmd, *cookie, *host, *path, *scheme;
   gint port;

   if (!(p = strchr(Buf, '>'))) {
      /* Haven't got a full tag */
      MSG("Haven't got a full tag!\n");
      return 1;
   }

   cmd = a_Dpip_get_attr(Buf, BufSize, "cmd");

   if (cmd && strcmp(cmd, "DpiBye") == 0) {
      g_free(cmd);
      MSG("Cookies dpi (pid %d): Got DpiBye.\n", (gint)getpid());
      exit(0);

   } else if (cmd && strcmp(cmd, "set_cookie") == 0) {
      g_free(cmd);
      cookie = a_Dpip_get_attr(Buf, BufSize, "cookie");
      host = a_Dpip_get_attr(Buf, BufSize, "host");
      path = a_Dpip_get_attr(Buf, BufSize, "path");
      p = a_Dpip_get_attr(Buf, BufSize, "port");
      port = strtol(p, NULL, 10);
      g_free(p);

      Cookies_set(cookie, host, path, port);

      g_free(path);
      g_free(host);
      g_free(cookie);
      return 2;

   } else if (cmd && strcmp(cmd, "get_cookie") == 0) {
      g_free(cmd);
      scheme = a_Dpip_get_attr(Buf, BufSize, "scheme");
      host = a_Dpip_get_attr(Buf, BufSize, "host");
      path = a_Dpip_get_attr(Buf, BufSize, "path");
      p = a_Dpip_get_attr(Buf, BufSize, "port");
      port = strtol(p, NULL, 10);
      g_free(p);

      cookie = Cookies_get(host, path, scheme, port);
      g_free(scheme);
      g_free(path);
      g_free(host);

      cmd = a_Dpip_build_cmd("cmd=%s cookie=%s", "get_cookie_answer", cookie);

      if (sock_handler_write_str(sh, cmd, 1)) {
          g_free(cookie);
          g_free(cmd);
          return 1;
      }
      g_free(cookie);
      g_free(cmd);

      return 2;
   }

   return 0;
}

/* --  Termination handlers ----------------------------------------------- */
/*
 * (was to delete the local namespace socket),
 *  but this is handled by 'dpid' now.
 */
static void cleanup(void)
{
  Cookies_freeall();
  MSG("cleanup\n");
  /* no more cleanup required */
}

/*
 * Perform any necessary cleanups upon abnormal termination
 */
static void termination_handler(int signum)
{
  exit(signum);
}


/*
 * -- MAIN -------------------------------------------------------------------
 */
int main (void) {
   struct sockaddr_un spun;
   int temp_sock_descriptor;
   int address_size;
   char *buf;
   int code;
   SockHandler *sh;

   /* Arrange the cleanup function for terminations via exit() */
   atexit(cleanup);

   /* Arrange the cleanup function for abnormal terminations */
   if (signal (SIGINT, termination_handler) == SIG_IGN)
     signal (SIGINT, SIG_IGN);
   if (signal (SIGHUP, termination_handler) == SIG_IGN)
     signal (SIGHUP, SIG_IGN);
   if (signal (SIGTERM, termination_handler) == SIG_IGN)
     signal (SIGTERM, SIG_IGN);

   Cookies_init();
   MSG("(v.1) accepting connections...\n");

   if (disabled)
      exit(1);

   /* some OSes may need this... */
   address_size = sizeof(struct sockaddr_un);

   while (1) {
      temp_sock_descriptor =
         accept(STDIN_FILENO, (struct sockaddr *)&spun, &address_size);
      if (temp_sock_descriptor == -1) {
         perror("[accept]");
         exit(1);
      }

      /* create the SockHandler structure */
      sh = sock_handler_new(temp_sock_descriptor,temp_sock_descriptor,8*1024);

      while (1) {
         code = 1;
         if ((buf = sock_handler_read(sh)) != NULL) {
            /* Let's see what we fished... */
            code = srv_parse_buf(sh, buf, strlen(buf));
         }
         if (code == 1)
            exit(1);
         else if (code == 2)
            break;
      }

      _MSG("Closing SockHandler\n");
      sock_handler_close(sh);
      sock_handler_free(sh);

   }/*while*/
}

#endif /* !DISABLE_COOKIES */
