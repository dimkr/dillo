/*
 * File: dpiutil.c
 *
 * Copyright 2004 Jorge Arellano Cid <jcid@dillo.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include "dpiutil.h"
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <glib.h>

/* Escaping/De-escaping ---------------------------------------------------*/

/*
 * Escape URI characters in 'esc_set' as %XX sequences.
 * Return value: New escaped string.
 */
gchar *Escape_uri_str(const gchar *str, gchar *p_esc_set)
{
   static const char *hex = "0123456789ABCDEF";
   gchar *p, *esc_set;
   GString *gstr;
   gint i;

   esc_set = (p_esc_set) ? p_esc_set : "%#:' ";
   gstr = g_string_sized_new(64);
   for (i = 0; str[i]; ++i) {
      if (str[i] <= 0x1F || str[i] == 0x7F || strchr(esc_set, str[i])) {
         g_string_append_c(gstr, '%');
         g_string_append_c(gstr, hex[(str[i] >> 4) & 15]);
         g_string_append_c(gstr, hex[str[i] & 15]);
      } else {
         g_string_append_c(gstr, str[i]);
      }
   }
   p = gstr->str;
   g_string_free(gstr, FALSE);

   return p;
}

static const char *unsafe_chars = "&<>\"'";
static const char *unsafe_rep[] =
  { "&amp;", "&lt;", "&gt;", "&quot;", "&#39;" };
static const int unsafe_rep_len[] =  { 5, 4, 4, 6, 5 };

/*
 * Escape unsafe characters as html entities.
 * Return value: New escaped string.
 */
gchar *Escape_html_str(const gchar *str)
{
   gint i;
   gchar *p;
   GString *gstr = g_string_sized_new(64);

   for (i = 0; str[i]; ++i) {
      if ((p = strchr(unsafe_chars, str[i])))
         g_string_append(gstr, unsafe_rep[p - unsafe_chars]);
      else
         g_string_append_c(gstr, str[i]);
   }
   p = gstr->str;
   g_string_free(gstr, FALSE);

   return p;
}

/*
 * Unescape a few HTML entities (inverse of Escape_html_str)
 * Return value: New unescaped string.
 */
gchar *Unescape_html_str(const gchar *str)
{
   gint i, j, k;
   gchar *u_str = g_strdup(str);

   if (!strchr(str, '&'))
      return u_str;

   for (i = 0, j = 0; str[i]; ++i) {
      if (str[i] == '&') {
         for (k = 0; k < 5; ++k) {
            if (!g_strncasecmp(str + i, unsafe_rep[k], unsafe_rep_len[k])) {
               i += unsafe_rep_len[k] - 1;
               break;
            }
         }
         u_str[j++] = (k < 5) ? unsafe_chars[k] : str[i];
      } else {
         u_str[j++] = str[i];
      }
   }
   u_str[j] = 0;

   return u_str;
}

/*
 * Filter '\n', '\r', "%0D" and "%0A" from the authority part of an FTP url.
 * This helps to avoid a SMTP relaying hack. This filtering could be done
 * only when port == 25, but if the mail server is listening on another
 * port it wouldn't work.
 * Note: AFAIS this should be done by wget.
 */
char *Filter_smtp_hack(char *url)
{
   int i;
   char c;

   if (strlen(url) > 6) { /* ftp:// */
      for (i = 6; (c = url[i]) && c != '/'; ++i) {
         if (c == '\n' || c == '\r') {
            memmove(url + i, url + i + 1, strlen(url + i));
            --i;
         } else if (c == '%' && url[i+1] == '0' &&
                    (tolower(url[i+2]) == 'a' || tolower(url[i+2]) == 'd')) {
            memmove(url + i, url + i + 3, strlen(url + i + 2));
            --i;
         }
      }
   }
   return url;
}


/* Streamed Sockets API (not mandatory)  ----------------------------------*/

/*
 * Create and initialize the SockHandler structure
 */
SockHandler *sock_handler_new(int fd_in, int fd_out, int flush_sz)
{
   SockHandler *sh = g_new(SockHandler, 1);

   /* init descriptors and streams */
   sh->fd_in  = fd_in;
   sh->fd_out = fd_out;
   sh->out = fdopen(fd_out, "w");

   /* init buffer */
   sh->buf_max = 8 * 1024 + 128;
   sh->buf = g_new(char, sh->buf_max);
   sh->buf_sz = 0;
   sh->flush_sz = flush_sz;

   return sh;
}

/*
 * Streamed write to socket
 * Return: 0 on success, 1 on error.
 */
int sock_handler_write(SockHandler *sh, const char *Data, size_t DataSize,
                       int flush)
{
   gint retval = 1;

   /* append to buf */
   while (sh->buf_max < sh->buf_sz + DataSize) {
      sh->buf_max <<= 1;
      sh->buf = g_realloc(sh->buf, sh->buf_max);
   }
   memcpy(sh->buf + sh->buf_sz, Data, DataSize);
   sh->buf_sz += DataSize;
/*
   g_printerr(
      "sh->buf=%p, sh->buf_sz=%d, sh->buf_max=%d, sh->flush_sz=%d\n",
      sh->buf, sh->buf_sz, sh->buf_max, sh->flush_sz);
*/
/**/
#if 0
{
   guint i;
   /* Test dpip's stream handling by chopping data into characters */
   for (i = 0; i < sh->buf_sz; ++i) {
      fputc(sh->buf[i], sh->out);
      fflush(sh->out);
      usleep(50);
   }
   if (i == sh->buf_sz) {
      sh->buf_sz = 0;
      retval = 0;
   }
}
#else
   /* flush data if necessary */
   if (flush || sh->buf_sz >= sh->flush_sz) {
      if (sh->buf_sz && fwrite (sh->buf, sh->buf_sz, 1, sh->out) != 1) {
         perror("[sock_handler_write]");
      } else {
         fflush(sh->out);
         sh->buf_sz = 0;
         retval = 0;
      }

   } else {
      retval = 0;
   }
#endif
   return retval;
}

/*
 * Convenience function.
 */
int sock_handler_write_str(SockHandler *sh, const char *str, int flush)
{
   return sock_handler_write(sh, str, strlen(str), flush);
}

/*
 * Return a newlly allocated string with the contents read from the socket.
 */
gchar *sock_handler_read(SockHandler *sh)
{
   ssize_t st;
   gchar buf[16384];

   /* can't use fread() */
   do
      st = read(sh->fd_in, buf, 16384);
   while (st < 0 && errno == EINTR);

   if (st == -1)
      perror("[sock_handler_read]");

   return (st > 0) ? g_strndup(buf, (guint)st) : NULL;
}

/*
 * Close this socket for reading and writing.
 */
void sock_handler_close(SockHandler *sh)
{
   /* flush before closing */
   sock_handler_write(sh, "", 0, 1);

   fclose(sh->out);
   close(sh->fd_out);
}

/*
 * Free the SockHandler structure
 */
void sock_handler_free(SockHandler *sh)
{
   g_free(sh->buf);
   g_free(sh);
}

/* ------------------------------------------------------------------------ */

