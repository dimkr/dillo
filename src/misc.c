/*
 * File: misc.c
 *
 * Copyright (C) 2000 Jorge Arellano Cid <jcid@dillo.org>,
 *                    Jörgen Viksell <vsksga@hotmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "msg.h"
#include "misc.h"

/*
 * Prepend the users home-dir to 'file' string i.e,
 * pass in .dillo/bookmarks.html and it will return
 * /home/imain/.dillo/bookmarks.html
 *
 * Remember to g_free() returned value!
 */
gchar *a_Misc_prepend_user_home(const char *file)
{
   return ( g_strconcat(g_get_home_dir(), "/", file, NULL) );
}

/*
 * Escape characters as %XX sequences.
 * Return value: New string, or NULL if there's no need to escape.
 */
gchar *a_Misc_escape_chars(const gchar *str, gchar *esc_set)
{
   static const char *hex = "0123456789ABCDEF";
   gchar *p = NULL;
   GString *gstr;
   gint i;

   for (i = 0; str[i]; ++i)
      if (str[i] <= 0x1F || str[i] == 0x7F || strchr(esc_set, str[i]))
         break;

   if (str[i]) {
      /* needs escaping */
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
   }
   return p;
}

/*
 * Case insensitive strstr
 */
gchar *a_Misc_stristr(char *src, char *str)
{
   int i, j;

   for (i = 0, j = 0; src[i] && str[j]; ++i)
      if (tolower(src[i]) == tolower(str[j])) {
         ++j;
      } else if (j) {
         i -= j;
         j = 0;
      }

   if (!str[j])                 /* Got all */
      return (src + i - j);
   return NULL;
}

/*
 * strsep implementation
 */
gchar *a_Misc_strsep(char **orig, const char *delim)
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

#define TAB_SIZE 8
/*
 * Takes a string and converts any tabs to spaces.
 */
gchar *a_Misc_expand_tabs(const char *str)
{
   GString *New = g_string_new("");
   int len, i, j, pos, old_pos;
   char *val;

   if ( (len = strlen(str)) ) {
      for (pos = 0, i = 0; i < len; i++) {
         if (str[i] == '\t') {
            /* Fill with whitespaces until the next tab. */
            old_pos = pos;
            pos += TAB_SIZE - (pos % TAB_SIZE);
            for (j = old_pos; j < pos; j++)
               g_string_append_c(New, ' ');
         } else {
            g_string_append_c(New, str[i]);
            pos++;
         }
      }
   }
   val = New->str;
   g_string_free(New, FALSE);
   return val;
}

/*
 * Split a string into tokens, at any character contained by delim,
 * and return the starting and ending positions within the string. For
 * n tokens, the returned array has at least 2 * n + 1 elements, and
 * contains the start of token i at 2 * i, the end at 2 * i + 1. The
 * array is terminated by -1.
 */
gint *a_Misc_strsplitpos(const gchar *str, const gchar *delim)
{
   gint array_max = 4;
   gint *array = g_new(gint, array_max);
   gint n = 0;
   gint p1 = 0, p2;

   while (TRUE) {
      while (str[p1] != 0 && strchr(delim, str[p1]) != NULL)
         p1++;
      if (str[p1] == 0)
         break;

      p2 = p1;
      while (str[p2] != 0 && strchr(delim, str[p2]) == NULL)
         p2++;

      if (array_max < 2 * n + 3) {
         array_max <<= 2;
         array = g_realloc(array, array_max * sizeof(gint));
      }

      array[2 * n] = p1;
      array[2 * n + 1] = p2;
      n++;

      if (str[p2] == 0)
         break;
      else {
         p1 = p2;
      }
   }

   array[2 * n] = -1;
   return array;
}

/*
 * Return a copy of an array which was created by a_Misc_strsplitpos.
 */
gint *a_Misc_strsplitposdup(gint *pos)
{
   gint n = 0;
   gint *pos2;
   while (pos[2 * n] != -1)
      n++;
   pos2 = g_new(gint, 2 * n + 1);
   memcpy(pos2, pos, (2 * n + 1) * sizeof(gint));
   return pos2;
}

/* TODO: could use dStr ADT! */
typedef struct ContentType_ {
   const char *str;
   int len;
} ContentType_t;

static const ContentType_t MimeTypes[] = {
   { "application/octet-stream", 24 },
   { "text/html", 9 },
   { "text/plain", 10 },
   { "image/gif", 9 },
   { "image/png", 9 },
   { "image/jpeg", 10 },
   { NULL, 0 }
};

/*
 * Detects 'Content-Type' from a data stream sample.
 *
 * It uses the magic(5) logic from file(1). Currently, it
 * only checks the few mime types that Dillo supports.
 *
 * 'Data' is a pointer to the first bytes of the raw data.
 *
 * Return value: (0 on success, 1 on doubt, 2 on lack of data).
 */
int a_Misc_get_content_type_from_data(void *Data, size_t Size, const char **PT)
{
   int st = 1;      /* default to "doubt' */
   int Type = 0;    /* default to "application/octet-stream" */
   char *p = Data;
   size_t i, non_ascci;

   /* HTML try */
   for (i = 0; i < Size && isspace(p[i]); ++i);
   if ((Size - i >= 5  && !g_strncasecmp(p+i, "<html", 5)) ||
       (Size - i >= 5  && !g_strncasecmp(p+i, "<head", 5)) ||
       (Size - i >= 6  && !g_strncasecmp(p+i, "<title", 6)) ||
       (Size - i >= 14 && !g_strncasecmp(p+i, "<!doctype html", 14)) ||
       /* this line is workaround for FTP through the Squid proxy */
       (Size - i >= 17 && !g_strncasecmp(p+i, "<!-- HTML listing", 17))) {

      Type = 1;
      st = 0;
   /* Images */
   } else if (Size >= 4 && !g_strncasecmp(p, "GIF8", 4)) {
      Type = 3;
      st = 0;
   } else if (Size >= 4 && !g_strncasecmp(p, "\x89PNG", 4)) {
      Type = 4;
      st = 0;
   } else if (Size >= 2 && !g_strncasecmp(p, "\xff\xd8", 2)) {
      /* JPEG has the first 2 bytes set to 0xffd8 in BigEndian - looking
       * at the character representation should be machine independent. */
      Type = 5;
      st = 0;

   /* Text */
   } else {
      /* We'll assume "text/plain" if the set of chars above 127 is <= 10
       * in a 256-bytes sample.  Better heuristics are welcomed! :-) */
      non_ascci = 0;
      Size = MIN (Size, 256);
      for (i = 0; i < Size; i++)
         if ((unsigned char) p[i] > 127)
            ++non_ascci;
      if (Size == 256) {
         Type = (non_ascci > 10) ? 0 : 2;
         st = 0;
      } else {
         Type = (non_ascci > 0) ? 0 : 2;
      }
   }

   *PT = MimeTypes[Type].str;
   return st;
}

/*
 * Check the server-supplied 'Content-Type' against our detected type.
 * (some servers seem to default to "text/plain").
 *
 * Return value:
 *  0,  if they match
 *  -1, if a mismatch is detected
 *
 * There're many MIME types Dillo doesn't know, they're handled
 * as "application/octet-stream" (as the SPEC says).
 *
 * A mismatch happens when receiving a binary stream as
 * "text/plain" or "text/html", or an image that's not an image of its kind.
 *
 * Note: this is a basic security procedure.
 *
 */
int a_Misc_content_type_check(const char *EntryType, const char *DetectedType)
{
   int i;
   int st = -1;

   MSG("Type check:  [Srv: %s  Det: %s]\n", EntryType, DetectedType);

   if (!EntryType)
      return 0; /* there's no mismatch without server type */

   for (i = 1; MimeTypes[i].str; ++i)
      if (g_strncasecmp(EntryType, MimeTypes[i].str, MimeTypes[i].len) == 0)
         break;

   if (!MimeTypes[i].str) {
      /* type not found, no mismatch */
      st = 0;
   } else if (g_strncasecmp(EntryType, "image/", 6) == 0 &&
             !g_strncasecmp(DetectedType,MimeTypes[i].str,MimeTypes[i].len)){
      /* An image, and there's an exact match */
      st = 0;
   } else if (g_strncasecmp(EntryType, "text/", 5) ||
              g_strncasecmp(DetectedType, "application/", 12)) {
      /* Not an application sent as text */
      st = 0;
   }

   return st;
} 

/*
 * Parse a geometry string.
 */
gint a_Misc_parse_geometry(gchar *str, gint *x, gint *y, gint *w, gint *h)
{
   gchar *p, *t1, *t2;
   gint n1, n2;
   gint ret = 0;

   if ((p = strchr(str, 'x')) || (p = strchr(str, 'X'))) {
      n1 = strtol(str, &t1, 10);
      n2 = strtol(++p, &t2, 10);
      if (t1 != str && t2 != p) {
         *w = n1;
         *h = n2;
         ret = 1;
         /* parse x,y now */
         p = t2;
         n1 = strtol(p, &t1, 10);
         n2 = strtol(t1, &t2, 10);
         if (t1 != p && t2 != t1) {
            *x = n1;
            *y = n2;
         }
      }
   }
   _MSG("geom: w,h,x,y = (%d,%d,%d,%d)\n", *w, *h, *x, *y);
   return ret;
}

/*
 * Encodes string using base64 encoding.
 * Return value: new string or NULL if input string is empty.
 */
gchar *a_Misc_encode_base64(const gchar *in)
{
   static const char *base64_hex = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";
   gchar *out = NULL;
   int len, i = 0;

   if (in == NULL) return NULL;
   len = strlen(in);

   out = (gchar *)g_malloc((len + 2) / 3 * 4 + 1);

   for (; len >= 3; len -= 3) {
      out[i++] = base64_hex[in[0] >> 2];
      out[i++] = base64_hex[((in[0]<<4) & 0x30) | (in[1]>>4)];
      out[i++] = base64_hex[((in[1]<<2) & 0x3c) | (in[2]>>6)];
      out[i++] = base64_hex[in[2] & 0x3f];
      in += 3;
   }

   if (len > 0) {
      unsigned char fragment;
      out[i++] = base64_hex[in[0] >> 2];
      fragment = (in[0] << 4) & 0x30;
      if (len > 1) fragment |= in[1] >> 4;
      out[i++] = base64_hex[fragment];
      out[i++] = (len < 2) ? '=' : base64_hex[(in[1] << 2) & 0x3c];
      out[i++] = '=';
   }
   out[i] = '\0';
   return out;
}
