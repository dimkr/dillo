/*
 * Dpi for FTP.
 *
 * This server checks the ftp-URL to be a directory (requires wget).
 * If true, it sends back an html representation of it, and if not
 * a dpip message (which is catched by dillo who redirects the ftp URL
 * to the downloads server).
 *
 * Feel free to polish!
 *
 * Copyright 2003-2005 Jorge Arellano Cid <jcid@dillo.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/*
 * TODO:
 * - Send feedback about the FTP login process from wget's stderr.
 *   i.e. capture our child's stderr, process it, and report back.
 * - Handle simultaneous connections.
 *   If ftp.dpi is implemented with a low level ftp library, it becomes
 *   possible to keep the connection alive, and thus make browsing of ftp
 *   directories faster (this avoids one login per page, and forks). Perhaps
 *   it's not worth, but can be done.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/time.h>
#include <ctype.h>

#include <glib.h>

#include "../dpip/dpip.h"
#include "dpiutil.h"

/*
 * Debugging macros
 */
#define _MSG(fmt...)
#define MSG(fmt...)  g_printerr("[ftp dpi]: " fmt)

/*
 * Global variables
 */
static SockHandler *sh = NULL;
char **dl_argv = NULL;

/*---------------------------------------------------------------------------*/

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
int a_Misc_get_content_type_from_data(void *Data, size_t Size,
                                       const char **PT)
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

/*---------------------------------------------------------------------------*/

/*
 * Build a shell command using wget for this URL.
 */
static void make_wget_argv(gchar *url)
{
   gchar *esc_url;

   if (dl_argv) {
      g_free(dl_argv[2]);
      g_free(dl_argv);
   }
   dl_argv = g_new(gchar*, 10);

   esc_url = Escape_uri_str(url, "'");
   /* avoid malicious SMTP relaying with FTP urls */
   Filter_smtp_hack(esc_url);

   dl_argv[0] = "wget";
   dl_argv[1] = "-O-";
   dl_argv[2] = g_strdup(esc_url);
   dl_argv[3] = NULL;
/*
   dl_argv[0] = "wget";
   dl_argv[1] = "-t2";
   dl_argv[2] = "-O-";
   dl_argv[3] = g_strdup_printf("'%s'", esc_url);
   dl_argv[4] = "2>/dev/null";
   dl_argv[5] = NULL;
*/
   g_free(esc_url);
}

/*
 * Fork, exec command, get its output and send via stdout.
 * Return: Number of bytes transfered.
 */
static gint try_ftp_transfer(gchar *url)
{
#define MinSZ 256

   ssize_t n;
   gint nb, minibuf_sz;
   const gchar *mime_type;
   char buf[4096], minibuf[MinSZ], *d_cmd;
   pid_t ch_pid;
   gint aborted = 0;
   int DataPipe[2];

   if (pipe(DataPipe) < 0) {
      MSG("pipe, %s\n", strerror(errno));
      return 0;
   }

   /* Prepare args for execvp() */
   make_wget_argv(url);

   /* Start the child process */
   if ((ch_pid = fork()) == 0) {
      /* child */
      /* start wget */
      close(DataPipe[0]);
      dup2(DataPipe[1], 1); /* stdout */
      execvp(dl_argv[0], dl_argv);
      _exit(1);
   } else if (ch_pid < 0) {
      perror("fork, ");
      exit(1);
   } else {   
      /* father continues below */
      close(DataPipe[1]);
   }

   /* Read/Write the real data */
   minibuf_sz = 0;
   for (nb = 0; 1; nb += n) {
      while ((n = read(DataPipe[0], buf, 4096)) < 0 && errno == EINTR);
      if (n <= 0)
         break;

      if (minibuf_sz < MinSZ) {
         memcpy(minibuf + minibuf_sz, buf, MIN(n, MinSZ - minibuf_sz));
         minibuf_sz += MIN(n, MinSZ - minibuf_sz);
         if (minibuf_sz < MinSZ)
            continue;
         a_Misc_get_content_type_from_data(minibuf, minibuf_sz, &mime_type);
         if (strcmp(mime_type, "application/octet-stream") == 0) {
            /* abort transfer */
            kill(ch_pid, SIGTERM);
            /* The "application/octet-stream" MIME type will be sent and
             * Dillo will offer a download dialog */
            aborted = 1;
         }
      }

      if (nb == 0) {
         /* Send dpip tag */
         d_cmd = a_Dpip_build_cmd("cmd=%s url=%s", "start_send_page", url);
         sock_handler_write_str(sh, d_cmd, 1);
         g_free(d_cmd);

         /* Send HTTP header. */
         sock_handler_write_str(sh, "Content-type: ", 0);
         sock_handler_write_str(sh, mime_type, 0);
         sock_handler_write_str(sh, "\n\n", 1);
      }

      if (!aborted)
         sock_handler_write(sh, buf, n, 0);
   }

   return nb;
}

/*
 *
 */
int main(void)
{
   gchar *dpip_tag = NULL, *cmd = NULL, *url = NULL, *url2 = NULL;
   gint nb;
   gchar *p, *d_cmd;

   /* Initialize the SockHandler */
   sh = sock_handler_new(STDIN_FILENO, STDOUT_FILENO, 8*1024);

   /* wget may need to write a temporary file... */
   chdir("/tmp");

   /* Read the dpi command from STDIN */
   dpip_tag = sock_handler_read(sh);
   g_printerr("ftp.dpi::[%s]\n", dpip_tag);

   cmd = a_Dpip_get_attr(dpip_tag, strlen(dpip_tag), "cmd");
   url = a_Dpip_get_attr(dpip_tag, strlen(dpip_tag), "url");
   if (!cmd || !url) {
      g_printerr("ftp.dpi:: Error, cmd=%s, url=%s\n", cmd, url);
      exit (EXIT_FAILURE);
   }

   if ((nb = try_ftp_transfer(url)) == 0) {
      /* Transfer failed, the requested file may not exist or be a symlink
       * to a directory. Try again... */
      if ((p = strrchr(url, '/')) && p[1]) {
         url2 = g_strconcat(url, "/", NULL);
         nb = try_ftp_transfer(url2);
      }
   }

   if (nb == 0) {
      /* The transfer failed, let dillo know... */
      d_cmd = a_Dpip_build_cmd("cmd=%s to_cmd=%s msg=%s",
                               "answer", "open_url", "not a directory");
      sock_handler_write_str(sh, d_cmd, 1);
      g_free(d_cmd);
   }

   g_free(cmd);
   g_free(url);
   g_free(url2);
   g_free(dpip_tag);

   /* Finish the SockHandler */
   sock_handler_close(sh);
   sock_handler_free(sh);

   return 0;
}

