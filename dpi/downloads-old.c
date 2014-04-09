/*
 * Downloads server (chat version).
 *
 * NOTE: A simple downloads dpi that illustrates how to make a dpi-server.
 *
 * It uses wget to download a link.  This has been tested with wget 1.8.1
 * The server accepts multiple connections once it has been started.
 * If there are no requests within 5 minutes it waits for all child processes
 * to finish and then it exits.
 *
 * Copyright 2002-2004 Jorge Arellano Cid <jcid@dillo.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */


#include <config.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/time.h>
#include <glib.h>
#include "../dpip/dpip.h"
#include "dpiutil.h"

/*
 * Debugging macros
 */
#define _MSG(fmt...)
#define _CMSG(fmt...)
#define MSG(fmt...)  g_print("[downloads dpi]: " fmt)
#define CMSG(fmt...)  g_print("[downloads (child)]: " fmt)

pid_t origpid, fpid;

/*---------------------------------------------------------------------------*/

/*
 * Make a new name and place it in 'dl_dest'.
 */
static void make_new_name(gchar **dl_dest, const gchar *url)
{
   GString *gstr = g_string_new(*dl_dest);
   gint idx = gstr->len;

   if (gstr->str[idx - 1] != '/'){
      g_string_append_c(gstr, '/');
      ++idx;
   }

   /* Use a mangled url as name */
   g_string_append(gstr, url);
   for (   ; idx < gstr->len; ++idx)
      if (!isalnum(gstr->str[idx]))
         gstr->str[idx] = '_';

   /* free memory */
   g_free(*dl_dest);
   *dl_dest = gstr->str;
   g_string_free(gstr, FALSE);
}


/*---------------------------------------------------------------------------*/

/*
 * SIGCHLD handler
 */
static void sigchld(int sig)
{
   MSG("received sigchld, pid=%d\n", origpid);
   fflush(stderr);
   while (waitpid(0, NULL, WNOHANG) > 0) {
   }
}

/*
 * Establish SIGCHLD handler
 */
static void est_sigchld(void)
{
   struct sigaction act;
   sigset_t block;

   sigemptyset(&block);
   sigaddset(&block, SIGCHLD);
   act.sa_handler = sigchld;
   act.sa_mask = block;
   act.sa_flags = SA_NOCLDSTOP;
   sigaction(SIGCHLD, &act, NULL);
}

/*
 * Read a single line from a socket and store it in a GString.
 */
static ssize_t readline(int socket, GString ** msg)
{
   ssize_t st;
   gchar buf[16384], *aux;

   /* can't use fread() */
   do
      st = read(socket, buf, 16384);
   while (st < 0 && errno == EINTR);

   if (st == -1)
      MSG("readline, %s\n", strerror(errno));

   if (st > 0) {
      aux = g_strndup(buf, (guint)st);
      g_string_assign(*msg, aux);
      g_free(aux);
   } else {
      g_string_assign(*msg, "");
   }

   return st;
}


/*!
 * Main download process.
 */
int main(void)
{
   int new_socket, ns;
   socklen_t csz;
   ssize_t rdlen;
   struct sockaddr_un clnt_addr;

   //char *wget_cmd = "wget --no-parent -t 1 -nc -k -nH --cut-dirs=30 -P";
   //char *wget_cmd = "wget -t 1 -nH -P";  --doesn't rename, +other problems
   char *wget_cmd = "wget -O - --load-cookies $HOME/.dillo/cookies.txt ";

   char *url = NULL, *esc_url = NULL, *dl_dest = NULL, *cmd = NULL;
   GString *gs_dl_cmd, *tag;
   fd_set active_set, selected_set;
   struct timeval tout;
   sigset_t blockSC;

   origpid = getpid();
   fpid = origpid;
   MSG("v1.1 started (pid=%u)\n", origpid);
   fflush(stdout);
   sigemptyset(&blockSC);
   sigaddset(&blockSC, SIGCHLD);
   est_sigchld();

   csz = (socklen_t) sizeof(clnt_addr);
   FD_ZERO(&active_set);
   FD_SET(STDIN_FILENO, &active_set);
   while (1) {
      MSG("before select\n");
      do {
         /* exit if there are no download requests after this time */
         tout.tv_sec = TOUT;
         tout.tv_usec = 0;
         selected_set = active_set;
         ns = select(STDIN_FILENO + 1, &selected_set, NULL, NULL, &tout);
      } while (ns == -1 && errno == EINTR);
      MSG("after select\n");

      if (ns == -1) {
         MSG("select, %s\n", strerror(errno));
         exit(1);

      } else if (ns == 0) {     /* exit if no download requests */
         close(STDIN_FILENO);
         printf("downloads server %d:Terminating.\n"
                "Waiting for children to finish\n", origpid);
         fflush(stdout);
         /* BUG? Any further calls to downloads server will be queued by dpid
          * until all the children have finished.  This could be a long time */
         while (waitpid(-1, NULL, 0) >= 0) {
         }
         printf("\n\nDL_SRV %d: EXITING\n", origpid);
         fflush(stdout);
         exit(0);

      } else {
         /* accept the request */
         do {
            new_socket = accept(STDIN_FILENO, (struct sockaddr *) &clnt_addr,
                                &csz);
         } while (new_socket == -1 && errno == EINTR);

         if (new_socket == -1) {
            MSG("accept, %s\n", strerror(errno));
            exit(1);
         }
      }

      sigprocmask(SIG_BLOCK, &blockSC, NULL);
      tag = g_string_new(NULL);
      MSG("before readline\n");
      rdlen = readline(new_socket, &tag);
      MSG("after readline\n");
      MSG("[%s]\n", tag->str);

      if ((cmd = a_Dpip_get_attr(tag->str, (size_t)tag->len, "cmd")) == NULL) {
         MSG("Failed to parse 'cmd' in %s\n", tag->str);
         exit(1);
      }
      if (strcmp(cmd, "DpiBye") == 0) {
         MSG("got DpiBye, terminating.\n");
         exit(0);
      }
      if (strcmp(cmd, "download") != 0) {
         MSG("unknown command: '%s'. Aborting.\n", cmd);
         exit(1);
      }
      g_free(cmd);

      fpid = fork();
      if (fpid == 0) {
         pid_t ppid, cpid;
         FILE *in_stream, *out_stream;
         gchar buf[4096];
         struct stat sb;
         size_t n;

         origpid = cpid = getpid();
         ppid = getppid();
         CMSG("pid=%u, from parent=%u\n", (unsigned)cpid, (unsigned)ppid);
         if (!(url = a_Dpip_get_attr(tag->str,(size_t)tag->len, "url"))){
            CMSG("Failed to parse 'url' in %s\n", tag->str);
            exit(1);
         }

         dl_dest = a_Dpip_get_attr(tag->str, (size_t)tag->len, "destination");
         if (dl_dest == NULL) {
            CMSG("Failed to parse 'destination' in %s\n", tag->str);
            exit(1);
         }

         CMSG("url=%s, dl_dest=%s\n", url, dl_dest);

         /* 'dl_dest' may be a directory */
         if (stat(dl_dest, &sb) == 0 && S_ISDIR(sb.st_mode))
            make_new_name(&dl_dest, url);

         /* open the target stream */
         if ((out_stream = fopen(dl_dest, "w")) == NULL) {
            CMSG("%s\n", strerror(errno));
            exit(1);
         }

         /* make the download command string */
         gs_dl_cmd = g_string_new(NULL);
         /* escape "'" character for the shell */
         esc_url = Escape_uri_str(url, "'");
         /* avoid malicious SMTP relaying with FTP urls */
         if (g_strncasecmp(esc_url, "ftp:/", 5) == 0)
            Filter_smtp_hack(esc_url);
         g_string_sprintf(gs_dl_cmd, "%s '%s'", wget_cmd, esc_url);
         CMSG(" cmd: %s\n", gs_dl_cmd->str);
         CMSG("  to: %s\n", dl_dest);

         g_free(dl_dest);
         g_free(esc_url);
         g_free(url);

         CMSG("pid=%u, Running: %s\n", cpid, gs_dl_cmd->str);

         /* fork through popen */
         if ((in_stream = popen(gs_dl_cmd->str, "r")) == NULL) {
            CMSG("popen, %s\n", strerror(errno));
            exit(1);
         }

         /* do the file transfer */
         while ((n = fread (buf, 1, 4096, in_stream)) > 0)
            fwrite(buf, 1, n, out_stream);

         /* close transfer */
         if (pclose(in_stream) != 0)
            CMSG("pclose, %s\n", strerror(errno));
         if (fclose(out_stream) != 0)
            CMSG("fclose, %s\n", strerror(errno));

         g_string_free(gs_dl_cmd, TRUE);


         if (close(new_socket) == -1) {
            CMSG("close, %s\n", strerror(errno));
            exit(EXIT_FAILURE);
         }

         CMSG("pid=%u, done!\n", cpid);
         exit(0);
      }
      g_string_free(tag, TRUE);
      sigprocmask(SIG_UNBLOCK, &blockSC, NULL);
      close(new_socket);
   }
}

