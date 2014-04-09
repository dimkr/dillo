/*
 * File: bookmark.c
 *
 * Copyright 2002 Jorge Arellano Cid <jcid@dillo.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg.h"
#include "browser.h"
#include "history.h"
#include "menu.h"
#include "capi.h"
#include "nav.h"
#include "misc.h"
#include "bookmark.h"  /* for prototypes */
#include "../dpip/dpip.h"



/*
 * Initialize the bookmarks module
 */
void a_Bookmarks_init(void)
{
   /* simple isn't it? ;) */
}

/*
 * Have a short chat with the bookmarks server,
 * and finally ask it to add a new bookmark.
 * (this is an example of dpi chat)
 */
void a_Bookmarks_chat_add(BrowserWindow *Bw, char *Cmd, char *answer)
{
   static char *cmd1 = NULL, *cmd2 = NULL, *cmd3 = NULL, *cmd4 = NULL;
   static BrowserWindow *bw = NULL;

   if (!cmd1) {
      cmd1 = a_Dpip_build_cmd("cmd=%s msg=%s", "chat", "Hi server");
      cmd2 = a_Dpip_build_cmd("cmd=%s msg=%s", "chat",
                              "I want to set a bookmark");
      cmd3 = a_Dpip_build_cmd("cmd=%s msg=%s", "chat", "Sure it is!");
   }

   _MSG("a_Bookmarks_chat_add\n answer=%s\n", answer ? answer : "(null)");

   if (Bw)
      bw = Bw;
   if (!cmd4 && Cmd)
      cmd4 = g_strdup(Cmd);

   if (!answer) {
      a_Capi_dpi_send_cmd(NULL, bw, cmd1, "bookmarks", 1);

   } else {
      /* we have an answer */
      if (answer) {
         if (*answer == 'H') {
            /* "Hi browser" */
            a_Capi_dpi_send_cmd(NULL, bw, cmd2, "bookmarks", 0);
         } else if (*answer == 'I') {
            /* "Is it worth?" */
            a_Capi_dpi_send_cmd(NULL, bw, cmd3, "bookmarks", 0);
         } else if (*answer == 'O') {
            /* "OK, send it!" */
            a_Capi_dpi_send_cmd(NULL, bw, cmd4, "bookmarks", 0);
            g_free(cmd4);
            cmd4 = NULL;
         }
      }
   }
}

/*
 * Add the new bookmark through the bookmarks server
 */
void a_Bookmarks_add(GtkWidget *widget, gpointer client_data)
{
   BrowserWindow *bw = (BrowserWindow *)client_data;
   DilloUrl *url;
   const gchar *title;
   gchar *cmd;

   url = a_Menu_popup_get_url(bw);
   g_return_if_fail(url != NULL);

   /* if the page has no title, we'll use the url string */
   title = a_History_get_title_by_url(url, 1);

   cmd = a_Dpip_build_cmd("cmd=%s url=%s title=%s",
                          "add_bookmark", URL_STR(url), title);
   a_Bookmarks_chat_add(bw, cmd, NULL);
   g_free(cmd);
}

/*
 * Request the server to show the bookmarks
 */
void a_Bookmarks_show(BrowserWindow *bw)
{
   DilloUrl *url;

   url = a_Url_new("dpi:/bm/", NULL, 0, 0, 0);
   a_Nav_push(bw, url);
   a_Url_free(url);
}

