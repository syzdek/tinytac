/*
 *  Tiny TACACS+ Client Library
 *  Copyright (C) 2022 David M. Syzdek <david@syzdek.net>.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of David M. Syzdek nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. SYZDEK BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */
#define _LIB_LIBTINYTAC_LCONF_C 1
#include "lconf.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <pwd.h>
#include <stdatomic.h>
#include <assert.h>

#include "lmemory.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef SYSCONFDIR
#   define SYSCONFDIR "/etc"
#endif

#define TTAC_OTYPE_NONE    0
#define TTAC_OTYPE_INT     1
#define TTAC_OTYPE_STR     2
#define TTAC_OTYPE_FLAG    3
#define TTAC_OTYPE_TV      4
#define TTAC_OTYPE_UINT    5
#define TTAC_OTYPE_OTHER   ~0


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types

typedef struct _tinytac_opt
{
   const char *          opt_name;
   uintptr_t             opt_id;
   uintptr_t             opt_type;
} tinytac_opt_t;


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark tinytac_conf_init
static atomic_int tinytac_conf_init;


#pragma mark tinytac_conf_options[]
static tinytac_opt_t tinytac_conf_options[] =
{
   { .opt_name = "AUTHEN_ASCII",       .opt_id = TTAC_OPT_AUTHEN_ASCII,    .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "AUTHEN_CHAP",        .opt_id = TTAC_OPT_AUTHEN_CHAP,     .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "AUTHEN_MSCHAP",      .opt_id = TTAC_OPT_AUTHEN_MSCHAP,   .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "AUTHEN_MSCHAPV2",    .opt_id = TTAC_OPT_AUTHEN_MSCHAPV2, .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "AUTHEN_PAP",         .opt_id = TTAC_OPT_AUTHEN_PAP,      .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "DEBUG_LEVEL",        .opt_id = TTAC_OPT_DEBUG_LEVEL,     .opt_type = TTAC_OTYPE_UINT },
   { .opt_name = "DEBUG_SYSLOG",       .opt_id = TTAC_OPT_DEBUG_SYSLOG,    .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "HOST",               .opt_id = TTAC_OPT_HOSTS,           .opt_type = TTAC_OTYPE_STR },
   { .opt_name = "IPV4",               .opt_id = TTAC_OPT_IPV4,            .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "IPV6",               .opt_id = TTAC_OPT_IPV6,            .opt_type = TTAC_OTYPE_FLAG },
   { .opt_name = "KEY",                .opt_id = TTAC_OPT_KEY,             .opt_type = TTAC_OTYPE_STR },
   { .opt_name = "NETWORK_TIMEOUT",    .opt_id = TTAC_OPT_NETWORK_TIMEOUT, .opt_type = TTAC_OTYPE_TV },
   { .opt_name = "RANDOM",             .opt_id = TTAC_OPT_RANDOM,          .opt_type = TTAC_OTYPE_OTHER },
   { .opt_name = "STOPINIT",           .opt_id = TTAC_OPT_STOPINIT,        .opt_type = TTAC_OTYPE_NONE },
   { .opt_name = "TIMEOUT",            .opt_id = TTAC_OPT_TIMEOUT,         .opt_type = TTAC_OTYPE_INT },
   { .opt_name = NULL,                 .opt_id = 0,                        .opt_type = 0 }
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static int
tinytac_conf_environment(
         void );


static int
tinytac_conf_file(
         const char *                  path );


static int
tinytac_conf_opt(
         const tinytac_opt_t *         opt,
         const char *                  value );


static int
tinytac_conf_opt_flag(
         const tinytac_opt_t *         opt,
         const char *                  value );


static int
tinytac_conf_opt_int(
         const tinytac_opt_t *         opt,
         const char *                  value );


static int
tinytac_conf_opt_timeval(
         const tinytac_opt_t *         opt,
         const char *                  value );


static void
tinytac_conf_print_line(
         int                           comment,
         const char *                  name,
         const char *                  value );


static tinytac_opt_t *
tinytac_opt_lookup_name(
         const char *                  name );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions


int
tinytac_conf(
         unsigned                      opts )
{
   int               rc;
   const char *      tintacrc;
   const char *      tinytacconf;
   char              buff[4096];
   char              path[128];
   const char *      home;
   struct passwd     pwd;
   struct passwd *   pwres;

   TinyTacDebugTrace();

   // exit if init is disabled or already initialized
   if ( ((opts & TTAC_NOINIT)) || ((tinytac_dflt.opts & TTAC_NOINIT)) )
      return(TTAC_SUCCESS);
   if ((atomic_fetch_or(&tinytac_conf_init, 1)))
      return(TTAC_SUCCESS);
   if ((getenv("TINYTACNOINIT")))
      return(TTAC_SUCCESS);
   if ((getenv("TINYTAC_NOINIT")))
      return(TTAC_SUCCESS);

   // system information
   getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &pwres);
   home = (((pwres)) ? pwres->pw_dir : "/");

   // load defaults
   if ((rc = tinytac_defaults(NULL)) != TTAC_SUCCESS)
      return(rc);

   // process "/usr/local/etc/tinytac.conf"
   tinytac_conf_file(SYSCONFDIR "/tinytac.conf");

   // process "~/tinytacrc"
   tinytacb_strlcpy(path, home,           sizeof(path));
   tinytacb_strlcat(path, "/tinytacrc",   sizeof(path));
   if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
      return(TTAC_SUCCESS);

   // process "~/.tinytacrc"
   tinytacb_strlcpy(path, home,           sizeof(path));
   tinytacb_strlcat(path, "/.tinytacrc",  sizeof(path));
   if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
      return(TTAC_SUCCESS);

   // process "./tinytacrc"
   tinytacb_strlcpy(path, "./tinytacrc",  sizeof(path));
   if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
      return(TTAC_SUCCESS);

   // process "${TINYTACCONF}"
   if ((tinytacconf = getenv("TINYTACCONF")) != NULL)
      if (tinytac_conf_file(tinytacconf) == TTAC_ESTOPINIT)
         return(TTAC_SUCCESS);

   // determine TINYTACRC suffix
   if ((tintacrc = getenv("TINYTACRC")) != NULL)
   {
      // process "~/${TINYTACRC}"
      tinytacb_strlcpy(path, home,        sizeof(path));
      tinytacb_strlcat(path, "/",         sizeof(path));
      tinytacb_strlcat(path, tintacrc,    sizeof(path));
      if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
         return(TTAC_SUCCESS);

      // process "~/.{$TINYTACRC}"
      tinytacb_strlcpy(path, home,        sizeof(path));
      tinytacb_strlcat(path, "/.",        sizeof(path));
      tinytacb_strlcat(path, tintacrc,    sizeof(path));
      if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
         return(TTAC_SUCCESS);

      // process "./${TINYTACRC}"
      tinytacb_strlcpy(path, "./",        sizeof(path));
      tinytacb_strlcat(path, tintacrc,    sizeof(path));
      if (tinytac_conf_file(path) == TTAC_ESTOPINIT)
         return(TTAC_SUCCESS);
   };

   // process environment variables
   if (tinytac_conf_environment() == TTAC_ESTOPINIT)
      return(TTAC_SUCCESS);

   return(TTAC_SUCCESS);
}


int
tinytac_conf_environment(
         void )
{
   size_t                  pos;
   char *                  value;
   char                    varname[64];
   tinytac_opt_t *         opt;

   TinyTacDebugTrace();

   for(pos = 0; ((tinytac_conf_options[pos].opt_name)); pos++)
   {
      opt = &tinytac_conf_options[pos];
      if (opt->opt_id == TTAC_OPT_STOPINIT)
         continue;
      tinytacb_strlcpy(varname, "TINYTAC_", sizeof(varname));
      tinytacb_strlcat(varname, opt->opt_name, sizeof(varname));
      if ((value = getenv(varname)) != NULL)
         tinytac_conf_opt(opt, value);
   };

   if (getenv("TINYTAC_STOPINIT") != NULL)
      return(TTAC_ESTOPINIT);

   return(TTAC_SUCCESS);
}


int
tinytac_conf_file(
         const char *                  path )
{
   int                     fd;
   int                     rc;
   ssize_t                 len;
   int                     argc;
   char                    buff[TTAC_LINE_MAX_LEN];
   char                    value[TTAC_LINE_MAX_LEN];
   char **                 argv;
   const char *            val;
   const tinytac_opt_t *   opt;

   TinyTacDebugTrace();

   len = 1;
   rc  = TTAC_SUCCESS;

   if (!(path))
      return(TTAC_SUCCESS);
   if ((fd = open(path, O_RDONLY)) == -1)
      return(TTAC_SUCCESS);

   while( ((len)) && (rc == TTAC_SUCCESS) )
   {
      if ((len = tinytacb_readline(fd, buff, sizeof(buff))) == -1)
      {
         close(fd);
         return(TTAC_EUNKNOWN);
      };
      if (!(len))
         continue;
      if (tinytacb_strtoargs(buff, &argv, &argc) != TTAC_SUCCESS)
      {
         close(fd);
         return(TTAC_ESYNTAX);
      };
      if ( (argc < 1) || (argc > 2) )
      {
         tinytacb_strsfree(argv);
         continue;
      };
      if ((opt = tinytac_opt_lookup_name(argv[0])) == NULL)
      {
         tinytacb_strsfree(argv);
         continue;
      };
      val = tinytacb_strexpand(value, argv[1], sizeof(value), TTAC_NO);
      switch(tinytac_conf_opt(opt, val))
      {
         case TTAC_ESTOPINIT: rc = TTAC_ESTOPINIT; break;
         case TTAC_ENOMEM:    rc = TTAC_ENOMEM;    break;
         default:                                  break;
      };
      tinytacb_strsfree(argv);
   };

   close(fd);

   return(rc);
}


int
tinytac_conf_opt(
         const tinytac_opt_t *         opt,
         const char *                  value )
{
   int               ival;

   TinyTacDebugTrace();

   switch(opt->opt_id)
   {
      case TTAC_OPT_AUTHEN_ASCII:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_AUTHEN_ASCII, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_AUTHEN_CHAP:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_AUTHEN_CHAP, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_AUTHEN_MSCHAP:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_AUTHEN_MSCHAP, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_AUTHEN_MSCHAPV2:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_AUTHEN_MSCHAPV2, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_AUTHEN_PAP:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_AUTHEN_PAP, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_DEBUG_LEVEL:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_DEBUG_LEVEL, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_int(opt, value));

      case TTAC_OPT_DEBUG_SYSLOG:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_DEBUG_SYSLOG, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_HOSTS:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_HOSTS, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_set_option(NULL, TTAC_OPT_HOSTS, value));

      case TTAC_OPT_IPV4:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_IPV4, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_IPV6:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_IPV6, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_KEY:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_KEY, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      if ((tinytac_dflt.keys))
         return(TTAC_SUCCESS);
      return(tinytac_set_option(NULL, TTAC_OPT_KEY, value));

      case TTAC_OPT_NETWORK_TIMEOUT:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_NETWORK_TIMEOUT, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_timeval(opt, value));

      case TTAC_OPT_NOINIT:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_NOINIT, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_flag(opt, value));

      case TTAC_OPT_RANDOM:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( tr, TTAC_OPT_RANDOM, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      if      (!(strcasecmp(value, "rand")))    ival = TTAC_RAND;
      else if (!(strcasecmp(value, "random")))  ival = TTAC_RANDOM;
      else if (!(strcasecmp(value, "urandom"))) ival = TTAC_URANDOM;
      else return(TTAC_SUCCESS);
      return(tinytac_set_option(NULL, TTAC_OPT_RANDOM, &ival));

      case TTAC_OPT_STOPINIT:
      return(TTAC_ESTOPINIT);

      case TTAC_OPT_TIMEOUT:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( TTAC_OPT_TIMEOUT, \"%s\" )", __func__, (((value)) ? value : "(null)"));
      return(tinytac_conf_opt_int(opt, value));

      default:
      break;
   };

   return(TTAC_SUCCESS);
}


int
tinytac_conf_opt_flag(
         const tinytac_opt_t *         opt,
         const char *                  value )
{
   int               i;

   TinyTacDebugTrace();

   switch(i = ((value)) ? tinytacb_strtobool(value) : TTAC_YES)
   {
      case TTAC_NO:  return(tinytac_set_option(NULL, (int)opt->opt_id, &i));
      case TTAC_YES: return(tinytac_set_option(NULL, (int)opt->opt_id, &i));
      default: break;
   };

   return(TTAC_SUCCESS);
}


int
tinytac_conf_opt_int(
         const tinytac_opt_t *         opt,
         const char *                  value )
{
   int      i;
   char *   endptr;

   TinyTacDebugTrace();

   if ((i = (int)strtoll(value, &endptr, 10)) < 1)
      return(TTAC_SUCCESS);
   if ((endptr[0]))
      return(TTAC_SUCCESS);

   return(tinytac_set_option(NULL, (int)opt->opt_id, &i));
}


int
tinytac_conf_opt_timeval(
         const tinytac_opt_t *         opt,
         const char *                  value )
{
   char *            endptr;
   struct timeval    tv;

   TinyTacDebugTrace();

   tv.tv_usec = 0;
   if ((tv.tv_sec = strtoull(value, &endptr, 10)) < 1)
      return(TTAC_SUCCESS);
   if ((endptr[0]))
      return(TTAC_SUCCESS);

   return(tinytac_set_option(NULL, (int)opt->opt_id, &tv));
}


void
tinytac_conf_print(
         TinyTac *                     tt )
{
   size_t            pos;
   tinytac_opt_t *   opt;
   int               ival;
   char *            str;
   struct timeval *  tv;
   char              buff[1024];

   printf("# TinyTac Library Configuration:\n");
   for(pos = 0; ((tinytac_conf_options[pos].opt_name)); pos++)
   {
      opt = &tinytac_conf_options[pos];
      switch(opt->opt_type)
      {
         case TTAC_OTYPE_FLAG:
         if ((tinytac_get_option(tt, (int)opt->opt_id, &ival)) == TTAC_SUCCESS)
            tinytac_conf_print_line(0, opt->opt_name, (((ival)) ? "yes" : "no"));
         break;

         case TTAC_OTYPE_INT:
         if ((tinytac_get_option(tt, (int)opt->opt_id, &ival)) == TTAC_SUCCESS)
         {
            snprintf(buff, sizeof(buff), "%i", ival);
            tinytac_conf_print_line(0, opt->opt_name, buff);
         };
         break;

         case TTAC_OTYPE_NONE:
         break;

         case TTAC_OTYPE_STR:
         if ((tinytac_get_option(tt, (int)opt->opt_id, &str)) == TTAC_SUCCESS)
         {
            snprintf(buff, sizeof(buff), "'%s'", str);
            tinytac_conf_print_line(0, opt->opt_name, buff);
            free(str);
         };
         break;

         case TTAC_OTYPE_OTHER:
         if (opt->opt_id == TTAC_OPT_RANDOM)
         {  if ((tinytac_get_option(tt, TTAC_OPT_RANDOM, &ival)) == TTAC_SUCCESS)
            {  switch(ival)
               {  case TTAC_RAND:    tinytac_conf_print_line(0, "rand", "rand"); break;
                  case TTAC_RANDOM:  tinytac_conf_print_line(0, "rand", "random"); break;
                  case TTAC_URANDOM: tinytac_conf_print_line(0, "rand", "urandom"); break;
                  default:           tinytac_conf_print_line(1, "rand", "unknown option"); break;
               };
            };
         };
         break;

         case TTAC_OTYPE_TV:
         if ((tinytac_get_option(tt, (int)opt->opt_id, &tv)) == TTAC_SUCCESS)
         {
            snprintf(buff, sizeof(buff), "%u", (unsigned)tv->tv_sec);
            tinytac_conf_print_line(0, opt->opt_name, buff);
            free(tv);
         };
         break;

         case TTAC_OTYPE_UINT:
         if ((tinytac_get_option(tt, (int)opt->opt_id, &ival)) == TTAC_SUCCESS)
         {
            snprintf(buff, sizeof(buff), "%u", (unsigned)ival);
            tinytac_conf_print_line(0, opt->opt_name, buff);
         };
         break;

         default:
         break;
      };
   };

   return;
}


void
tinytac_conf_print_line(
         int                           comment,
         const char *                  name,
         const char *                  value )
{
   printf("%s%-20s %s\n", (((comment)) ? "#" : ""), name, value);
   return;
}


tinytac_opt_t *
tinytac_opt_lookup_name(
         const char *                  name )
{
   size_t pos;
   if (!(name))
      return(NULL);
   for(pos = 0; ((tinytac_conf_options[pos].opt_name)); pos++)
      if (!(strcasecmp(tinytac_conf_options[pos].opt_name, name)))
         return(&tinytac_conf_options[pos]);
   return(NULL);
}

/* end of source */
