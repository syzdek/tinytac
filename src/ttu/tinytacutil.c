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
#define _SRC_TTU_TINYTACUTIL_C 1
#include "tinytacutil.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>

#include <tinytac.h>
#include <bindle_prefix.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "tinytac"

#ifndef PACKAGE_BUGREPORT
#   define PACKAGE_BUGREPORT "unknown"
#endif
#ifndef PACKAGE_COPYRIGHT
#   define PACKAGE_COPYRIGHT "unknown"
#endif
#ifndef PACKAGE_NAME
#   define PACKAGE_NAME "Tiny RADIUS Client Library"
#endif
#ifndef PACKAGE_VERSION
#   define PACKAGE_VERSION "unknown"
#endif


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
main(
         int                           argc,
         char *                        argv[] );


static void
ttu_cleanup(
         ttu_config_t *                cnf );


static ttu_widget_t *
ttu_widget_lookup(
         const char *                  wname,
         int                           exact );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark ttu_widget_map[]
ttu_widget_t ttu_widget_map[] =
{
   {  .name       = "acct",
      .desc       = "TACACS+ accounting client",
      .usage      = NULL,
      .aliases    = (const char * const[]) { "accounting", NULL },
      .func_exec  = &ttu_widget_acct,
      .func_usage = NULL,
   },
   {  .name       = "authen",
      .desc       = "TACACS+ authentication client",
      .usage      = " username",
      .aliases    = (const char * const[]) { "authentication", NULL },
      .func_exec  = &ttu_widget_authen,
      .func_usage = NULL,
   },
   {  .name       = "author",
      .desc       = "TACACS+ authorization client",
      .usage      = " username cmd [ arg1 arg2 ... argN ]",
      .aliases    = (const char * const[]) { "authorization", NULL },
      .func_exec  = &ttu_widget_author,
      .func_usage = NULL,
   },
   {  .name       = "config",
      .desc       = "print configuration",
      .usage      = NULL,
      .aliases    = (const char * const[]) { "configuration", NULL },
      .func_exec  = &ttu_widget_config,
      .func_usage = NULL,
   },
   {  .name       = NULL,
      .desc       = NULL,
      .usage      = NULL,
      .aliases    = NULL,
      .func_exec  = NULL,
      .func_usage = NULL,
   }
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//---------------//
// main function //
//---------------//
#pragma mark main function

int main(int argc, char * argv[])
{
   int                           rc;
   ttu_config_t                  cnfdata;

   memset(&cnfdata, 0, sizeof(cnfdata));

   // determine program name
   if ((cnfdata.prog_name = strrchr(argv[0], '/')) != NULL)
      cnfdata.prog_name = &cnfdata.prog_name[1];
   if (!(cnfdata.prog_name))
      cnfdata.prog_name = argv[0];

   // initialize state
   if ((rc = tinytac_set_option(NULL, TTAC_OPT_DEBUG_IDENT, PROGRAM_NAME)) != TTAC_SUCCESS)
   {
      fprintf(stderr, "%s: tinytac_set_option(%s): %s\n", PROGRAM_NAME, "TTAC_OPT_DEBUG_IDENT", tinytac_strerror(rc));
      return(1);
   };
   if ((rc = tinytac_initialize(&cnfdata.tt, NULL, NULL, 0)) != TTAC_SUCCESS)
   {
      fprintf(stderr, "%s: tinytac_initialize(): %s\n", PROGRAM_NAME, tinytac_strerror(rc));
      return(1);
   };

   // skip argument processing if called via alias
   if ((cnfdata.widget = ttu_widget_lookup(cnfdata.prog_name, TTAC_YES)) != NULL)
   {
      cnfdata.argc        = argc;
      cnfdata.argv        = argv;
      rc = cnfdata.widget->func_exec(&cnfdata);
      ttu_cleanup(&cnfdata);
      return(rc);
   };

   // initial processing of cli arguments
   if ((rc = ttu_cli_arguments(&cnfdata, argc, argv)) != 0)
      return((rc == -1) ? 0 : 1);
   if ((argc - optind) < 1)
   {
      fprintf(stderr, "%s: missing required argument\n", cnfdata.prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnfdata.prog_name);
      return(1);
   };
   cnfdata.argc        = (argc - optind);
   cnfdata.argv        = &argv[optind];

   // looks up widget
   if ((cnfdata.widget = ttu_widget_lookup(argv[optind], TTAC_NO)) == NULL)
   {
      fprintf(stderr, "%s: unknown or ambiguous widget -- \"%s\"\n", cnfdata.prog_name, cnfdata.argv[0]);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnfdata.prog_name);
      return(1);
   };

   rc = cnfdata.widget->func_exec(&cnfdata);
   ttu_cleanup(&cnfdata);

   return(rc);
}


//-------------------//
// logging functions //
//-------------------//
#pragma mark logging functions

int
ttu_error(
         ttu_config_t *                cnf,
         int                           rc,
         const char *                  fmt,
         ... )
{
   va_list args;
   if ((cnf->opts & TTUTILS_OPT_QUIET))
      return(rc);
   fprintf(stderr, "%s: ", (((cnf->prog_name)) ? cnf->prog_name : PROGRAM_NAME));
   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
   fprintf(stderr, "\n");
   return(rc);
}


int
ttu_printf(
         ttu_config_t *                cnf,
         const char *                  fmt,
         ... )
{
   int            rc;
   va_list        args;
   if ((cnf->opts & TTUTILS_OPT_QUIET))
      return(0);
   va_start(args, fmt);
   rc = vprintf(fmt, args);
   va_end(args);
   return(rc);
}


int
tru_verbose(
         ttu_config_t *                cnf,
         const char *                  fmt,
         ... )
{
   int            rc;
   va_list        args;
   if (!(cnf->opts & TTUTILS_OPT_VERBOSE))
      return(0);
   va_start(args, fmt);
   rc = vprintf(fmt, args);
   va_end(args);
   return(rc);
}


//-------------------------//
// miscellaneous functions //
//-------------------------//
#pragma mark miscellaneous functions

void
ttu_cleanup(
         ttu_config_t *                cnf )
{
   tinytac_free(cnf->tt);
   if ((cnf->pass_buff))
      free(cnf->pass_buff);
   return;
}


char *
ttu_file2str(
         const char *                  path )
{
   int               fd;
   struct stat       sb;
   char *            str;

   if (stat(path, &sb) == -1)
      return(NULL);

   if ((str = malloc(sb.st_size+1)) == NULL)
      return(NULL);

   if ((fd = open(path, O_RDONLY)) == -1)
   {
      free(str);
      return(NULL);
   }

   if (read(fd, str, sb.st_size) == -1)
   {
      close(fd);
      free(str);
      return(NULL);
   };

   str[sb.st_size] = '\0';
   close(fd);

   tinytacb_strchomp(str, NULL);

   return(str);
}


int
ttu_password(
         ttu_config_t *                cnf )
{
   const char *   pass;

   if ((cnf->pass))
      return(0);

   // process password file
   if ((cnf->pass_file))
   {
      if ((cnf->pass_buff))
         free(cnf->pass_buff);
      if ((cnf->pass_buff = ttu_file2str(cnf->pass_file)) == NULL)
         return(ttu_error(cnf, 1, "%s: %s", cnf->pass_file, strerror(errno)));
      cnf->pass = cnf->pass_buff;
   };

   // prompt for password
   if ((cnf->opts & TTUTILS_OPT_PASSPROMPT))
   {
      if ((pass = tinytacb_getpass("Enter TACACS+ Password: ")) == NULL)
         return(ttu_error(cnf, 1, "getpass: %s", strerror(errno)));
      if ((cnf->pass_buff))
         free(cnf->pass_buff);
      if ((cnf->pass_buff = tinytacb_strdup(pass)) == NULL)
         return(ttu_error(cnf, 1, "%s", strerror(errno)));
      cnf->pass = cnf->pass_buff;
   };

   return(0);
}


//-----------------//
// usage functions //
//-----------------//
#pragma mark usage functions

int
ttu_cli_arguments(
         ttu_config_t *                cnf,
         int                           argc,
         char * const *                argv )
{
   int            c;
   int            opt_index;
   int            opt;
   int            ival;
   int            rc;

   // getopt options
   static const char *  short_opt = "+46a:dH:hVvqWw:y:";
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   optind    = 1;
   opt_index = 0;

   if ((cnf->widget))
      short_opt = &short_opt[1];

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case '4':
         ival = TTAC_YES; tinytac_set_option(cnf->tt, TTAC_OPT_IPV4, &ival);
         ival = TTAC_NO;  tinytac_set_option(cnf->tt, TTAC_OPT_IPV6, &ival);
         break;

         case '6':
         ival = TTAC_YES; tinytac_set_option(cnf->tt, TTAC_OPT_IPV6, &ival);
         ival = TTAC_NO;  tinytac_set_option(cnf->tt, TTAC_OPT_IPV4, &ival);
         break;

         case 'a':
         opt = 0;
         if      (!(strcasecmp(optarg, "ascii")))    opt = TTAC_OPT_AUTHEN_ASCII;
         else if (!(strcasecmp(optarg, "chap")))     opt = TTAC_OPT_AUTHEN_CHAP;
         else if (!(strcasecmp(optarg, "mschap")))   opt = TTAC_OPT_AUTHEN_MSCHAP;
         else if (!(strcasecmp(optarg, "mschapv2"))) opt = TTAC_OPT_AUTHEN_MSCHAPV2;
         else if (!(strcasecmp(optarg, "pap")))      opt = TTAC_OPT_AUTHEN_PAP;
         else
         {  fprintf(stderr, "%s: unknown authentication type `%s'\n", PROGRAM_NAME, optarg);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         ival = TTAC_NO;  tinytac_set_option(cnf->tt, TTAC_OPT_AUTHEN_ALL, &ival);
         ival = TTAC_YES; tinytac_set_option(cnf->tt, opt, &ival);
         break;

         case 'd':
         ival = TTAC_DEBUG_ANY; tinytac_set_option(NULL, TTAC_OPT_DEBUG_LEVEL, &ival);
         break;

         case 'H':
         if ((rc = tinytac_set_option(cnf->tt, TTAC_OPT_HOSTS, optarg)) != TTAC_SUCCESS)
            return(ttu_error(cnf, 1, "tinytac_set_option(TTAC_OPT_HOSTS): %s", tinytac_strerror(rc)));
         break;

         case 'h':
         ttu_usage(cnf);
         return(-1);

         case 'q':
         cnf->opts |=  TTUTILS_OPT_QUIET;
         cnf->opts &= ~TTUTILS_OPT_VERBOSE;
         break;

         case 'V':
         printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
         return(-1);

         case 'v':
         cnf->opts |=  TTUTILS_OPT_VERBOSE;
         cnf->opts &= ~TTUTILS_OPT_QUIET;
         break;

         case 'W':
         cnf->opts      |= TTUTILS_OPT_PASSPROMPT;
         cnf->pass       = NULL;
         cnf->pass_file  = NULL;
         break;

         case 'w':
         cnf->opts      &= ~TTUTILS_OPT_PASSPROMPT;
         cnf->pass       = optarg;
         cnf->pass_file  = NULL;
         break;

         case 'y':
         cnf->opts      &= ~TTUTILS_OPT_PASSPROMPT;
         cnf->pass       = NULL;
         cnf->pass_file  = optarg;
         break;

         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
   };

   return(0);
}


int
ttu_usage(
         ttu_config_t *                cnf )
{
   size_t            pos;
   const char *      widget_name;
   const char *      widget_help;
   ttu_widget_t *    widget;

   widget_name  = (!(cnf->widget)) ? "widget" : cnf->widget->name;
   widget_help  = "";
   if ((cnf->widget))
      widget_help = ((cnf->widget->usage)) ? cnf->widget->usage : "";

   printf("Usage: %s [OPTIONS] %s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("       %s-%s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("       %s%s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("OPTIONS:\n");
   printf("  -4                        use IPv4\n");
   printf("  -6                        use IPv6\n");
   printf("  -a type                   authen type: ascii, pap, chap, mschap, or mschapv2\n");
   printf("  -d, --debug               print debug messages\n");
   printf("  -H host                   TACACS+ host\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -q, --quiet, --silent     do not print messages\n");
   printf("  -V, --version             print version number and exit\n");
   printf("  -v, --verbose             print verbose messages\n");
   printf("  -W                        prompt for authentication password\n");
   printf("  -w passwd                 authentication password\n");
   printf("  -y file                   read password from file\n");
   if (!(cnf->widget))
   {
      printf("WIDGETS:\n");
      for(pos = 0; ttu_widget_map[pos].name != NULL; pos++)
      {
         widget = &ttu_widget_map[pos];
         if ((widget->desc))
            printf("  %-25s %s\n", widget->name, widget->desc);
      };
   };
   if ((cnf->widget))
      if ((cnf->widget->func_usage))
         cnf->widget->func_usage(cnf);
   printf("\n");

   return(0);
}


ttu_widget_t *
ttu_widget_lookup(
         const char *                  wname,
         int                           exact )
{
   size_t                     x;
   size_t                     y;
   size_t                     len;
   size_t                     wname_len;
   const char *               alias;
   ttu_widget_t *             match;
   ttu_widget_t *             widget;

   // strip program prefix from widget name
   len = strlen(PROGRAM_NAME);
   if (!(strncasecmp(wname, PROGRAM_NAME, len)))
      wname = &wname[len];
   if (wname[0] == '-')
      wname = &wname[1];
   if (!(wname[0]))
      return(NULL);

   match       = NULL;
   wname_len   = strlen(wname);

   for(x = 0; ((ttu_widget_map[x].name)); x++)
   {
      // check widget
      widget = &ttu_widget_map[x];
      if (widget->func_exec == NULL)
         continue;

      // compare widget name for match
      if (!(strncmp(widget->name, wname, wname_len)))
      {
         if (widget->name[wname_len] == '\0')
            return(widget);
         if ( ((match)) && (match != widget) )
            return(NULL);
         if (exact == TTAC_NO)
            match = widget;
      };

      if (!(widget->aliases))
         continue;

      for(y = 0; ((widget->aliases[y])); y++)
      {
         alias = widget->aliases[y];
         if (!(strncmp(alias, wname, wname_len)))
         {
            if (alias[wname_len] == '\0')
               return(widget);
            if ( ((match)) && (match != widget) )
               return(NULL);
            if (exact == TTAC_NO)
               match = widget;
         };
      };
   };

   return((exact == TTAC_NO) ? match : NULL);
}


/* end of source */
