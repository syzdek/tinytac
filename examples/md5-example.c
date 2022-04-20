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
#define _EXAMPLES_MD5_EXAMPLE_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <assert.h>
#include <getopt.h>
#include <sys/time.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "md5-example"
#ifndef PACKAGE_BUGREPORT
#   define PACKAGE_BUGREPORT "unknown"
#endif
#ifndef PACKAGE_COPYRIGHT
#   define PACKAGE_COPYRIGHT "unknown"
#endif
#ifndef PACKAGE_NAME
#   define PACKAGE_NAME "Tiny TACACS+ Client Library"
#endif
#ifndef PACKAGE_VERSION
#   define PACKAGE_VERSION "unknown"
#endif

#define MY_VERBOSE      0x0001U
#define MY_QUIET        0x0002U
#define MY_TEST         0x0004U

#define MY_CYCLES       1000000


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


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int
main(
         int                           argc,
         char *                        argv[] )
{
   int                  c;
   int                  opt_index;
   int                  i;
   int                  cycle;
   unsigned             pos;
   unsigned             opts;
   unsigned             md_len;
   unsigned char        md_value[EVP_MAX_MD_SIZE];
   EVP_MD_CTX *         mdctx;
   struct timeval       tv1;
   struct timeval       tv2;
   uint64_t             usec;

   // getopt options
   static char          short_opt[] = "hqtVv";
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   opts = 0;

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'h':
         printf("Usage: %s [OPTIONS] string\n", PROGRAM_NAME);
         printf("Options:\n");
         printf("  -h, --help                                print this help and exit\n");
         printf("  -q, --quiet, --silent                     do not print messages\n");
         printf("  -t                                        run speed test\n");
         printf("  -V, --version                             print version number and exit\n");
         printf("  -v, --verbose                             print verbose messages\n");
         printf("\n");
         return(0);

         case 'q':
         opts |= MY_QUIET;
         opts &= ~MY_VERBOSE;
         break;

         case 't':
         opts |= MY_TEST;
         break;

         case 'V':
         printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
         return(0);

         case 'v':
         opts |= MY_VERBOSE;
         opts &= ~MY_QUIET;
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
   if (optind >= argc)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // loop through strings
   if (!(opts & MY_TEST))
   {
      for(i = optind; (i < argc); i++)
      {
         mdctx = EVP_MD_CTX_new();
         EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
         EVP_DigestUpdate(mdctx, argv[i], strlen(argv[i]));
         EVP_DigestFinal_ex(mdctx, md_value, &md_len);
         EVP_MD_CTX_free(mdctx);

         printf("MD5 (\"%s\") = ", argv[i]);
         for (pos = 0; (pos < md_len); pos++)
            printf("%02x", md_value[pos]);
         printf("\n");
      };
      return(0);
   };

   memset(md_value, 0, sizeof(md_value));
   md_len = (unsigned)strlen(argv[optind]);
   md_len = (md_len > sizeof(md_value)) ? sizeof(md_value) : md_len;
   memcpy(md_value, argv[optind], md_len);
   gettimeofday(&tv1, NULL);
   for(cycle = 0; (cycle < MY_CYCLES); cycle++)
   {
      for(i = optind; (i < argc); i++)
      {
         mdctx = EVP_MD_CTX_new();
         EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
         EVP_DigestUpdate(mdctx, md_value, md_len);
         EVP_DigestFinal_ex(mdctx, md_value, &md_len);
         EVP_MD_CTX_free(mdctx);
      };
   };
   gettimeofday(&tv2, NULL);
   usec = (((tv2.tv_sec - tv1.tv_sec) * 1000000) + tv2.tv_usec) - tv1.tv_usec;
   printf("EVP_DigestInit_ex(): %u usec\n", (unsigned)usec);

   memset(md_value, 0, sizeof(md_value));
   md_len = (unsigned)strlen(argv[optind]);
   md_len = (md_len > sizeof(md_value)) ? sizeof(md_value) : md_len;
   memcpy(md_value, argv[optind], md_len);
   gettimeofday(&tv1, NULL);
   for(cycle = 0; (cycle < MY_CYCLES); cycle++)
   {
      for(i = optind; (i < argc); i++)
      {
         EVP_Digest(md_value, md_len, md_value, &md_len, EVP_md5(), NULL);
      };
   };
   gettimeofday(&tv2, NULL);
   usec = (((tv2.tv_sec - tv1.tv_sec) * 1000000) + tv2.tv_usec) - tv1.tv_usec;
   printf("EVP_Digest():        %u usec\n", (unsigned)usec);

   return(0);
}


/* end of source */
