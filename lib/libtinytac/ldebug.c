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
#define _LIB_LIBTINYTAC_LDEBUG_C 1
#include "ldebug.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#undef NDEBUG

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <syslog.h>
#include <stdatomic.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef GIT_PACKAGE_MAJOR
#   define GIT_PACKAGE_MAJOR 0
#endif
#ifndef GIT_PACKAGE_MINOR
#   define GIT_PACKAGE_MINOR 0
#endif
#ifndef GIT_PACKAGE_PATCH
#   define GIT_PACKAGE_PATCH 0
#endif
#ifndef GIT_PACKAGE_BUILD
#   define GIT_PACKAGE_BUILD "g0000000"
#endif
#ifndef GIT_PACKAGE_VERSION_BUILD
#   define GIT_PACKAGE_VERSION_BUILD "0.0.0.g0000000"
#endif


#ifndef LIB_VERSION_CURRENT
#   define LIB_VERSION_CURRENT 0
#endif
#ifndef LIB_VERSION_REVISION
#   define LIB_VERSION_REVISION 0
#endif
#ifndef LIB_VERSION_AGE
#   define LIB_VERSION_AGE 0
#endif
#ifndef LIB_VERSION_INFO
#   define LIB_VERSION_INFO "0:0:0"
#endif


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

// yes, global variables are evil...
const char *   tinytac_debug_ident     = TTAC_DFLT_DEBUG_IDENT;
char           tinytac_debug_ident_buff[128];
int            tinytac_debug_level     = TTAC_DFLT_DEBUG_LEVEL;
int            tinytac_debug_syslog    = TTAC_DFLT_DEBUG_SYSLOG;


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void
tinytac_debug(
         int                           level,
         const char *                  fmt,
         ... )
{
   va_list  args;

   if ( ((level & tinytac_debug_level) == 0) || (!(fmt)) )
      return;

   if (!(tinytac_debug_syslog))
      printf("%s: DEBUG: ", tinytac_debug_ident);

   va_start(args, fmt);
   if ((tinytac_debug_syslog))
      vsyslog(LOG_DEBUG, fmt, args);
   else
      vprintf(fmt, args);
   va_end(args);

   if (!(tinytac_debug_syslog))
      printf("\n");

   return;
}

/* end of source */
