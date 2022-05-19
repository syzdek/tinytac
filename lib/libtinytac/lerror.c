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
#define _LIB_LIBTINYTAC_LERROR_C 1
#include "lerror.h"


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
#include <syslog.h>
#include <stdatomic.h>
#include <assert.h>


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static const char *
tinytac_error_map(
         int                           errnum );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

static const char *
tinytac_error_map(
         int                           errnum )
{
   TinyTacDebugTrace();
   switch(errnum)
   {
      case TTAC_SUCCESS:      return("success");
      case TTAC_EUNKNOWN:     return("unknown error");
      case TTAC_ENOMEM:       return("out of virtual memory");
      case TTAC_EACCES:       return("permission denied");
      case TTAC_ENOENT:       return("no such file or directory");
      case TTAC_ESYNTAX:      return("invalid or unrecognized syntax");
      case TTAC_ENOBUFS:      return("no buffer space available");
      case TTAC_EEXISTS:      return("dictionary object exists");
      case TTAC_EINVAL:       return("invalid argument");
      case TTAC_EOPTION:      return("invalid or unknown option");
      case TTAC_EOPTVAL:      return("invalid option value");
      default:
      break;
   };
   return("unknown error code");
}


char *
tinytac_strerror(
         int                           errnum )
{
   static char buff[128];
   TinyTacDebugTrace();
   return(tinytac_strerror_r(errnum, buff, sizeof(buff)));
}


char *
tinytac_strerror_r(
         int                           errnum,
         char *                        strerrbuf,
         size_t                        buflen )
{
   const char *   msg;
   TinyTacDebugTrace();
   assert(strerrbuf != NULL);
   assert(buflen > 1);
   msg = tinytac_error_map(errnum);
   tinytacb_strlcpy(strerrbuf, msg, buflen);
   return(strerrbuf);
}


/* end of source */
