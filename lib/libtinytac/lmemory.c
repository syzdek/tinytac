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
#define _LIB_LIBTINYTAC_LMEMORY_C 1
#include "lmemory.h"


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
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define TRAD_SOCKET_BIND_ADDRESSES_LEN (INET6_ADDRSTRLEN+INET6_ADDRSTRLEN+2)


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//--------------------//
// TinyTac prototypes //
//--------------------//
#pragma mark TinyTac prototypes

extern void
tinytac_tiytac_free(
         TinyTac *                     tt );


//-------------------//
// object prototypes //
//-------------------//
#pragma mark object prototypes

static int
tinytac_verify_is_obj(
         TinyTacObj *                  obj );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

const char *            tinytac_dflt_hosts      = TTAC_DFLT_HOSTS;
char                    tinytac_dflt_hosts_buff[128];
unsigned                tinytac_dflt_opts       = TTAC_DFLT_OPTS;
unsigned                tinytac_dflt_opts_neg   = TTAC_DFLT_OPTS_NEG;


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//-------------------//
// TinyTac functions //
//-------------------//
#pragma mark TinyTac functions

void
tinytac_tiytac_free(
         TinyTac *                     tt )
{
   TinyTacDebugTrace();

   assert(tt != NULL);

   if ((tt->hosts))
      free(tt->hosts);
   if ((tt->key))
      free(tt->key);

   memset(tt, 0, sizeof(TinyTac));
   free(tt);

   return;
}


int
tinytac_get_option(
         TinyTac *                     tt,
         int                           option,
         void *                        outvalue )
{
   const char *   str;
   unsigned *     optsp;

   TinyTacDebugTrace();

   assert(outvalue != NULL);

   // get global options
   switch(option)
   {
      case TTAC_OPT_AUTHEN_ASCII:
      optsp = ((tt)) ? &tt->opts : &tinytac_dflt_opts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_ASCII, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((*optsp & TTAC_ASCII)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((*optsp & TTAC_ASCII)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_AUTHEN_CHAP:
      optsp = ((tt)) ? &tt->opts : &tinytac_dflt_opts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_CHAP, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((*optsp & TTAC_CHAP)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((*optsp & TTAC_CHAP)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_AUTHEN_MSCHAP:
      optsp = ((tt)) ? &tt->opts : &tinytac_dflt_opts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_MSCHAP, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((*optsp & TTAC_MSCHAP)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((*optsp & TTAC_MSCHAP)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_AUTHEN_MSCHAPV2:
      optsp = ((tt)) ? &tt->opts : &tinytac_dflt_opts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_MSCHAPV2, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((*optsp & TTAC_MSCHAPV2)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((*optsp & TTAC_MSCHAPV2)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_AUTHEN_PAP:
      optsp = ((tt)) ? &tt->opts : &tinytac_dflt_opts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_PAP, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((*optsp & TTAC_PAP)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((*optsp & TTAC_PAP)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_DEBUG_IDENT:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( tt, TTAC_OPT_DEBUG_IDENT, outvalue )", __func__);
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", tinytac_debug_ident);
      if ((*((char **)outvalue) = tinytacb_strdup(tinytac_debug_ident)) == NULL)
         return(TTAC_ENOMEM);
      return(TTAC_SUCCESS);

      case TTAC_OPT_DEBUG_LEVEL:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( tt, TTAC_OPT_DEBUG_LEVEL, outvalue )", __func__);
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: 0x%08x", tinytac_debug_level);
      *((int *)outvalue) = tinytac_debug_level;
      return(TTAC_SUCCESS);

      case TTAC_OPT_DEBUG_SYSLOG:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( tt, TTAC_OPT_DEBUG_SYSLOG, outvalue )", __func__);
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", ((tinytac_debug_syslog)) ? "TTAC_YES" : "TTAC_NO");
      *((int *)outvalue) = ((tinytac_debug_syslog)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_HOSTS:
      str = ((tt)) ? tt->hosts : tinytac_dflt_hosts;
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_HOSTS, outvalue )", __func__, (((tt)) ? "tt" : "NULL"));
      TinyTacDebug(TTAC_DEBUG_ARGS, "   <= outvalue: %s", str);
      if ((*((char **)outvalue) = tinytacb_strdup(str)) == NULL)
         return(TTAC_ENOMEM);
      return(TTAC_SUCCESS);

      default:
      break;
   };

   return(TTAC_EOPT);
}


int
tinytac_initialize(
         TinyTac **                    ttp,
         const char *                  hosts,
         const char *                  key,
         unsigned                      opts )
{
   TinyTac *         tt;

   TinyTacDebugTrace();

   assert(ttp != NULL);

   if ((tt = tinytac_obj_alloc(sizeof(TinyTac), (void(*)(void*))&tinytac_tiytac_free)) == NULL)
      return(TTAC_ENOMEM);

   // adjust options
   tt->opts = opts;
   if (!(tt->opts & TTAC_IP_UNSPEC))
      tt->opts |= TTAC_IP_UNSPEC;
   if (!(tt->opts & TTAC_AUTHEN_TYPES))
      tt->opts |= TTAC_AUTHEN_TYPES;

   if ((tt->hosts = strdup(hosts)) == NULL)
   {
      tinytac_tiytac_free(tt);
      return(TTAC_ENOMEM);
   };
   if ((tt->key = strdup(key)) == NULL)
   {
      tinytac_tiytac_free(tt);
      return(TTAC_ENOMEM);
   };

   *ttp = tinytac_obj_retain(&tt->obj);

   return(TTAC_SUCCESS);
}


//------------------//
// object functions //
//------------------//
#pragma mark object functions

void
tinytac_free(
         void *                        ptr )
{
   TinyTacDebugTrace();
   if (!(ptr))
      return;
   if (tinytac_verify_is_obj(ptr) == TTAC_NO)
   {
      free(ptr);
      return;
   };
   tinytac_obj_release(ptr);
   return;
}


void *
tinytac_obj_alloc(
         size_t                        size,
         void (*free_func)(void * ptr) )
{
   TinyTacObj *      obj;
   TinyTacDebugTrace();
   assert(size > sizeof(TinyTacObj));
   if ((obj = malloc(size)) == NULL)
      return(NULL);
   memset(obj, 0, size);
   memcpy(obj->magic, TTAC_MAGIC, 8);
   atomic_init(&obj->ref_count, 0);
   obj->free_func = ((free_func)) ? free_func : &free;
   return(obj);
}


void
tinytac_obj_release(
         TinyTacObj *                  obj )
{
   TinyTacDebugTrace();
   assert(obj != NULL);
   assert(tinytac_verify_is_obj(obj) == TTAC_YES);
   if (atomic_fetch_sub(&obj->ref_count, 1) > 1)
      return;
   obj->free_func(obj);
   return;
}


void *
tinytac_obj_retain(
         TinyTacObj *                  obj )
{
   TinyTacDebugTrace();
   if (obj == NULL)
      return(NULL);
   assert(tinytac_verify_is_obj(obj) == TTAC_YES);
   atomic_fetch_add(&obj->ref_count, 1);
   return(obj);
}


intptr_t
tinytac_obj_retain_count(
         TinyTacObj *                  obj )
{
   TinyTacDebugTrace();
   if (obj == NULL)
      return(0);
   assert(tinytac_verify_is_obj(obj) == TTAC_YES);
   return(atomic_fetch_add(&obj->ref_count, 0));
}


int
tinytac_verify_is_obj(
         TinyTacObj *                  obj )
{
   size_t   pos;
   TinyTacDebugTrace();
   if (!(obj))
      return(TTAC_NO);
   for(pos = 0; (pos < 8); pos++)
      if (obj->magic[pos] != TTAC_MAGIC[pos])
         return(TTAC_NO);
   return(TTAC_YES);
}


/* end of source */
