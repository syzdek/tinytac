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
#include <errno.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define TTAC_SOCKET_BIND_ADDRESSES_LEN (INET6_ADDRSTRLEN+INET6_ADDRSTRLEN+2)


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
tinytac_tinytac_free(
         TinyTac *                     tt );


static void
tinytac_tinytac_free_budps(
         BindleURLDesc **              budps );


static int
tinytac_set_option_flag(
         TinyTac *                     tt,
         unsigned                      flag,
         const int *                   invalue );


static int
tinytac_set_option_host(
         TinyTac *                     tt,
         const char *                  invalue );


static int
tinytac_set_option_keys(
         TinyTac *                     tt,
         const char *                  invalue,
         char * const *                invalues );


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
char *                  tinytac_dflt_hosts_buff = NULL;
unsigned                tinytac_dflt_opts       = TTAC_DFLT_OPTS;
unsigned                tinytac_dflt_opts_neg   = TTAC_DFLT_OPTS_NEG;
char **                 tinytac_dflt_keys       = NULL;


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
tinytac_tinytac_free(
         TinyTac *                     tt )
{
   TinyTacDebugTrace();

   assert(tt != NULL);

   if ((tt->hosts))
      free(tt->hosts);
   if ((tt->keys))
      tinytacb_strsfree(tt->keys);

   tinytac_tinytac_free_budps(tt->budps);

   memset(tt, 0, sizeof(TinyTac));
   free(tt);

   return;
}


void
tinytac_tinytac_free_budps(
         BindleURLDesc **              budps )
{
   size_t pos;
   if (!(budps))
      return;
   for(pos = 0; ((budps[pos])); pos++)
      tinytacb_urldesc_free(budps[pos]);
   free(budps);
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

   return(TTAC_EOPTION);
}


int
tinytac_initialize(
         TinyTac **                    ttp,
         const char *                  hosts,
         const char *                  key,
         unsigned                      opts )
{
   TinyTac *         tt;
   int               rc;

   TinyTacDebugTrace();

   assert(ttp != NULL);

   if ((tt = tinytac_obj_alloc(sizeof(TinyTac), (void(*)(void*))&tinytac_tinytac_free)) == NULL)
      return(TTAC_ENOMEM);

   // adjust options
   tt->opts = opts;
   if (!(tt->opts & TTAC_IP_UNSPEC))
      tt->opts |= TTAC_IP_UNSPEC;
   if (!(tt->opts & TTAC_AUTHEN_TYPES))
      tt->opts |= TTAC_AUTHEN_TYPES;

   if ((rc = tinytac_set_option(tt, TTAC_OPT_HOSTS, hosts)) != TTAC_SUCCESS)
   {
      tinytac_tinytac_free(tt);
      return(rc);
   };
   if ((rc = tinytac_set_option(tt, TTAC_OPT_KEY, key)) != TTAC_SUCCESS)
   {
      tinytac_tinytac_free(tt);
      return(rc);
   };

   *ttp = tinytac_obj_retain(&tt->obj);

   return(TTAC_SUCCESS);
}


int
tinytac_set_option(
         TinyTac *                     tt,
         int                           option,
         const void *                  invalue )
{
   int            ival;
   const char *   istr;

   TinyTacDebugTrace();

   assert(invalue != NULL);

   switch(option)
   {
      case TTAC_OPT_AUTHEN_ASCII:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_ASCII, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_flag(tt, TTAC_ASCII, invalue));

      case TTAC_OPT_AUTHEN_CHAP:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_CHAP, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_flag(tt, TTAC_CHAP, invalue));

      case TTAC_OPT_AUTHEN_MSCHAP:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_MSCHAP, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_flag(tt, TTAC_MSCHAP, invalue));

      case TTAC_OPT_AUTHEN_MSCHAPV2:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_MSCHAPV2, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_flag(tt, TTAC_MSCHAPV2, invalue));

      case TTAC_OPT_AUTHEN_PAP:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_AUTHEN_PAP, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_flag(tt, TTAC_PAP, invalue));

      case TTAC_OPT_DEBUG_IDENT:
      TinyTacDebug(  TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_DEBUG_IDENT, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      istr = (((const char *)invalue)) ? ((const char *)invalue) : TTAC_DFLT_DEBUG_IDENT;
      tinytacb_strlcpy(tinytac_debug_ident_buff, istr, sizeof(tinytac_debug_ident_buff));
      tinytac_debug_ident = tinytac_debug_ident_buff;
      return(TTAC_SUCCESS);

      case TTAC_OPT_DEBUG_LEVEL:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_DEBUG_LEVEL, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      ival = (((const int *)invalue)) ? *((const int *)invalue) : TTAC_DFLT_DEBUG_LEVEL;
      tinytac_debug_level = ival;
      return(TTAC_SUCCESS);

      case TTAC_OPT_DEBUG_SYSLOG:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_DEBUG_SYSLOG, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      ival = (((const int *)invalue)) ? *((const int *)invalue) : TTAC_DFLT_DEBUG_SYSLOG;
      tinytac_debug_syslog = ((ival)) ? TTAC_YES : TTAC_NO;
      return(TTAC_SUCCESS);

      case TTAC_OPT_HOSTS:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_HOSTS, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_host(tt, invalue));

      case TTAC_OPT_KEY:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_KEY, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_keys(tt, invalue, NULL));

      case TTAC_OPT_KEYS:
      TinyTacDebug(TTAC_DEBUG_ARGS, "   == %s( %s, TTAC_OPT_KEYS, invalue )", __func__, (((tt)) ? "tt" : "NULL") );
      return(tinytac_set_option_keys(tt, NULL, invalue));

      default:
      break;
   };

   return(TTAC_EOPTION);
}


int
tinytac_set_option_flag(
         TinyTac *                     tt,
         unsigned                      flag,
         const int *                   invalue )
{
   int            ival;
   int            dflt;
   unsigned *     optsp;
   unsigned *     opts_negp;

   TinyTacDebugTrace();

   if (!(flag))
      return(TTAC_SUCCESS);

   dflt        = ((tt))       ? (tinytac_dflt_opts & flag)  : (flag & TTAC_DFLT_OPTS);
   ival        = ((invalue))  ? *invalue                    : dflt;
   optsp       = ((tt))       ? &tt->opts                   : &tinytac_dflt_opts;
   opts_negp   = ((tt))       ? &tt->opts_neg               : &tinytac_dflt_opts_neg;

   if ((ival))
   {
      *optsp      |= flag;
      *opts_negp  ^= flag;
   } else {
      *optsp      ^= flag;
      *opts_negp  |= flag;
   };

   return(TTAC_SUCCESS);
}


int
tinytac_set_option_host(
         TinyTac *                     tt,
         const char *                  invalue )
{
   int                     rc;
   char *                  buff;
   char *                  ostr;
   const char *            dflt;
   size_t                  size;
   char *                  eol;
   char *                  str;
   void *                  ptr;
   size_t                  budps_len;
   BindleURLDesc **        budps;

   TinyTacDebugTrace();

   dflt      = ((tt))      ? tinytac_dflt_hosts : TTAC_DFLT_HOSTS;
   invalue   = ((invalue)) ? invalue            : dflt;
   size      = 0;
   budps     = NULL;
   budps_len = 0;

   if ((buff = tinytacb_strdup(invalue)) == NULL)
      return(TTAC_ENOMEM);

   str = buff;
   while( ((str)) && ((str[0])) )
   {
      // find next whitespace
      eol = strchr(str, ' ');
      eol = ((eol)) ? eol : strchr(str, '\t');
      if ((eol))
         eol[0] = '\0';

      // skip empty host
      if (str[0] == '\0')
      {
         str = ((eol)) ? &eol[1] : NULL;
         continue;
      };

      // increase size of URL list
      if ((ptr = realloc(budps, sizeof(BindleURLDesc *)*(budps_len+2))) == NULL)
      {
         free(buff);
         tinytac_tinytac_free_budps(budps);
         return(TTAC_ENOMEM);
      };
      budps[budps_len+0] = NULL;
      budps[budps_len+1] = NULL;

      // parse URL
      if ((rc = tinytacb_urldesc_parse(str, &budps[budps_len])) != 0)
      {
         free(buff);
         tinytac_tinytac_free_budps(budps);
         return((rc = ENOMEM) ? TTAC_ENOMEM : TTAC_EINVAL);
      };

      // check URL result
      if ( ((budps[budps_len]->bud_scheme)) && (!(strcasecmp("tacacs+", budps[budps_len]->bud_scheme))) )
      {
         free(buff);
         tinytac_tinytac_free_budps(budps);
         return(TTAC_EINVAL);
      };
      if ( ((budps[budps_len]->bud_userinfo)) || ((budps[budps_len]->bud_path)) ||
           ((budps[budps_len]->bud_query)) || ((budps[budps_len]->bud_fragment)) )
      {
         free(buff);
         tinytac_tinytac_free_budps(budps);
         return(TTAC_EINVAL);
      };

      // resolve URL host
      if ((rc = tinytacb_urldesc_resolve(budps[budps_len], AF_UNSPEC, TTAC_DFLT_PORT)) != 0)
      {
         free(buff);
         tinytac_tinytac_free_budps(budps);
         return((rc = ENOMEM) ? TTAC_ENOMEM : TTAC_EINVAL);
      };

      // shift string
      str = ((eol)) ? &eol[1] : NULL;
   };

   free(buff);

   // saves host string
   if ((ostr = tinytacb_strdup(invalue)) == NULL)
   {
      tinytac_tinytac_free_budps(budps);
      return(TTAC_ENOMEM);
   };
   if (!(tt))
   {
      tinytac_tinytac_free_budps(budps);
      if ((tinytac_dflt_hosts_buff))
         free(tinytac_dflt_hosts_buff);
      tinytac_dflt_hosts_buff = ostr;
      tinytac_dflt_hosts      = tinytac_dflt_hosts_buff;
   } else
   {
      tinytac_tinytac_free_budps(tt->budps);
      tt->budps = budps;
      if ((tt->hosts))
         free(tt->hosts);
      tt->hosts = ostr;
   };

   return(TTAC_SUCCESS);
}


int
tinytac_set_option_keys(
         TinyTac *                     tt,
         const char *                  invalue,
         char * const *                invalues )
{
   char ***       strsp;
   char **        strs;

   TinyTacDebugTrace();

   strs     = NULL;
   strsp    = ((tt)) ? &tt->keys : &tinytac_dflt_keys;

   if ((invalue))
   {
      if (tinytacb_strsadd(&strs, invalue) != 0)
         return(TTAC_ENOMEM);
   }
   else if ((invalues))
   {
      if (tinytacb_strsdup(&strs, invalues) != 0)
         return(TTAC_ENOMEM);
   }
   else if ((tt))
   {
      if ((tinytac_dflt_keys))
         if (tinytacb_strsdup(&strs, tinytac_dflt_keys) != 0)
            return(TTAC_ENOMEM);
   };

   tinytacb_strsfree(*strsp);
   *strsp = strs;

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
