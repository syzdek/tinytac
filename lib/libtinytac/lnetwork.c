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
#define _LIB_LIBTINYTAC_LNETWORK_C 1
#include "lnetwork.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

char *
tinytac_ntop(
         int                           s,
         unsigned                      peer )
{
   struct sockaddr_storage    sa;
   socklen_t                  sa_len;
   char                       addrstr[INET6_ADDRSTRLEN];
   static char                buff[INET6_ADDRSTRLEN+16];
   int                        port;

   sa_len = sizeof(sa);
   if ((peer))
   {
      if (getpeername(s, (struct sockaddr *)&sa, &sa_len) == -1)
         return(NULL);
   } else {
      if (getsockname(s, (struct sockaddr *)&sa, &sa_len) == -1)
         return(NULL);
   };

   switch(sa.ss_family)
   {
      case AF_INET:
      inet_ntop(AF_INET, &((const struct sockaddr_in *)&sa)->sin_addr, addrstr, sizeof(addrstr));
      port = ntohs(((const struct sockaddr_in *)&sa)->sin_port);
      snprintf(buff, (sizeof(buff)-1), "%s:%i", addrstr, port);
      break;

      case AF_INET6:
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)&sa)->sin6_addr, addrstr, sizeof(addrstr));
      port = ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port);
      snprintf(buff, (sizeof(buff)-1), "[%s]:%i", addrstr, port);
      break;

      default:
      return(NULL);
   };
   buff[sizeof(buff)-1] = '\0';

   return(buff);
}


int
tinytac_recv(
         int                           s,
         char *                        key,
         tinytac_pckt_t **             pcktp )
{
   size_t               pckt_len;
   ssize_t              rc;
   tinytac_pckt_t *     pckt;
   void *               ptr;

   pckt_len = sizeof(tinytac_pckt_t);

   if ((pckt = malloc(pckt_len)) == NULL)
      return(-1);

   if ((rc = recv(s, pckt, pckt_len, 0)) == -1)
   {
      free(pckt);
      return(-1);
   };
   if (((size_t)rc) != pckt_len)
   {
      free(pckt);
      errno = EBADMSG;
      return(-1);
   };

   pckt_len = ntohl(pckt->pckt_length) + sizeof(tinytac_pckt_t);
   if ((ptr = realloc(pckt, pckt_len)) == NULL)
   {
      free(pckt);
      return(-1);
   };
   pckt = ptr;

   if ((rc = recv(s, pckt->pckt_body, ntohl(pckt->pckt_length), 0)) == -1)
   {
      free(pckt);
      return(-1);
   };
   if (((size_t)rc) != ntohl(pckt->pckt_length))
   {
      free(pckt);
      errno = EBADMSG;
      return(-1);
   };

   tinytac_pckt_obfuscate(pckt, key, strlen(key), TTAC_NO);

   *pcktp = pckt;

   return(0);
}


int
tinytac_send(
         int                           s,
         char *                        key,
         tinytac_pckt_t *              pckt )
{
   size_t   pckt_len;
   ssize_t  rc;
   tinytac_pckt_obfuscate(pckt, key, strlen(key), TTAC_YES);
   pckt_len = ntohl(pckt->pckt_length) + sizeof(tinytac_pckt_t);
   if ((rc = send(s, pckt, pckt_len, 0)) == -1)
      return(-1);
   if (((size_t)rc) != pckt_len)
   {
      errno = EBADMSG;
      return(-1);
   };
   return(0);
}


/* end of source */
