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
#define _LIB_LIBTINYTAC_LPROTO_C 1
#include "lproto.h"


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
#include <openssl/evp.h>


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

//------------------//
// packet functions //
//------------------//
#pragma mark packet functions

void
tinytac_pckt_hexdump(
         FILE *                        fs,
         tinytac_pckt_t *              pckt,
         const char *                  prefix )
{
   uint8_t *         bytes;
   unsigned          line;
   unsigned          pos;
   unsigned          pckt_len;
   const char *      str;

   bytes    = (void *)pckt;
   pckt_len = ntohl(pckt->pckt_length) + sizeof(tinytac_pckt_t);
   prefix   = ((prefix)) ? prefix : "";

   fprintf(fs, "%spacket: version: %u.%u;", prefix, (pckt->pckt_version >> 4), (pckt->pckt_version & 0x0f));
   switch(pckt->pckt_type)
   {
      case TAC_PLUS_TYPE_AUTHEN: str = "authen";  break;
      case TAC_PLUS_TYPE_AUTHOR: str = "author";  break;
      case TAC_PLUS_TYPE_ACCT:   str = "acct";    break;
      default:                   str = "unknown"; break;
   };
   fprintf(fs, " type: %s;", str);
   fprintf(fs, " seq_no: %u;", pckt->pckt_seq_no);
   fprintf(fs, " session_id: %08x;", ntohl(pckt->pckt_session_id));
   fprintf(fs, "\n%spacket: length: %u (0x%x);", prefix, pckt_len, pckt_len);
   fprintf(fs, " flags:");
   if (!(pckt->pckt_flags))
      fprintf(fs, " NONE");
   if ((pckt->pckt_flags & TAC_PLUS_FLAG_SINGLE_CONNECT))
      fprintf(fs, " SINGLE-CONNECT");
   if ((pckt->pckt_flags & TAC_PLUS_FLAG_UNENCRYPTED))
      fprintf(fs, " UNENCRYPTED");
   fprintf(fs, ";");
   fprintf(fs, "\n");


   fprintf(fs, "%s offset    0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f  0123456789abcdef\n", prefix);
   for(line = 0; (line < pckt_len); line += 0x10)
   {
      fprintf(fs, "%s%08x", prefix, line);
      for(pos = line; (pos < (line+0x10)); pos++)
      {
         if ((pos & 0x03) == 0)
            fprintf(fs, " ");
         if (pos < pckt_len)
            fprintf(fs, " %02x", bytes[pos]);
         else
            fprintf(fs, "   ");
      };
      fprintf(fs, "  ");
      for(pos = line; ((pos < (line+0x10)) && (pos < pckt_len)); pos++)
         fprintf(fs, "%c", ((bytes[pos] < 0x20) || (bytes[pos] > 0x7e)) ? '.' : bytes[pos]);
      fprintf(fs, "\n");
      if ((line & 0xf0) == 0xf0)
         fprintf(fs, "\n");
   };

   return;
}


int
tinytac_pckt_md5pad(
         tinytac_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         uint8_t *                     md5pad_prev,
         uint8_t *                     md5pad )
{
   unsigned             md_len;
   EVP_MD_CTX *         mdctx;

   assert(pckt    != NULL);
   assert(key     != NULL);
   assert(md5pad  != NULL);

   key_len = ((key)) ? key_len : 0;

   mdctx = EVP_MD_CTX_new();
   EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
   EVP_DigestUpdate(mdctx, &pckt->pckt_session_id, 4);
   EVP_DigestUpdate(mdctx, key, key_len);
   EVP_DigestUpdate(mdctx, &pckt->pckt_version, 1);
   EVP_DigestUpdate(mdctx, &pckt->pckt_seq_no, 1);
   if ((md5pad_prev))
      EVP_DigestUpdate(mdctx, md5pad_prev, 16);
   EVP_DigestFinal_ex(mdctx, md5pad, &md_len);
   EVP_MD_CTX_free(mdctx);

   return(0);
}


int
tinytac_pckt_obfuscate(
         tinytac_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         unsigned                      unencrypted )
{
   uint8_t        md_value[EVP_MAX_MD_SIZE];
   size_t         pckt_len;
   size_t         off;
   size_t         pos;

   assert(pckt != NULL);
   assert(key  != NULL);

   // check for existing obfuscation and flip flag
   unencrypted = (unencrypted == TTAC_NO) ? 0 : TAC_PLUS_FLAG_UNENCRYPTED;
   if ((pckt->pckt_flags & TAC_PLUS_FLAG_UNENCRYPTED) == unencrypted)
      return(0);
   pckt->pckt_flags ^= TAC_PLUS_FLAG_UNENCRYPTED;

   // create initial pad
   tinytac_pckt_md5pad(pckt, key, key_len, NULL, md_value);
   pckt_len = ntohl(pckt->pckt_length);

   // apply pads to packet body
   for(off = 0; ((pckt_len - off) > 15); off += 16)
   {
      for(pos = 0; (pos < 16); pos++)
         pckt->pckt_body[off+pos] ^= md_value[pos];
      tinytac_pckt_md5pad(pckt, key, key_len, md_value, md_value);
   };
   for(pos = 0; ((pos+off) < pckt_len); pos++)
      pckt->pckt_body[off+pos] ^= md_value[pos];

   return(0);
}


/* end of source */
