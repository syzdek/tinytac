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
#ifndef _LIB_LIBTINYTAC_LPROTO_H
#define _LIB_LIBTINYTAC_LPROTO_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include "libtinytac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define TTAC_MINOR_TO_VERSION( minor, ver ) ((ver & 0xff00) | ((minor & 0x00ff) << 0))
#define TTAC_MAJOR_TO_VERSION( major, ver ) ((ver & 0x00ff) | ((major & 0x00ff) << 4))
#define TTAC_VERSION_TO_MINOR( ver )        ((ver & 0x00ff) >> 0)
#define TTAC_VERSION_TO_MAJOR( ver )        ((ver & 0xff00) >> 4)


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types

// RFC 8907 Section 4.1. The TACACS+ Packet Header
typedef struct tinytac_header
{
   uint8_t              pckt_version;  // 4 bits major and 4 bits minor
   uint8_t              pckt_type;
   uint8_t              pckt_seq_no;
   uint8_t              pckt_flags;
   uint32_t             pckt_session_id;
   uint32_t             pckt_length;
   uint8_t              pckt_body[];
} tinyrad_header_t;


// RFC 8907 Section 5.1. The Authentication START Packet Body
typedef struct tinytac_packet_authen_start
{
   uint8_t              bdy_action;
   uint8_t              bdy_priv_lvl;
   uint8_t              bdy_authen_type;
   uint8_t              bdy_authen_service;
   uint8_t              bdy_user_len;
   uint8_t              bdy_port_len;
   uint8_t              bdy_rem_addr_len;
   uint8_t              bdy_data_len;
   uint8_t              bdy_bytes[];
} tinyrad_authen_start_t;


// RFC 8907 Section 5.2. The Authentication REPLY Packet Body
typedef struct tinytac_packet_authen_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_flags;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
} tinyrad_authen_reply_t;


// RFC 8907 Section 5.3. The Authentication CONTINUE Packet Body
typedef struct tinytac_packet_authen_continue
{
   uint16_t             bdy_user_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_flags;
   uint8_t              bdy_bytes[];
} tinyrad_authen_contiue_t;


// RFC 8907 Section 6.1. The Authorization REQUEST Packet Body
typedef struct tinytac_packet_author_request
{
   uint8_t              bdy_authen_method;
   uint8_t              bdy_priv_lvl;
   uint8_t              bdy_authen_type;
   uint8_t              bdy_authen_service;
   uint8_t              bdy_user_len;
   uint8_t              bdy_port_len;
   uint8_t              bdy_rem_addr_len;
   uint8_t              bdy_arg_cnt;
   uint8_t              bdy_bytes[];
} tinyrad_author_request_t;


// RFC 8907 Section 6.2. The Authorization REPLY Packet Body
typedef struct tinytac_packet_author_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_arg_cnt;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
} tinyrad_author_reply_t;


// RFC 8907 Section 7.1. The Account REQUEST Packet Body
typedef struct tinytac_packet_acct_reqeust
{
   uint8_t              bdy_flags;
   uint8_t              bdy_authen_method;
   uint8_t              bdy_priv_lvl;
   uint8_t              bdy_authen_type;
   uint8_t              bdy_authen_service;
   uint8_t              bdy_user_len;
   uint8_t              bdy_port_len;
   uint8_t              bdy_rem_addr_len;
   uint8_t              bdy_arg_cnt;
   uint8_t              bdy_bytes[];
} tinyrad_acct_request_t;


// RFC 8907 Section 7.2. The Accounting REPLY Packet Body
typedef struct tinytac_packet_acct_reply
{
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_status;
   uint8_t              bdy_bytes[];
} tinyrad_acct_reply_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//-------------------//
// object prototypes //
//-------------------//
#pragma mark object prototypes


#endif /* end of header */
