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
#ifndef __TINYTAC_H
#define __TINYTAC_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include <tinytac_plus.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
#pragma mark - Macros

// Exports function type
#undef TINYTAC_C_DECLS
#undef TINYTAC_BEGIN_C_DECLS
#undef TINYTAC_END_C_DECLS
#undef _TINYTAC_I
#undef _TINYTAC_F
#undef _TINYTAC_V
#if defined(__cplusplus) || defined(c_plusplus)
#   define TINYTAC_C_DECLS        "C"             ///< exports as C functions
#   define TINYTAC_BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#   define TINYTAC_END_C_DECLS    }               ///< exports as C functions
#else
#   define TINYTAC_C_DECLS        /* empty */     ///< exports as C functions
#   define TINYTAC_BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#   define TINYTAC_END_C_DECLS    /* empty */     ///< exports as C functions
#endif
#ifdef WIN32
#   ifdef _LIB_LIBTINYTAC_H
#      define _TINYTAC_I   inline
#      define _TINYTAC_F   extern TINYTAC_C_DECLS __declspec(dllexport)   ///< used for library calls
#      define _TINYTAC_V   extern TINYTAC_C_DECLS __declspec(dllexport)   ///< used for library calls
#   else
#      define _TINYTAC_I   extern TINYTAC_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _TINYTAC_F   extern TINYTAC_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _TINYTAC_V   extern TINYTAC_C_DECLS __declspec(dllimport)   ///< used for library calls
#   endif
#else
#   ifdef _LIB_LIBTINYTAC_H
#      define _TINYTAC_I   inline
#      define _TINYTAC_F   /* empty */                                    ///< used for library calls
#      define _TINYTAC_V   extern TINYTAC_C_DECLS                         ///< used for library calls
#   else
#      define _TINYTAC_I   extern TINYTAC_C_DECLS                         ///< used for library calls
#      define _TINYTAC_F   extern TINYTAC_C_DECLS                         ///< used for library calls
#      define _TINYTAC_V   extern TINYTAC_C_DECLS                         ///< used for library calls
#   endif
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

// library error codes
#define TTAC_SUCCESS                0x0000 ///< success
#define TTAC_EUNKNOWN               0x0001 ///< unknown error
#define TTAC_ENOMEM                 0x0002 ///< out of virtual memory
#define TTAC_EACCES                 0x0003 ///< permission denied
#define TTAC_ENOENT                 0x0004 ///< no such file or directory
#define TTAC_ESYNTAX                0x0005 ///< invalid or unrecognized syntax
#define TTAC_ENOBUFS                0x0006 ///< no buffer space available
#define TTAC_EEXISTS                0x0007 ///< dictionary object exists
#define TTAC_EINVAL                 0x0008 ///< invalid argument
#define TTAC_EOPTION                0x0009 ///< invalid or unknown option
#define TTAC_EOPTVAL                0x000a ///< invalid option value


// library user options
#define TTAC_NOINIT                 0x00000001U
#define TTAC_IPV4                   0x00000002U
#define TTAC_IPV6                   0x00000004U
#define TTAC_IP_UNSPEC              (TTAC_IPV4 | TTAC_IPV6)
#define TTAC_SERVER                 0x00000080U
#define TTAC_ASCII                  0x00000100U ///< allow ASCII authentication
#define TTAC_PAP                    0x00000200U ///< allow PAP authentication
#define TTAC_CHAP                   0x00000400U ///< allow CHAP authentication
#define TTAC_MSCHAP                 0x00000800U ///< allow MSCHAP authentication
#define TTAC_MSCHAPV2               0x00001000U ///< allow MSCHAPv2 authentication
#define TTAC_AUTHEN_TYPES           (TTAC_ASCII | TTAC_PAP | TTAC_CHAP | TTAC_MSCHAP | TTAC_MSCHAPV2 )


#define TTAC_NO                     0
#define TTAC_YES                    1


// library get/set options
#define TTAC_OPT_DEBUG_LEVEL        1
#define TTAC_OPT_DEBUG_IDENT        2
#define TTAC_OPT_DEBUG_SYSLOG       3
#define TTAC_OPT_HOSTS              10
#define TTAC_OPT_SECRETS            11
#define TTAC_OPT_AUTHEN_ASCII       20
#define TTAC_OPT_AUTHEN_PAP         21
#define TTAC_OPT_AUTHEN_CHAP        22
#define TTAC_OPT_AUTHEN_MSCHAP      23
#define TTAC_OPT_AUTHEN_MSCHAPV2    24


// library debug levels
#define TTAC_DEBUG_NONE             0
#define TTAC_DEBUG_TRACE            0x0000001
#define TTAC_DEBUG_ARGS             0x0000002
#define TTAC_DEBUG_CONNS            0x0000004
#define TTAC_DEBUG_PACKETS          0x0000008
#define TTAC_DEBUG_PARSE            0x0000010
#define TTAC_DEBUG_ANY              (~0x00)


// library defaults
#define TTAC_DFLT_DEBUG_IDENT             "libtinytac"
#define TTAC_DFLT_DEBUG_LEVEL             TTAC_DEBUG_NONE
#define TTAC_DFLT_DEBUG_SYSLOG            TTAC_NO
#define TTAC_DFLT_HOSTS                   "localhost"
#define TTAC_DFLT_SECRETS                 NULL
#define TTAC_DFLT_OPTS                    0
#define TTAC_DFLT_OPTS_NEG                0


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types

typedef struct _tinytac                   TinyTac;
typedef struct _tinytac_packet            tinytac_pckt_t;
typedef struct _tinytac_authen_start      tinytac_authen_start_t;
typedef struct _tinytac_authen_reply      tinytac_authen_reply_t;
typedef struct _tinytac_authen_continue   tinytac_authen_cont_t;
typedef struct _tinytac_author_request    tinytac_author_req_t;
typedef struct _tinytac_author_reply      tinytac_author_reply_t;
typedef struct _tinytac_account_request   tinytac_acct_req_t;
typedef struct _tinytac_account_reply     tinytac_acct_reply_t;


struct _tinytac_packet
{
   uint8_t              pckt_version;  // 4 bits major and 4 bits minor
   uint8_t              pckt_type;
   uint8_t              pckt_seq_no;
   uint8_t              pckt_flags;
   uint32_t             pckt_session_id;
   uint32_t             pckt_length;
   uint8_t              pckt_body[];
};


struct _tinytac_authen_start
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
};


struct _tinytac_authen_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_flags;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
};


struct _tinytac_authen_continue
{
   uint16_t             bdy_user_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_flags;
   uint8_t              bdy_bytes[];
};


struct _tinytac_author_request
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
};


struct _tinytac_author_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_arg_cnt;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
};


struct _tinytac_account_request
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
};


struct _tinytac_account_reply
{
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_status;
   uint8_t              bdy_bytes[];
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//------------------//
// error prototypes //
//------------------//
#pragma mark error prototypes

_TINYTAC_F char *
tinytac_strerror(
         int                           errnum );


_TINYTAC_F char *
tinytac_strerror_r(
         int                           errnum,
         char *                        strerrbuf,
         size_t                        buflen );


//-------------------//
// memory prototypes //
//-------------------//
#pragma mark memory prototypes

_TINYTAC_F void
tinytac_free(
         void *                        ptr );


_TINYTAC_F int
tinytac_get_option(
         TinyTac *                     tt,
         int                           option,
         void *                        outvalue );


_TINYTAC_F int
tinytac_initialize(
         TinyTac **                    ttp,
         const char *                  hosts,
         const char *                  key,
         unsigned                      opts );


_TINYTAC_F int
tinytac_set_option(
         TinyTac *                     tt,
         int                           option,
         const void *                  invalue );


//--------------------//
// network prototypes //
//--------------------//
#pragma mark network prototypes

_TINYTAC_F int
tinytac_recv(
         int                           s,
         char *                        key,
         tinytac_pckt_t **             pcktp );


_TINYTAC_F int
tinytac_send(
         int                           s,
         char *                        key,
         tinytac_pckt_t *              pckt );


//---------------------//
// protocol prototypes //
//---------------------//
#pragma mark protocol prototypes

/// prints hexdump of packet to file stream
///
/// @param[in]  fs            write hexdump to file stream 'fs'
/// @param[in]  pckt          packet used to generate psuedo-random pad
/// @param[in]  prefix        string to prepend to each line
void
tinytac_pckt_hexdump(
         FILE *                        fs,
         tinytac_pckt_t *              pckt,
         const char *                  prefix );


/// generates pseudo-random pad used to obfuscate the packet body
///
/// @param[in]  pckt          packet used to generate psuedo-random pad
/// @param[in]  key           shared secret key used to protect the communication
/// @param[in]  key_len       length of shared secret key
/// @param[in]  md5pad_prev   previously generated psuedo-random pad (must be 16 bytes)
/// @param[out] md5pad        buffer to store generated
///
/// @return    Returns 0 on success or -1 on error.
_TINYTAC_F int
tinytac_pckt_md5pad(
         tinytac_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         uint8_t *                     md5pad_prev,
         uint8_t *                     md5pad );


/// obfuscate or unobfuscate packet using shared secret key
///
/// @param[in]  pckt          packet used to generate psuedo-random pad
/// @param[in]  key           shared secret key used to protect the communication
/// @param[in]  key_len       length of shared secret key
/// @param[in]  unencrypted   packet should not be obfuscated (TTAC_YES or TTAC_NO)
///
/// @return    Returns 0 on success or -1 on error.
_TINYTAC_F int
tinytac_pckt_obfuscate(
         tinytac_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         unsigned                      unencrypted );

#endif /* end of header */
