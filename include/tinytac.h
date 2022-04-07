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


// library user options
#define TTAC_NOINIT                 0x00000001U
#define TTAC_IPV4                   0x00000002U
#define TTAC_IPV6                   0x00000004U
#define TTAC_IP_UNSPEC              (TRAD_IPV4 | TRAD_IPV6)
#define TTAC_SERVER                 0x00000080U


#define TTAC_NO                     0
#define TTAC_YES                    1


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


// RFC8907 Section 4.1 The TACACS+ Packet Header
#define TTAC_MAJOR_VER              0x0c  // RFC name: TTAC_PLUS_MAJOR_VER
#define TTAC_MINOR_VER_DEFAULT      0x00  // RFC name: TTAC_PLUS_MINOR_VER_DEFAULT
#define TTAC_MINOR_VER_ONE          0x01  // RFC name: TTAC_PLUS_MINOR_VER_ONE
#define TTAC_TYPE_AUTHEN            0x01  // RFC name: TTAC_PLUS_AUTHEN
#define TTAC_TYPE_AUTHOR            0x02  // RFC name: TTAC_PLUS_AUTHOR
#define TTAC_TYPE_ACCT              0x03  // RFC name: TTAC_PLUS_ACCT
#define TTAC_FLAG_UNENCRYPTED       0x01  // RFC name: TAC_PLUS_UNENCRYPTED_FLAG
#define TTAC_FLAG_SINGLE_CONNECT    0x04  // RFC name: TAC_PLUS_SINGLE_CONNECT_FLAG


// RFC8907 Section 5.1 The Authentication START Packet Body
#define TTAC_AUTHEN_LOGIN           0x01  // RFC name: TAC_PLUS_AUTHEN_LOGIN
#define TTAC_AUTHEN_CHPASS          0x02  // RFC name: TAC_PLUS_AUTHEN_CHPASS
#define TTAC_AUTHEN_SENDAUTH        0x04  // RFC name: TAC_PLUS_AUTHEN_SENDAUTH
#define TTAC_AUTHEN_TYPE_ASCII      0x01  // RFC name: TAC_PLUS_AUTHEN_TYPE_ASCII
#define TTAC_AUTHEN_TYPE_PAP        0x02  // RFC name: TAC_PLUS_AUTHEN_TYPE_PAP
#define TTAC_AUTHEN_TYPE_CHAP       0x03  // RFC name: TAC_PLUS_AUTHEN_TYPE_CHAP
#define TTAC_AUTHEN_TYPE_MSCHAP     0x05  // RFC name: TAC_PLUS_AUTHEN_TYPE_MSCHAP
#define TTAC_AUTHEN_TYPE_MSCHAPV2   0x06  // RFC name: TAC_PLUS_AUTHEN_TYPE_MSCHAPV2
#define TTAC_AUTHEN_SVC_NONE        0x00  // RFC name: TAC_PLUS_AUTHEN_SVC_NONE
#define TTAC_AUTHEN_SVC_LOGIN       0x01  // RFC name: TAC_PLUS_AUTHEN_SVC_LOGIN
#define TTAC_AUTHEN_SVC_ENABLE      0x02  // RFC name: TAC_PLUS_AUTHEN_SVC_ENABLE
#define TTAC_AUTHEN_SVC_PPP         0x03  // RFC name: TAC_PLUS_AUTHEN_SVC_PPP
#define TTAC_AUTHEN_SVC_PT          0x05  // RFC name: TAC_PLUS_AUTHEN_SVC_PT
#define TTAC_AUTHEN_SVC_RCMD        0x06  // RFC name: TAC_PLUS_AUTHEN_SVC_RCMD
#define TTAC_AUTHEN_SVC_X25         0x07  // RFC name: TAC_PLUS_AUTHEN_SVC_X25
#define TTAC_AUTHEN_SVC_NASI        0x08  // RFC name: TAC_PLUS_AUTHEN_SVC_NASI
#define TTAC_AUTHEN_SVC_FWPROXY     0x09  // RFC name: TAC_PLUS_AUTHEN_SVC_FWPROXY


// RFC8907 Section 5.2 The Authentication REPLY Packet Body
#define TTAC_AUTHEN_STATUS_PASS     0x01  // RFC name: TAC_PLUS_AUTHEN_STATUS_PASS
#define TTAC_AUTHEN_STATUS_FAIL     0x02  // RFC name: TAC_PLUS_AUTHEN_STATUS_FAIL
#define TTAC_AUTHEN_STATUS_GETDATA  0x03  // RFC name: TAC_PLUS_AUTHEN_STATUS_GETDATA
#define TTAC_AUTHEN_STATUS_GETUSER  0x04  // RFC name: TAC_PLUS_AUTHEN_STATUS_GETUSER
#define TTAC_AUTHEN_STATUS_GETPASS  0x05  // RFC name: TAC_PLUS_AUTHEN_STATUS_GETPASS
#define TTAC_AUTHEN_STATUS_RESTART  0x06  // RFC name: TAC_PLUS_AUTHEN_STATUS_RESTART
#define TTAC_AUTHEN_STATUS_ERROR    0x07  // RFC name: TAC_PLUS_AUTHEN_STATUS_ERROR
#define TTAC_AUTHEN_STATUS_FOLLOW   0x21  // RFC name: TAC_PLUS_AUTHEN_STATUS_FOLLOW
#define TTAC_REPLY_FLAG_NOECHO      0x01  // RFC name: TAC_PLUS_REPLY_FLAG_NOECHO


// RFC8907 Section 5.3 The Authentication CONTINUE Packet Body
#define TTAC_CONTINUE_FLAG_ABORT    0x01  // RFC name: TAC_PLUS_CONTINUE_FLAG_ABORT


// RFC8907 Section 6.1 The Authorization REQUEST Packet Body
#define TTAC_AUTHEN_METH_NOT_SET    0x00  // RFC name: TAC_PLUS_AUTHEN_METH_NOT_SET
#define TTAC_AUTHEN_METH_NONE       0x01  // RFC name: TAC_PLUS_AUTHEN_METH_NONE
#define TTAC_AUTHEN_METH_KRB5       0x02  // RFC name: TAC_PLUS_AUTHEN_METH_KRB5
#define TTAC_AUTHEN_METH_LINE       0x03  // RFC name: TAC_PLUS_AUTHEN_METH_LINE
#define TTAC_AUTHEN_METH_ENABLE     0x04  // RFC name: TAC_PLUS_AUTHEN_METH_ENABLE
#define TTAC_AUTHEN_METH_LOCAL      0x05  // RFC name: TAC_PLUS_AUTHEN_METH_LOCAL
#define TTAC_AUTHEN_METH_TACACSPLUS 0x06  // RFC name: TAC_PLUS_AUTHEN_METH_TACACSPLUS
#define TTAC_AUTHEN_METH_GUEST      0x08  // RFC name: TAC_PLUS_AUTHEN_METH_GUEST
#define TTAC_AUTHEN_METH_RADIUS     0x10  // RFC name: TAC_PLUS_AUTHEN_METH_RADIUS
#define TTAC_AUTHEN_METH_KRB4       0x11  // RFC name: TAC_PLUS_AUTHEN_METH_KRB4
#define TTAC_AUTHEN_METH_RCMD       0x20  // RFC name: TAC_PLUS_AUTHEN_METH_RCMD


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types

typedef struct _tinytac                   TinyTac;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

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
         const char *                  url,
         unsigned                      opts );


_TINYTAC_F int
tinytac_set_option(
         TinyTac *                     tt,
         int                           option,
         const void *                  invalue );


#endif /* end of header */
