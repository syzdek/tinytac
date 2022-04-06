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
