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
#ifndef _SRC_TTU_TINYTACUTIL_H
#define _SRC_TTU_TINYTACUTIL_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <tinytac_compat.h>

#include <stdlib.h>
#include <tinytac.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "tinytac"

#define TTUTILS_OPT_QUIET           0x00000001U
#define TTUTILS_OPT_VERBOSE         0x00000002U
#define TTUTILS_OPT_PASSPROMPT      0x00000004U


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types

typedef struct _tinytac_util_widget     ttu_widget_t;
typedef struct _tinytac_util_config     ttu_config_t;

struct _tinytac_util_config
{
   unsigned                   opts;
   int                        argc;
   char **                    argv;
   const char *               pass;
   const char *               pass_file;
   char *                     pass_buff;
   const char *               prog_name;
   const ttu_widget_t *       widget;
   TinyTac *                  tt;
};


struct _tinytac_util_widget
{
   const char *               name;
   const char *               desc;
   const char *               usage;
   const char * const *       aliases;
   int  (*func_exec)(ttu_config_t * cnf);
   int  (*func_usage)(ttu_config_t * cnf);
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern ttu_widget_t ttu_widget_map[];


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//--------------------//
// logging prototypes //
//--------------------//
#pragma mark logging prototypes

extern int
ttu_error(
         ttu_config_t *                cnf,
         int                           rc,
         const char *                  fmt,
         ... );


extern int
ttu_printf(
         ttu_config_t *                cnf,
         const char *                  fmt,
         ... );


extern int
tru_verbose(
         ttu_config_t *                cnf,
         const char *                  fmt,
         ... );


//--------------------------//
// miscellaneous prototypes //
//--------------------------//
#pragma mark miscellaneous prototypes

extern char *
ttu_file2str(
         const char *                  path );


extern int
ttu_password(
         ttu_config_t *                cnf );


//------------------//
// usage prototypes //
//------------------//
#pragma mark usage prototypes

extern int
ttu_cli_arguments(
         ttu_config_t *                cnf,
         int                           argc,
         char * const *                argv );


extern int
ttu_usage(
         ttu_config_t *                cnf );


extern int
tru_verbose(
         ttu_config_t *                cnf,
         const char *                  fmt,
         ... );


//-------------------//
// widget prototypes //
//-------------------//
#pragma mark widget prototypes

extern int
ttu_widget_acct(
         ttu_config_t *                cnf );


extern int
ttu_widget_authen(
         ttu_config_t *                cnf );


extern int
ttu_widget_author(
         ttu_config_t *                cnf );


extern int
ttu_widget_config(
         ttu_config_t *                cnf );


#endif /* end of header */
