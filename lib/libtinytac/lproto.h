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

#define TTAC_VERSION( major, minor )         (((major & 0x0f) << 4) | (minor & 0x0f))
#define TTAC_VERSION_MINOR( version, minor ) ((version & 0xf0) | (minor & 0x0f))
#define TTAC_VERSION_MAJOR( version, major ) ((version & 0x0f) | ((major & 0x0f) << 4))
#define TTAC_VERSION_TO_MINOR( version )     ((version & 0x0f) >> 0)
#define TTAC_VERSION_TO_MAJOR( version )     ((version & 0xf0) >> 4)


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
#pragma mark - Data Types


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


#endif /* end of header */
