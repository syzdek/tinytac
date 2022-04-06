#
#   Tiny TACACS+ Client Library
#   Copyright (C) 2022 David M. Syzdek <david@syzdek.net>.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   acinclude.m4 - custom m4 macros used by configure.ac
#

# AC_TINYTAC_DOCUMENTATION()
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_DOCUMENTATION],[dnl
   enableval=""
   AC_ARG_ENABLE(
      documentation,
      [AS_HELP_STRING([--enable-documentation], [install extra documentation])],
      [ EDOCUMENATION=$enableval ],
      [ EDOCUMENATION=$enableval ]
   )

   if test "x${EDOCUMENATION}" == "xyes";then
      ENABLE_DOCUMENATION="yes"
   else
      ENABLE_DOCUMENATION="no"
   fi

   AM_CONDITIONAL([ENABLE_DOCUMENATION],  [test "$ENABLE_DOCUMENATION" = "yes"])
   AM_CONDITIONAL([DISABLE_DOCUMENATION], [test "$ENABLE_DOCUMENATION" = "no"])
])dnl


# AC_TINYTAC_EXAMPLES()
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_EXAMPLES],[dnl
   enableval=""
   AC_ARG_ENABLE(
      examples,
      [AS_HELP_STRING([--enable-examples], [build TinyTac examples])],
      [ EEXAMPLES=$enableval ],
      [ EEXAMPLES=$enableval ]
   )

   if test "x${EEXAMPLES}" == "xyes";then
      ENABLE_EXAMPLES="yes"
   else
      ENABLE_EXAMPLES="no"
   fi

   AM_CONDITIONAL([ENABLE_EXAMPLES],  [test "$ENABLE_EXAMPLES" = "yes"])
   AM_CONDITIONAL([DISABLE_EXAMPLES], [test "$ENABLE_EXAMPLES" = "no"])
])dnl


# AC_TINYTAC_IPV4
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_IPV4],[dnl
   WITH_IPV4=yes
   AM_CONDITIONAL([WITH_IPV4],    [test "${WITH_IPV4}" == "yes"])
   AM_CONDITIONAL([WITHOUT_IPV4], [test "${WITH_IPV4}" != "yes"])
])dnl


# AC_TINYTAC_IPV6
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_IPV6],[dnl

   # prerequists
   AC_REQUIRE([AC_PROG_CC])

   enableval=""
   AC_ARG_WITH(
      ipv6,
      [AS_HELP_STRING([--without-ipv6], [disable IPv6 support])],
      [ WIPV6=$enableval ],
      [ WIPV6=$enableval ]
   )

   HAVE_IPV6=yes
   AC_MSG_CHECKING(for working IPv6 support)
   AC_COMPILE_IFELSE(
      [
         AC_LANG_PROGRAM(
            [[ #include <sys/types.h>
               #include <netinet/in.h>
               #include <sys/socket.h>
               #include <netdb.h>
            ]],
            [[ struct sockaddr_in6  a;
               struct addrinfo      hints;
               a.sin6_family  = AF_INET6;
               a.sin6_family  = PF_INET6;
               hints.ai_flags = AI_V4MAPPED|AI_ALL;
            ]]
         )
      ],
      [],
      [HAVE_IPV6="no"]
   )
   AC_MSG_RESULT($HAVE_IPV6)

   WITH_IPV6=yes
   if test "x${WIPV6}" = "xno";then
      WITH_IPV6=no
   elif test "x${WIPV6}" = "x";then
      WITH_IPV6=${HAVE_IPV6}
   else
      if test "x${HAVE_IPV6}" = "xno";then
         AC_MSG_ERROR([unable to determine IPv6 support])
      fi
   fi

   if test "x${WITH_IPV6}" == "xno";then
      AC_DEFINE_UNQUOTED(WITHOUT_IPV6, 1, [Disable IPv6])
   fi
   AM_CONDITIONAL([WITH_IPV6],    [test "${WITH_IPV6}" == "yes"])
   AM_CONDITIONAL([WITHOUT_IPV6], [test "${WITH_IPV6}" != "yes"])
])dnl


# AC_TINYTAC_LIBTINYTAC()
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_LIBTINYTAC],[dnl
   enableval=""
   AC_ARG_ENABLE(
      libtinytac,
      [AS_HELP_STRING([--disable-libtinytac], [disable TinyTac library])],
      [ ELIBTINYTAC=$enableval ],
      [ ELIBTINYTAC=$enableval ]
   )
   if test "x${ELIBTINYTAC}" != "xno";then
      ENABLE_LIBTINYTAC="yes"
   else
      ENABLE_LIBTINYTAC="no"
   fi
   AM_CONDITIONAL([ENABLE_LIBTINYTAC],  [test "$ENABLE_LIBTINYTAC" = "yes"])
   AM_CONDITIONAL([DISABLE_LIBTINYTAC], [test "$ENABLE_LIBTINYTAC" = "no"])
])dnl


# AC_TINYTAC_TINYTAC()
# ______________________________________________________________________________
AC_DEFUN([AC_TINYTAC_TINYTAC],[dnl

   enableval=""
   AC_ARG_ENABLE(
      tinytac,
      [AS_HELP_STRING([--disable-tinytac], [disable TinyTac client])],
      [ ETINYTAC=$enableval ],
      [ ETINYTAC=$enableval ]
   )

   if test "x${ETINYTAC}" == "xyes";then
      ENABLE_TINYTAC="yes"
   elif test "x${ETINYTAC}" == "xno";then
      ENABLE_TINYTAC="no"
   else
      ENABLE_TINYTAC="yes"
   fi

   AM_CONDITIONAL([ENABLE_TINYTAC],  [test "$ENABLE_TINYTAC" = "yes"])
   AM_CONDITIONAL([DISABLE_TINYTAC], [test "$ENABLE_TINYTAC" = "no"])
])dnl

# end of m4 file
