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
#define _EXAMPLES_TACACS_EXAMPLE_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <assert.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <pwd.h>
#include <unistd.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "tacacs-example"
#ifndef PACKAGE_BUGREPORT
#   define PACKAGE_BUGREPORT "unknown"
#endif
#ifndef PACKAGE_COPYRIGHT
#   define PACKAGE_COPYRIGHT "unknown"
#endif
#ifndef PACKAGE_NAME
#   define PACKAGE_NAME "Tiny TACACS+ Client Library"
#endif
#ifndef PACKAGE_VERSION
#   define PACKAGE_VERSION "unknown"
#endif


#define MY_VERBOSE      0x0001U
#define MY_QUIET        0x0002U
#define MY_DEBUG        0x0004U
#define MY_DEBUGMORE    0x0008U


#ifndef SO_NOSIGPIPE
#   define SO_NOSIGPIPE SO_REUSEADDR
#endif
#ifndef SO_REUSEPORT
#   define SO_REUSEPORT SO_REUSEADDR
#endif


#define TAC_PLUS_VER                      0xc1
#define TAC_PLUS_AUTHEN                   0x01
#define TAC_PLUS_AUTHOR                   0x02
#define TAC_PLUS_ACCT                     0x03
#define TAC_PLUS_UNENCRYPTED_FLAG         0x01
#define TAC_PLUS_SINGLE_CONNECT_FLAG      0x04

#define TAC_PLUS_AUTHEN_LOGIN             0x01
#define TAC_PLUS_AUTHEN_CHPASS            0x02
#define TAC_PLUS_AUTHEN_SENDAUTH          0x03

#define TAC_PLUS_AUTHEN_METH_NOT_SET      0x00
#define TAC_PLUS_AUTHEN_METH_NONE         0x01
#define TAC_PLUS_AUTHEN_METH_KRB5         0x02
#define TAC_PLUS_AUTHEN_METH_LINE         0x03
#define TAC_PLUS_AUTHEN_METH_ENABLE       0x04
#define TAC_PLUS_AUTHEN_METH_LOCAL        0x05
#define TAC_PLUS_AUTHEN_METH_TACACSPLUS   0x06
#define TAC_PLUS_AUTHEN_METH_GUEST        0x08
#define TAC_PLUS_AUTHEN_METH_RADIUS       0x10
#define TAC_PLUS_AUTHEN_METH_KRB4         0x11
#define TAC_PLUS_AUTHEN_METH_RCMD         0x20

#define TAC_PLUS_AUTHEN_TYPE_ASCII        0x01
#define TAC_PLUS_AUTHEN_TYPE_PAP          0x02
#define TAC_PLUS_AUTHEN_TYPE_CHAP         0x03
#define TAC_PLUS_AUTHEN_TYPE_MSCHAP       0x05
#define TAC_PLUS_AUTHEN_TYPE_MSCHAPV2     0x06

#define TAC_PLUS_AUTHEN_SVC_NONE          0x00
#define TAC_PLUS_AUTHEN_SVC_LOGIN         0x01
#define TAC_PLUS_AUTHEN_SVC_ENABLE        0x02
#define TAC_PLUS_AUTHEN_SVC_PPP           0x03
#define TAC_PLUS_AUTHEN_SVC_PT            0x05
#define TAC_PLUS_AUTHEN_SVC_RCMD          0x06
#define TAC_PLUS_AUTHEN_SVC_X25           0x07
#define TAC_PLUS_AUTHEN_SVC_NASI          0x08
#define TAC_PLUS_AUTHEN_SVC_FWPROXY       0x09

#define TAC_PLUS_AUTHEN_STATUS_PASS       0x01
#define TAC_PLUS_AUTHEN_STATUS_FAIL       0x02
#define TAC_PLUS_AUTHEN_STATUS_GETDATA    0x03
#define TAC_PLUS_AUTHEN_STATUS_GETUSER    0x04
#define TAC_PLUS_AUTHEN_STATUS_GETPASS    0x05
#define TAC_PLUS_AUTHEN_STATUS_RESTART    0x06
#define TAC_PLUS_AUTHEN_STATUS_ERROR      0x07
#define TAC_PLUS_AUTHEN_STATUS_FOLLOW     0x21

#define TAC_PLUS_REPLY_FLAG_NOECHO        0x01

#define TAC_PLUS_AUTHOR_STATUS_PASS_ADD   0x01
#define TAC_PLUS_AUTHOR_STATUS_PASS_REPL  0x02
#define TAC_PLUS_AUTHOR_STATUS_FAIL       0x10
#define TAC_PLUS_AUTHOR_STATUS_ERROR      0x11
#define TAC_PLUS_AUTHOR_STATUS_FOLLOW     0x21

#define PPP_PAP_CODE_REQUEST              1
#define PPP_PAP_CODE_ACK                  2
#define PPP_PAP_CODE_NAK                  3


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct tac_plus_packet
{
   uint8_t              pckt_version;  // 4 bits major and 4 bits minor
   uint8_t              pckt_type;
   uint8_t              pckt_seq_no;
   uint8_t              pckt_flags;
   uint32_t             pckt_session_id;
   uint32_t             pckt_length;
   uint8_t              pckt_body[];
} tacplus_pckt_t;


typedef struct tac_plus_authen_start
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
} authen_start_t;


typedef struct tac_plus_authen_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_flags;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
} authen_reply_t;


typedef struct tac_plus_author_request
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
} author_request_t;


typedef struct tac_plus_author_reply
{
   uint8_t              bdy_status;
   uint8_t              bdy_arg_cnt;
   uint16_t             bdy_server_msg_len;
   uint16_t             bdy_data_len;
   uint8_t              bdy_bytes[];
} author_reply_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
main(
         int                           argc,
         char *                        argv[] );


int
my_cmd_authen(
         unsigned                      opts,
         int                           s,
         uint8_t                       seq_no,
         char *                        key,
         char *                        user );


int
my_cmd_author(
         unsigned                      opts,
         int                           s,
         uint8_t                       seq_no,
         char *                        key,
         char *                        user,
         int                           argc,
         char **                       argv );


int
my_connect(
         unsigned                      opts,
         const char *                  hostport );


int
my_error(
         const char *                  fmt,
         ... );


char *
my_ntop(
         struct sockaddr_storage *     sa,
         char *                        buff,
         size_t                        len );


tacplus_pckt_t *
my_pckt_alloc(
         uint8_t                       pckt_type,
         uint8_t                       seq_no,
         size_t                        nbytes );


tacplus_pckt_t *
my_pckt_allocmore(
         tacplus_pckt_t *              pckt,
         size_t                        nbytes );


int
my_pckt_copy_bytes(
         void *                        buff,
         size_t                        buff_len,
         size_t *                      offp,
         const void *                  bytes,
         size_t                        nbytes );


void
my_pckt_hexdump(
         unsigned                      opts,
         tacplus_pckt_t *              pckt );


int
my_pckt_md5pad(
         tacplus_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         uint8_t *                     md5pad,
         uint8_t *                     md_value );


int
my_pckt_obfuscate(
         unsigned                      opts,
         tacplus_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         unsigned                      obfuscate );


int
my_pckt_recv(
         unsigned                      opts,
         int                           s,
         char *                        key,
         tacplus_pckt_t **             pcktp );


int
my_pckt_send(
         unsigned                      opts,
         int                           s,
         char *                        key,
         tacplus_pckt_t *              pckt );


void
my_verbose(
         unsigned                      opts,
         const char *                  fmt,
         ... );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int
main(
         int                           argc,
         char *                        argv[] )
{
   int                           c;
   int                           s;
   int                           opt_index;
   unsigned                      opts;
   char *                        host;
   char *                        user;
   char *                        key;
   unsigned                      type;
   uint8_t                       seq_no;

   // getopt options
   static char          short_opt[] = "dhk:qVv";
   static struct option long_opt[] =
   {
      {"debug",            no_argument,       NULL, 'd' },
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   opts   = 0;
   seq_no = 0;
   key    = NULL;

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'd':
         opts |= ((opts & MY_DEBUG)) ? MY_DEBUGMORE : MY_DEBUG;
         break;

         case 'h':
         printf("Usage: %s [OPTIONS] host[:port] user\n", PROGRAM_NAME);
         printf("       %s [OPTIONS] host[:port] user cmd arg1 ... argN\n", PROGRAM_NAME);
         printf("Options:\n");
         printf("  -d, --debug                               print debugging information\n");
         printf("  -h, --help                                print this help and exit\n");
         printf("  -k secret                                 shared secret key\n");
         printf("  -q, --quiet, --silent                     do not print messages\n");
         printf("  -V, --version                             print version number and exit\n");
         printf("  -v, --verbose                             print verbose messages\n");
         printf("\n");
         return(0);

         case 'k':
         key = optarg;
         break;

         case 'q':
         opts |= MY_QUIET;
         opts &= ~MY_VERBOSE;
         break;

         case 'V':
         printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
         return(0);

         case 'v':
         opts |= MY_VERBOSE;
         opts &= ~MY_QUIET;
         break;

         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
   };
   if ((optind + 2) > argc)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   type = ((optind + 3) < argc) ? TAC_PLUS_AUTHOR : TAC_PLUS_AUTHEN;
   if (!(key))
   {
      fprintf(stderr, "%s: missing required argument `-k'\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   host = argv[optind++];
   user = argv[optind++];

   if ((s = my_connect(opts, host)) == -1)
      return(1);

   seq_no++;

   if (type == TAC_PLUS_AUTHEN)
   {
      if (my_cmd_authen(opts, s, seq_no, key, user) != 0)
      {
         close(s);
         return(1);
      };
   } else {
      if (my_cmd_author(opts, s, seq_no, key, user, (argc - optind), &argv[optind]) != 0)
      {
         close(s);
         return(1);
      };
   };

   close(s);

   return(0);
}


int
my_cmd_authen(
         unsigned                      opts,
         int                           s,
         uint8_t                       seq_no,
         char *                        key,
         char *                        user )
{
   tacplus_pckt_t *        pckt;
   authen_start_t *        authen;
   authen_reply_t *        reply;
   size_t                  nbytes;
   size_t                  off;
   size_t                  user_len;
   size_t                  port_len;
   size_t                  rem_addr_len;
   size_t                  data_len;
   char                    pass[_PASSWORD_LEN+1];
   const char *            msg;
   char *                  str;

   assert(s      != -1);
   assert(key    != NULL);
   assert(user   != NULL);
   assert(pass   != NULL);

   str = getpass("Enter password: ");
   strncpy(pass, str, sizeof(pass));
   pass[sizeof(pass)-1] = '\0';

   user_len       = strlen(user);
   port_len       = strlen(PROGRAM_NAME);
   rem_addr_len   = strlen("127.0.0.1");
   data_len       = strlen(pass);

   nbytes  = sizeof(authen_start_t);    // base amount of bytes
   nbytes += user_len;
   nbytes += port_len;                  // PROGRAM_NAME is used as port
   nbytes += rem_addr_len;              // localhost is used as remote address
   nbytes += data_len;

   // create initial authen start packet
   if ((pckt = my_pckt_alloc(TAC_PLUS_AUTHEN, seq_no, nbytes)) == NULL)
   {
      my_error("out of virtual memory");
      return(1);
   };
   authen                     = (void *)pckt->pckt_body;
   authen->bdy_action         = TAC_PLUS_AUTHEN_LOGIN;
   authen->bdy_priv_lvl       = 15;
   authen->bdy_authen_type    = TAC_PLUS_AUTHEN_TYPE_PAP;
   authen->bdy_authen_service = TAC_PLUS_AUTHEN_SVC_LOGIN;
   authen->bdy_user_len       = strlen(user);
   authen->bdy_port_len       = strlen(PROGRAM_NAME);
   authen->bdy_rem_addr_len   = strlen("127.0.0.1");
   authen->bdy_data_len       = data_len;

   // copy dynamic strings into packet
   off = 0;
   my_pckt_copy_bytes(authen->bdy_bytes, nbytes, &off, user, user_len);
   my_pckt_copy_bytes(authen->bdy_bytes, nbytes, &off, PROGRAM_NAME, port_len);
   my_pckt_copy_bytes(authen->bdy_bytes, nbytes, &off, "127.0.0.1", rem_addr_len);
   my_pckt_copy_bytes(authen->bdy_bytes, nbytes, &off, pass, data_len);

   if (my_pckt_send(opts, s, key, pckt) == -1)
   {
      free(pckt);
      return(1);
   };
   free(pckt);

   if (my_pckt_recv(opts, s, key, &pckt) == -1)
      return(1);
   reply = (void *)pckt->pckt_body;
   if ((opts & MY_VERBOSE))
   {
      switch(reply->bdy_status)
      {
         case TAC_PLUS_AUTHEN_STATUS_PASS:      msg = "received authen status pass"; break;
         case TAC_PLUS_AUTHEN_STATUS_FAIL:      msg = "received authen status fail"; break;
         case TAC_PLUS_AUTHEN_STATUS_GETDATA:   msg = "received authen status getdata"; break;
         case TAC_PLUS_AUTHEN_STATUS_GETUSER:   msg = "received authen status getuser"; break;
         case TAC_PLUS_AUTHEN_STATUS_GETPASS:   msg = "received authen status getpass"; break;
         case TAC_PLUS_AUTHEN_STATUS_RESTART:   msg = "received authen status restart"; break;
         case TAC_PLUS_AUTHEN_STATUS_ERROR:     msg = "received authen status error"; break;
         case TAC_PLUS_AUTHEN_STATUS_FOLLOW:    msg = "received authen status follow"; break;
         default:                               msg = "received authen status unknown"; break;
      };
      my_verbose(opts, "%s", msg);
      if (((ntohs(reply->bdy_server_msg_len))))
      {
         if ((str = malloc(ntohs(reply->bdy_server_msg_len)+1)) == NULL)
         {
            my_error("out of virtual memory");
            free(pckt);
            return(-1);
         };
         memcpy(str, reply->bdy_bytes, ntohs(reply->bdy_server_msg_len));
         str[ntohs(reply->bdy_server_msg_len)] = '\0';
         my_verbose(opts, "server message: %s", str);
         free(str);
      };
   };

   free(pckt);

   return(0);
}


int
my_cmd_author(
         unsigned                      opts,
         int                           s,
         uint8_t                       seq_no,
         char *                        key,
         char *                        user,
         int                           argc,
         char **                       argv )
{
   tacplus_pckt_t *        pckt;
   author_request_t *      author;
   authen_reply_t *        reply;
   int                     pos;
   size_t                  nbytes;
   size_t                  off;
   size_t                  user_len;
   size_t                  port_len;
   size_t                  rem_addr_len;
   size_t                  data_len;
   const char *            msg;
   char *                  str;

   assert(s      != -1);
   assert(key    != NULL);
   assert(user   != NULL);

   user_len       = strlen(user);
   port_len       = strlen(PROGRAM_NAME);
   rem_addr_len   = strlen("127.0.0.1");
   data_len       = strlen("service=shell") + 1;
   data_len      += strlen("cmd=") + strlen(argv[0]) + 1;
   for(pos = 1; (pos < argc); pos++)
      data_len += strlen("cmd-arg=") + strlen(argv[pos]) + 1;

   nbytes  = sizeof(authen_start_t);    // base amount of bytes
   nbytes += user_len;
   nbytes += port_len;                  // PROGRAM_NAME is used as port
   nbytes += rem_addr_len;              // localhost is used as remote address
   nbytes += data_len;

   // create initial authen start packet
   if ((pckt = my_pckt_alloc(TAC_PLUS_AUTHOR, seq_no, nbytes)) == NULL)
   {
      my_error("out of virtual memory");
      return(1);
   };
   pckt->pckt_version         = 0xc0;
   author                     = (void *)pckt->pckt_body;
   author->bdy_authen_method  = TAC_PLUS_AUTHEN_METH_TACACSPLUS;
   author->bdy_priv_lvl       = 15;
   author->bdy_authen_type    = TAC_PLUS_AUTHEN_TYPE_PAP;
   author->bdy_authen_service = TAC_PLUS_AUTHEN_SVC_LOGIN;
   author->bdy_user_len       = strlen(user);
   author->bdy_port_len       = strlen(PROGRAM_NAME);
   author->bdy_rem_addr_len   = strlen("127.0.0.1");
   author->bdy_arg_cnt        = argc + 1;

   // copy dynamic strings into packet
   off = 0;
   author->bdy_bytes[off++] = strlen("service=shell");
   author->bdy_bytes[off++] = strlen("cmd=") + strlen(argv[0]);
   for(pos = 1; (pos < argc); pos++)
      author->bdy_bytes[off++] = strlen("cmd-arg=") + strlen(argv[pos]);
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, user, user_len);
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, PROGRAM_NAME, port_len);
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, "127.0.0.1", rem_addr_len);
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, "service=shell", strlen("service=shell"));
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, "cmd=", strlen("cmd="));
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, argv[0], strlen(argv[0]));
   for(pos = 1; (pos < argc); pos++)
   {
      my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, "cmd-arg=", strlen("cmd-arg="));
      my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, argv[pos], strlen(argv[pos]));
   };
   my_pckt_copy_bytes(author->bdy_bytes, nbytes, &off, "cmd-arg=", strlen("cmd-arg="));

   if (my_pckt_send(opts, s, key, pckt) == -1)
   {
      free(pckt);
      return(1);
   };
   free(pckt);

   if (my_pckt_recv(opts, s, key, &pckt) == -1)
      return(1);
   reply = (void *)pckt->pckt_body;
   if ((opts & MY_VERBOSE))
   {
      switch(reply->bdy_status)
      {
         case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:  msg = "received author status pass add"; break;
         case TAC_PLUS_AUTHOR_STATUS_PASS_REPL: msg = "received author status pass repl"; break;
         case TAC_PLUS_AUTHOR_STATUS_FAIL:      msg = "received author status fail"; break;
         case TAC_PLUS_AUTHOR_STATUS_ERROR:     msg = "received author status error"; break;
         case TAC_PLUS_AUTHOR_STATUS_FOLLOW:    msg = "received author status follow"; break;
         default:                               msg = "received authen status unknown"; break;
      };
      my_verbose(opts, "%s", msg);
      if (((ntohs(reply->bdy_server_msg_len))))
      {
         if ((str = malloc(ntohs(reply->bdy_server_msg_len)+1)) == NULL)
         {
            my_error("out of virtual memory");
            free(pckt);
            return(-1);
         };
         memcpy(str, reply->bdy_bytes, ntohs(reply->bdy_server_msg_len));
         str[ntohs(reply->bdy_server_msg_len)] = '\0';
         my_verbose(opts, "server message: %s", str);
         free(str);
      };
   };

   free(pckt);

   return(0);
}


int
my_connect(
         unsigned                      opts,
         const char *                  hostport )
{
   int                           rc;
   int                           s;
   int                           opt;
   char                          buff[128];
   char *                        str;
   const char *                  host;
   const char *                  port;
   struct addrinfo               hints;
   struct addrinfo *             res;
   socklen_t                     sa_len;
   struct sockaddr_storage       sa;

   assert(hostport != NULL);

   strncpy(buff, hostport, (sizeof(buff)-1));
   buff[sizeof(buff)-1] = '\0';
   host = buff;
   port = "49";
   s    = -1;

   // split host and port
   if (buff[0] == '[')
   {
      if ((str = strchr(buff, ']')) == NULL)
      {
         my_error("malformed hostname");
         return(-1);
      };
      str[0] = '\0';
      if ((str = strrchr(&str[1], ':')) == NULL)
      {
         my_error("malformed port");
         return(-1);
      };
      port = &str[1];
      host = &buff[1];
   } else {
      if ( ((str = strrchr(buff, ':')) != NULL) && (strchr(buff, ':') == str) )
      {
         str[0] = '\0';
         if ((str[1]))
            port = &str[1];
      };
   };

   my_verbose(opts, "resolving \"%s\" on \"%s\" ...", host, port);
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family      = PF_UNSPEC;
   hints.ai_protocol    = IPPROTO_TCP;
   hints.ai_socktype    = SOCK_STREAM;
   hints.ai_flags       = AI_NUMERICSERV | AI_ADDRCONFIG;
   if ((rc = getaddrinfo(host, port, &hints, &res)) != 0)
   {
      my_error("getaddrinfo(\"%s\", \"%s\"): %s", host, port, gai_strerror(rc));
      return(s);
   };
   memset(&sa, 0, sizeof(struct sockaddr_storage));
   memcpy(&sa, res->ai_addr, res->ai_addrlen);
   sa_len   = res->ai_addrlen;
   freeaddrinfo(res);

   switch(sa.ss_family)
   {
      case AF_INET:  break;
      case AF_INET6: break;
      default: my_error("unsupported network family"); return(-1);
   };

   my_verbose(opts, "connecting to \"%s\" ...", my_ntop(&sa, NULL, 0));

   if ((s = socket(sa.ss_family, hints.ai_socktype, 0)) == -1)
   {
      my_error("socket(): %s\n", strerror(errno));
      return(s);
   };

   opt = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (void *)&opt, sizeof(int));
   opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(int));
   opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(int));
   opt = 1; setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(int));

   if (connect(s, (struct sockaddr *)&sa, sa_len) == -1)
   {
      my_error("connect(): %s\n", strerror(errno));
      close(s);
      return(-1);
   };

   sa_len = sizeof(sa);
   getsockname(s, (struct sockaddr *)&sa, &sa_len);
   my_verbose(opts, "connected from \"%s\"", my_ntop(&sa, NULL, 0));

   return(s);
}


int
my_error(
         const char *                  fmt,
         ... )
{
   va_list args;
   fprintf(stderr, "%s: ", PROGRAM_NAME);
   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
   fprintf(stderr, "\n");
   return(1);
}


char *
my_ntop(
         struct sockaddr_storage *     sa,
         char *                        buff,
         size_t                        len )
{
   char           addrstr[INET6_ADDRSTRLEN];
   static char    str[INET6_ADDRSTRLEN+16];
   int            port;

   if (!(buff))
   {
      buff = str;
      len  = sizeof(str);
   };

   switch(sa->ss_family)
   {
      case AF_INET:
      inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, addrstr, sizeof(addrstr));
      port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
      snprintf(buff, (len-1), "%s:%i", addrstr, port);
      break;

      case AF_INET6:
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, addrstr, sizeof(addrstr));
      port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
      snprintf(buff, (len-1), "[%s]:%i", addrstr, port);
      break;

      default:
      return(NULL);
   };
   buff[len-1] = '\0';

   return(buff);
}


tacplus_pckt_t *
my_pckt_alloc(
         uint8_t                       pckt_type,
         uint8_t                       seq_no,
         size_t                        nbytes )
{
   tacplus_pckt_t *        pckt;
   size_t                  size;
   uint32_t                r;

   size = sizeof(tacplus_pckt_t) + nbytes;
   switch(pckt_type)
   {
      case TAC_PLUS_AUTHEN: size += 8; break;
      case TAC_PLUS_AUTHOR: size += 8; break;
      case TAC_PLUS_ACCT:   size += 9; break;
      default:
      my_error("invalid packet type");
      return(NULL);
      break;
   };

   if ((pckt = malloc(size)) == NULL)
   {
      my_error("out of virtual memory");
      return(NULL);
   };
   memset(pckt, 0, size);
   pckt->pckt_version = TAC_PLUS_VER;
   pckt->pckt_type    = pckt_type;
   pckt->pckt_seq_no  = seq_no;
   pckt->pckt_flags   = TAC_PLUS_UNENCRYPTED_FLAG | TAC_PLUS_SINGLE_CONNECT_FLAG;
   pckt->pckt_length  = htonl(nbytes);

   r = (uint32_t)random();
   memcpy(&pckt->pckt_session_id, &r, sizeof(uint32_t));

   return(pckt);
}


tacplus_pckt_t *
my_pckt_allocmore(
         tacplus_pckt_t *              pckt,
         size_t                        nbytes )
{
   void *   ptr;
   size_t   len;
   len = ntohl(pckt->pckt_length);
   if ((ptr = realloc(pckt, (nbytes+len))) == NULL)
   {
      my_error("out of virtual memory");
      return(NULL);
   };
   pckt              = ptr;
   pckt->pckt_length = htonl(nbytes+len);
   if ((len))
      memset(&pckt->pckt_body[len], 0, nbytes);
   return(ptr);
}


int
my_pckt_copy_bytes(
         void *                        dst,
         size_t                        dst_size,
         size_t *                      offp,
         const void *                  bytes,
         size_t                        nbytes )
{
   assert(dst   != NULL);
   assert(offp  != NULL);
   assert(bytes != NULL);
   if (((*offp) + nbytes) > dst_size)
      return(1);
   memcpy((((char *)dst) + *offp), bytes, nbytes);
   *offp += nbytes;
   return(0);
}


void
my_pckt_hexdump(
         unsigned                      opts,
         tacplus_pckt_t *              pckt )
{
   uint8_t *         bytes;
   unsigned          line;
   unsigned          pos;
   unsigned          pckt_len;

   if (!(opts & MY_DEBUG))
      return;
   if ( (!(pckt->pckt_flags & TAC_PLUS_UNENCRYPTED_FLAG)) && (!(opts & MY_DEBUGMORE)) )
      return;

   bytes    = (void *)pckt;
   pckt_len = ntohl(pckt->pckt_length) + sizeof(tacplus_pckt_t);

   printf("packet: version: %u.%u; type: ", (pckt->pckt_version >> 4), (pckt->pckt_version & 0x0f));
   switch(pckt->pckt_type)
   {
      case TAC_PLUS_AUTHEN: printf("authen;"); break;
      case TAC_PLUS_AUTHOR: printf("author;"); break;
      case TAC_PLUS_ACCT:   printf("acct;"); break;
      default: printf("unknown;"); break;
   };
   printf(" seq_no: %u;", pckt->pckt_seq_no);
   printf(" session_id: %08x;", ntohl(pckt->pckt_session_id));
   printf("\n");
   printf("packet: length: %u (0x%x);", pckt_len, pckt_len);
   printf(" flags:");
   if (!(pckt->pckt_flags))
      printf(" NONE");
   if ((pckt->pckt_flags & TAC_PLUS_SINGLE_CONNECT_FLAG))
      printf(" SINGLE-CONNECT");
   if ((pckt->pckt_flags & TAC_PLUS_UNENCRYPTED_FLAG))
      printf(" UNENCRYPTED");
   printf(";");
   printf("\n");


   printf(" offset    0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f  0123456789abcdef\n");
   for(line = 0; (line < pckt_len); line += 0x10)
   {
      printf("%08x", line);
      for(pos = line; (pos < (line+0x10)); pos++)
      {
         if ((pos & 0x03) == 0)
            printf(" ");
         if (pos < pckt_len)
            printf(" %02x", bytes[pos]);
         else
            printf("   ");
      };
      printf("  ");
      for(pos = line; ((pos < (line+0x10)) && (pos < pckt_len)); pos++)
         printf("%c", ((bytes[pos] < 0x20) || (bytes[pos] > 0x7e)) ? '.' : bytes[pos]);
      printf("\n");
      if ((line & 0xf0) == 0xf0)
         printf("\n");
   };

   return;
}


int
my_pckt_md5pad(
         tacplus_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         uint8_t *                     md5pad,
         uint8_t *                     md_value )
{
   unsigned             md_len;
//   unsigned char        md_value[EVP_MAX_MD_SIZE];
   EVP_MD_CTX *         mdctx;

   assert(pckt     != NULL);
   assert(key      != NULL);
   assert(md_value != NULL);

   key_len = ((key)) ? key_len : 0;

   mdctx = EVP_MD_CTX_new();
   EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
   EVP_DigestUpdate(mdctx, &pckt->pckt_session_id, 4);
   EVP_DigestUpdate(mdctx, key, key_len);
   EVP_DigestUpdate(mdctx, &pckt->pckt_version, 1);
   EVP_DigestUpdate(mdctx, &pckt->pckt_seq_no, 1);
   if ((md5pad))
      EVP_DigestUpdate(mdctx, md5pad, 16);
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);
   EVP_MD_CTX_free(mdctx);

   return(0);
}


int
my_pckt_obfuscate(
         unsigned                      opts,
         tacplus_pckt_t *              pckt,
         char *                        key,
         size_t                        key_len,
         unsigned                      obfuscate )
{
   uint8_t        md_value[EVP_MAX_MD_SIZE];
   size_t         pckt_len;
   size_t         off;
   size_t         pos;

   assert(pckt != NULL);
   assert(key  != NULL);

   // check for existing obfuscation and flip flag
   obfuscate = ((obfuscate)) ? 0 : TAC_PLUS_UNENCRYPTED_FLAG;
   if ((pckt->pckt_flags & TAC_PLUS_UNENCRYPTED_FLAG) == obfuscate)
      return(0);
   pckt->pckt_flags ^= TAC_PLUS_UNENCRYPTED_FLAG;
   my_verbose(opts, "%s packet", ( ((pckt->pckt_flags&TAC_PLUS_UNENCRYPTED_FLAG)) ? "deobfuscating" : "obfuscating"));

   // create initial pad
   my_pckt_md5pad(pckt, key, key_len, NULL, md_value);
   pckt_len = ntohl(pckt->pckt_length);

   // apply pads to packet body
   for(off = 0; ((pckt_len - off) > 15); off += 16)
   {
      for(pos = 0; (pos < 16); pos++)
         pckt->pckt_body[off+pos] ^= md_value[pos];
      my_pckt_md5pad(pckt, key, key_len, md_value, md_value);
   };
   for(pos = 0; ((pos+off) < pckt_len); pos++)
      pckt->pckt_body[off+pos] ^= md_value[pos];

   return(0);
}


int
my_pckt_recv(
         unsigned                      opts,
         int                           s,
         char *                        key,
         tacplus_pckt_t **             pcktp )
{
   size_t               pckt_len;
   ssize_t              rc;
   tacplus_pckt_t *     pckt;
   void *               ptr;

   my_verbose(opts, "receiving packet ...");

   pckt_len = sizeof(tacplus_pckt_t);

   if ((pckt = malloc(pckt_len)) == NULL)
   {
      my_error("out of virtual memory");
      free(pckt);
      return(-1);
   };

   if ((rc = read(s, pckt, pckt_len)) == -1)
   {
      my_error("recv(): %s", strerror(errno));
      free(pckt);
      return(-1);
   };
   if (rc != (ssize_t)pckt_len)
   {
      my_error("my_pckt_recv(): unable to read data");
      free(pckt);
      return(-1);
   };

   pckt_len = ntohl(pckt->pckt_length) + sizeof(tacplus_pckt_t);
   if ((ptr = realloc(pckt, pckt_len)) == NULL)
   {
      my_error("out of virtual memory");
      free(pckt);
      return(-1);
   };
   pckt = ptr;

   if ((rc = read(s, pckt->pckt_body, ntohl(pckt->pckt_length))) == -1)
   {
      my_error("recv(): %s", strerror(errno));
      free(pckt);
      return(-1);
   };
   if (rc != (ssize_t)ntohl(pckt->pckt_length))
   {
      my_error("my_pckt_recv(): unable to read data");
      free(pckt);
      return(-1);
   };

   my_pckt_hexdump(opts, pckt);
   my_pckt_obfuscate(opts, pckt, key, strlen(key), 0);
   my_pckt_hexdump(opts, pckt);

   *pcktp = pckt;

   return(0);
}


int
my_pckt_send(
         unsigned                      opts,
         int                           s,
         char *                        key,
         tacplus_pckt_t *              pckt )
{
   size_t         pckt_len;
   const char *   str;

   my_pckt_hexdump(opts, pckt);
   my_pckt_obfuscate(opts, pckt, key, strlen(key), 1);
   my_pckt_hexdump(opts, pckt);

   switch(pckt->pckt_type)
   {
      case TAC_PLUS_AUTHEN: str = "authen";  break;
      case TAC_PLUS_AUTHOR: str = "author";  break;
      case TAC_PLUS_ACCT:   str = "acct";    break;
      default:              str = "unknown"; break;
   };
   my_verbose(opts, "sending %s packet ...", str);

   pckt_len = ntohl(pckt->pckt_length) + sizeof(tacplus_pckt_t);
   if (write(s, (void *)pckt, pckt_len) == -1)
   {
      my_error("write(): %s", strerror(errno));
      return(-1);
   };

   return(0);
}


void
my_verbose(
         unsigned                      opts,
         const char *                  fmt,
         ... )
{
   va_list args;
   if (!(opts & MY_VERBOSE))
      return;
   printf("%s: ", PROGRAM_NAME);
   va_start(args, fmt);
   vprintf(fmt, args);
   va_end(args);
   printf("\n");
   return;
}

/* end of source */
