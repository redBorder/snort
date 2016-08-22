/*
 **  $Id$
 **
 **  sfcontrol.c
 **
 **  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 **  Copyright (C) 2002-2013 Sourcefire, Inc.
 **  Author(s):  Ron Dempster <rdempster@sourcefire.com>
 **
 **  NOTES
 **  5.5.11 - Initial Source Code. Dempster
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "sfcontrol.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum
{
    PRINT_MODE_FAST,
    PRINT_MODE_DETAIL
}PrintMode;

#define TIMEOUT_KEYWORD  "-timeout"

#define RECEIVED_SEGMENT_SUCCESFULY_CODE 9

struct _CS_MESSAGE
{
    CSMessageHeader hdr;
    CSMessageDataHeader msg_hdr;
    uint8_t msg[4096];
} __attribute__((packed));

typedef struct _CS_MESSAGE CSMessage;

static void DumpHex(FILE *fp, const uint8_t *data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    for (i=0, pos=0; i<len; i++, pos++)
    {
        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) && (c == ' ' || !isspace(c)))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos)
    {
        str[pos] = 0;
        for (; pos < 17; pos++)
        {
            if (pos == 8)
            {
                pos++;
                fprintf(fp, "%s", "    ");
            }
            else
            {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}

static void DisplayUsage(const char *progname)
{
    fprintf(stderr, "Usage %s <snort log dir> "TIMEOUT_KEYWORD
        "<timeout (ms)>\n",progname);
}

static int SendMessage(int socket_fd, const CSMessage *msg)
{
    ssize_t numsent;
    const unsigned total_len = sizeof(*msg);
    unsigned total = 0;

    do
    {
        numsent = write(socket_fd, (*(uint8_t **)&msg) + total, total_len - total);
        if (!numsent)
            return 0;
        else if (numsent > 0)
            total += numsent;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < total_len);
    return 1;
}

static int ReadData(int socket_fd, uint8_t *buffer, uint32_t length, unsigned long timeout_ms)
{
    ssize_t numread;
    unsigned total = 0;
    fd_set socket_fd_set;

    do
    {
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000)*1000};
        FD_ZERO(&socket_fd_set);
        FD_SET(socket_fd,&socket_fd_set);

        const int select_result = select(socket_fd+1,&socket_fd_set,NULL,NULL,&tv);
        if(select_result <= 0)
            return -1;
        else if(select_result == 0)
            return 0;

        numread = read(socket_fd, buffer + total, length - total);
        if (!numread)
            return 0;
        else if (numread > 0)
            total += numread;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < length);
    if (total < length)
        return 0;
    return 1;
}

static int ReadResponse(int socket_fd, CSMessageHeader *hdr, int timeout_ms)
{
    const int rc = ReadData(socket_fd,(uint8_t *)hdr,sizeof(*hdr),timeout_ms);
    if(rc > 0){
        hdr->length = ntohl(hdr->length);
        hdr->version = ntohs(hdr->version);
        hdr->type = ntohs(hdr->type);
    }

    return rc;
}

static void ConnectToUnixSocket(const char * const name, int * const psock)
{
    struct sockaddr_un sunaddr;
    int sock = -1;
    int rval;

    memset(&sunaddr, 0, sizeof(sunaddr));
    rval = snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", name);
    if (rval < 0 || (size_t)rval >= sizeof(sunaddr.sun_path))
    {
        fprintf(stderr, "Socket name '%s' is too long\n", name);
        exit(-1);
    }

    sunaddr.sun_family = AF_UNIX;

    /* open the socket */
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
        exit(-1);
    }

    if (connect(sock, (struct sockaddr *) &sunaddr, sizeof(sunaddr)) == -1)
    {
        fprintf(stderr, "Unable to connect to UNIX socket at %s: %s\n", name, strerror(errno));
        close(sock);
        exit(-1);
    }

    *psock = sock;
}

int main(int argc, char *argv[])
{
    int rval;
    char socket_fn[PATH_MAX];
    int socket_fd;
    CSMessage *message;
    const unsigned long type = 1361;
    const char *sep;
    ssize_t len;
    PrintMode mode = PRINT_MODE_FAST;
    unsigned int timeout_ms = 0;

    if (argc != 4 || !*argv[1] || !*argv[2] || !*argv[3])
    {
        DisplayUsage(argv[0]);
        exit(-1);
    }
    else if (argc > 2)
    {
        int idx = 2;

        if((strlen(TIMEOUT_KEYWORD) == strlen(argv[idx])) &&
           (strcmp(TIMEOUT_KEYWORD,argv[idx]) == 0))
        {
            mode = PRINT_MODE_FAST;
            idx ++;
        }

        if (argc > idx)
        {
             timeout_ms = atoi(argv[idx]);
        }
    }

    len = strlen(argv[1]);
    if (len && argv[1][len - 1] == '/')
        sep = "";
    else
        sep = "/";

    snprintf(socket_fn, sizeof(socket_fn), "%s%s%s", argv[1], sep, CONTROL_FILE);
    ConnectToUnixSocket(socket_fn, &socket_fd);

    message = malloc(sizeof *message);
    if (message == NULL)
    {
        fprintf(stderr, "%s: could not allocate message.\n",argv[0]);
        exit(-1);
    }

    message->hdr.version = htons(CS_HEADER_VERSION);
    message->hdr.type = htons((uint16_t)type);
    message->hdr.length = 0;

    if ((rval = SendMessage(socket_fd, message)) < 0)
    {
        fprintf(stderr, "Failed to send the message: %s\n", strerror(errno));
        close(socket_fd);
        exit(-1);
    }
    else if (!rval)
    {
        fprintf(stderr, "Server closed the socket\n");
        close(socket_fd);
        exit(-1);
    }

    if ((rval = ReadResponse(socket_fd, &message->hdr,timeout_ms)) < 0)
    {
        fprintf(stderr, "Failed to read the response: %s\n", strerror(errno));
        close(socket_fd);
        exit(-1);
    }
    else if (!rval)
    {
        fprintf(stderr, "Server closed the socket before sending a response\n");
        close(socket_fd);
        exit(-1);
    }

    if (message->hdr.version != CS_HEADER_VERSION)
    {
        printf("%s: bad response version\n",argv[0]);
        close(socket_fd);
        exit(-1);
    }

    if (message->hdr.type != 9)
    {
        printf("%s: bad response type:%d, expected %d",argv[0],message->hdr.type,9);
        close(socket_fd);
        exit(-1);
    }

    if (message->hdr.length)
    {

        if (message->hdr.length < sizeof(message->msg_hdr))
        {
            printf("%s: response message is too small\n",argv[0]);
            close(socket_fd);
            exit(-1);
        }

        if (message->hdr.length > sizeof(message->msg))
        {
            printf("%s: response message is too large\n",argv[0]);
            close(socket_fd);
            exit(-1);
        }

        if ((rval = ReadData(socket_fd, (uint8_t *)message+sizeof(message->hdr), message->hdr.length, timeout_ms)) < 0)
        {
            fprintf(stderr, "Failed to read the response data: %s\n", strerror(errno));
            close(socket_fd);
            exit(-1);
        }
        else if (!rval)
        {
            fprintf(stderr, "Server closed the socket before sending the response data\n");
            close(socket_fd);
            exit(-1);
        }

        message->msg_hdr.code = ntohl(message->msg_hdr.code);
        message->msg_hdr.length = ntohs(message->msg_hdr.length);

        if (mode == PRINT_MODE_DETAIL)
        {
            fprintf(stdout, "Response %04X with code %d and length %u\n",
                message->hdr.type, message->msg_hdr.code, message->msg_hdr.length);
            DumpHex(stdout, message->msg, message->msg_hdr.length);
        }
        else if (mode == PRINT_MODE_FAST)
        {
            if (message->msg_hdr.length == message->hdr.length - sizeof(message->msg_hdr))
            {
                message->msg[message->msg_hdr.length-1] = 0;
                fprintf(stdout, "Response %04X with code %d (%s)\n",
                    message->hdr.type, message->msg_hdr.code, message->msg);
            }
            else
                fprintf(stdout, "Response %04X with code %d\n", message->hdr.type, message->msg_hdr.code);
        }
    }
    else
    {
        if (mode == PRINT_MODE_DETAIL)
            printf("Response %04X without data\n", message->hdr.type);
        else
            printf("Response %04X\n", message->hdr.type);
    }

    return 0;
}

