/*
 **  $Id: sfcontrol.c,v 1.12 2015/04/23 18:28:11 jocornet Exp $
 **
 **  sfcontrol.c
 **
 **  Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
#include <poll.h>

#include "sfcontrol.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct _CS_MESSAGE
{
    CSMessageHeader hdr;
    CSMessageDataHeader msg_hdr;
    uint8_t msg[4096];
} __attribute__((packed));

typedef struct _CS_MESSAGE CSMessage;

static void DisplayUsage(const char *progname)
{
    fprintf(stderr, "Usage %s <snort cs dir> <timeout_ms>\n",progname);
}

static int SendMessage(int socket_fd, const CSMessage *msg, uint32_t len)
{
    ssize_t numsent;
    unsigned total_len = sizeof(*msg) + len;
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

static int ReadData(int socket_fd, uint8_t *buffer, uint32_t length)
{
    ssize_t numread;
    unsigned total = 0;

    do
    {
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

static int ReadResponse(int socket_fd, CSMessageHeader *hdr,int timeout_ms)
{
    ssize_t numread;
    unsigned total = 0;

    do
    {
        struct pollfd fds = { fd: socket_fd, events: POLLIN };
        const int r = poll(&fds, 1, timeout_ms);

        if (r <= 0)
            return r;

        numread = read(socket_fd, (*(uint8_t **)&hdr) + total, sizeof(*hdr) - total);
        if (!numread)
            return 0;
        else if (numread > 0)
            total += numread;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < sizeof(*hdr));
    if (total < sizeof(*hdr))
        return 0;

    hdr->length = ntohl(hdr->length);
    hdr->version = ntohs(hdr->version);
    hdr->type = ntohs(hdr->type);
    return 1;
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
    char *p;
    CSMessage *message;
    unsigned long type;
    const char *sep;
    ssize_t len;

    if (argc != 3 || !*argv[1] || !*argv[2])
    {
        DisplayUsage(argv[0]);
        exit(-1);
    }

    type = 2;

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
        fprintf(stderr, "snort_control: could not allocate message.\n");
        exit(-1);
    }

    message->hdr.version = htons(CS_HEADER_VERSION);
    message->hdr.type = htons((uint16_t)type);
    message->hdr.length = 0;

    const int timeout_ms = strtoul(argv[2], &p, 0);
    if (*p || timeout_ms < 1)
    {
        DisplayUsage(argv[0]);
        exit(-1);
    }

    if ((rval = SendMessage(socket_fd, message, 0)) < 0)
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

    do
    {
        /* Reusing the same CSMessage to capture the response */
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
            printf("snort_control: bad response version\n");
            close(socket_fd);
            exit(-1);
        }

        if (message->hdr.length)
        {

            if (message->hdr.length < sizeof(message->msg_hdr))
            {
                printf("snort_control: response message is too small\n");
                close(socket_fd);
                exit(-1);
            }

            if (message->hdr.length > sizeof(message->msg))
            {
                printf("snort_control: response message is too large\n");
                close(socket_fd);
                exit(-1);
            }

            if ((rval = ReadData(socket_fd, (uint8_t *)message+sizeof(message->hdr), message->hdr.length)) < 0)
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

            if (message->msg_hdr.length == message->hdr.length - sizeof(message->msg_hdr))
            {
                message->msg[message->msg_hdr.length-1] = 0;
                fprintf(stdout, "Response %04X with code %d (%s)\n",
                    message->hdr.type, message->msg_hdr.code, message->msg);
            }
            else
            {
                fprintf(stdout, "Response %04X with code %d\n", message->hdr.type, message->msg_hdr.code);
            }
        }
        else
        {
            printf("Response %04X\n", message->hdr.type);
        }
    } while (message->hdr.type == CS_HEADER_DATA);
    return 0 == message->msg_hdr.code ? 0 : -2;
}

