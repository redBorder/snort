/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 * Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
 * Author: Adam Keeton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef WIN32
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#ifdef HAVE_UUID_UUID_H
#include<uuid/uuid.h>
#endif

#include "Unified2_common.h"
#include "u2boat.h"

#define SUCCESS 314159265
#define STEVE -1
#define FAILURE STEVE

#ifndef WIN32
#ifndef uint32_t
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
#endif
#else
static void inet_ntop(int family, const void *ip_raw, char *buf, int bufsize) {
    int i;

    if(!ip_raw || !buf || !bufsize ||
       (family != AF_INET && family != AF_INET6) ||
       /* Make sure if it's IPv6 that the buf is large enough. */
       /* Need atleast a max of 8 fields of 4 bytes plus 7 for colons in
        * between.  Need 1 more byte for null. */
       (family == AF_INET6 && bufsize < 8*4 + 7 + 1) ||
       /* Make sure if it's IPv4 that the buf is large enough. */
       /* 4 fields of 3 numbers, plus 3 dots and a null byte */
       (family == AF_INET && bufsize < 3*4 + 4) )
    {
        if(buf && bufsize > 0) buf[0] = 0;
        return;
    }

    /* 4 fields of at most 3 characters each */
    if(family == AF_INET) {
        u_int8_t *p = (u_int8_t*)ip_raw;

        for(i=0; p < ((u_int8_t*)ip_raw) + 4; p++) {
            i += sprintf(&buf[i], "%d", *p);

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if(i < bufsize && ((p + 1) < ((u_int8_t*)ip_raw+4)))
                buf[i] = '.';

            i++;
        }

    /* Check if this is really just an IPv4 address represented as 6,
     * in compatible format */
#if 0
    }
    else if(!field[0] && !field[1] && !field[2]) {
        unsigned char *p = (unsigned char *)(&ip->ip[12]);

        for(i=0; p < &ip->ip[16]; p++)
             i += sprintf(&buf[i], "%d.", *p);
#endif
    }
    else {
        u_int16_t *p = (u_int16_t*)ip_raw;

        for(i=0; p < ((u_int16_t*)ip_raw) + 8; p++) {
            i += sprintf(&buf[i], "%04x", ntohs(*p));

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if(i < bufsize && ((p + 1) < ((u_int16_t*)ip_raw) + 8))
                buf[i] = ':';

            i++;
        }
    }
}
#endif

static long s_off = 0;

#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff

static void extradata_dump(const u2record *record,FILE *out_file) {
    uint8_t *field, *data;
    int i;
    int len = 0;
    SerialUnified2ExtraData event;
    Unified2ExtraDataHdr eventHdr;
    uint32_t ip;
    char ip6buf[INET6_ADDRSTRLEN+1];
    struct in6_addr ipAddr;

    memcpy(&eventHdr, record->data, sizeof(Unified2ExtraDataHdr));

    memcpy(&event, record->data + sizeof(Unified2ExtraDataHdr) , sizeof(SerialUnified2ExtraData));

    /* network to host ordering */
    field = (uint8_t*)&eventHdr;
    for(i=0; i<2; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = (uint8_t*)&event;
    for(i=0; i<6; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }



    fprintf(out_file,"\n(ExtraDataHdr)\n"
            "\tevent type: %u\tevent length: %u\n",
            eventHdr.event_type, eventHdr.event_length);

    fprintf(out_file,"\n(ExtraData)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
            "\ttype: %u\tdatatype: %u\tbloblength: %u\t",
             event.sensor_id, event.event_id,
             event.event_second, event.type,
             event.data_type, event.blob_length);

    len = event.blob_length - sizeof(event.blob_length) - sizeof(event.data_type);

    switch(event.type)
    {
        case EVENT_INFO_XFF_IPV4:
            memcpy(&ip, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData), sizeof(uint32_t));
            ip = ntohl(ip);
            fprintf(out_file,"Original Client IP: %u.%u.%u.%u\n",
                    TO_IP(ip));
            break;

        case EVENT_INFO_XFF_IPV6:
            memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
            fprintf(out_file,"Original Client IP: %s\n",
                    ip6buf);
            break;

        case EVENT_INFO_GZIP_DATA:
            fprintf(out_file,"GZIP Decompressed Data: %.*s\n",
                len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_JSNORM_DATA:
            fprintf(out_file,"Normalized JavaScript Data: %.*s\n",
                len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_SMTP_FILENAME:
            fprintf(out_file,"SMTP Attachment Filename: %.*s\n",
                len,record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_SMTP_MAILFROM:
            fprintf(out_file,"SMTP MAIL FROM Addresses: %.*s\n",
                    len,record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_SMTP_RCPTTO:
            fprintf(out_file,"SMTP RCPT TO Addresses: %.*s\n",
                len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_SMTP_EMAIL_HDRS:
            fprintf(out_file,"SMTP EMAIL HEADERS: \n%.*s\n",
                len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_HTTP_URI:
            fprintf(out_file,"HTTP URI: %.*s\n",
                len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
            break;

        case EVENT_INFO_HTTP_HOSTNAME:
            fprintf(out_file,"HTTP Hostname: ");
            data = record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData);
            for(i=0; i < len; i++)
            {
                if(iscntrl(data[i]))
                    fprintf(out_file,"%c",'.');
                else
                    fprintf(out_file,"%c",data[i]);
            }
            fprintf(out_file,"\n");
            break;

        case EVENT_INFO_IPV6_SRC:
            memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
            fprintf(out_file,"IPv6 Source Address: %s\n",
                    ip6buf);
            break;

        case EVENT_INFO_IPV6_DST:
            memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
            fprintf(out_file,"IPv6 Destination Address: %s\n",
                    ip6buf);
            break;

        default :
            break;
    }

}

static void event_dump(const u2record *record, FILE *out_file) {
    uint8_t *field;
    int i;
    Serial_Unified2IDSEvent_legacy event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEvent_legacy));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first 11 fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<11; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    /* done changing the network ordering */


    fprintf(out_file,
        "\n(Event)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
            "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
            "\tpriority: %u\tip source: %u.%u.%u.%u\tip destination: %u.%u.%u.%u\n"
            "\tsrc port: %u\tdest port: %u\tprotocol: %u\timpact_flag: %u\tblocked: %u\n",
             event.sensor_id, event.event_id,
             event.event_second, event.event_microsecond,
             event.signature_id, event.generator_id,
             event.signature_revision, event.classification_id,
             event.priority_id, TO_IP(event.ip_source),
             TO_IP(event.ip_destination), event.sport_itype,
             event.dport_icode, event.protocol,
             event.impact_flag, event.blocked);
}

static void event6_dump(const u2record *record,FILE *out_file) {
    uint8_t *field;
    int i;
    Serial_Unified2IDSEventIPv6_legacy event;
    char ip6buf[INET6_ADDRSTRLEN+1];

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEventIPv6_legacy));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<9; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    /* done changing the network ordering */

    inet_ntop(AF_INET6, &event.ip_source, ip6buf, INET6_ADDRSTRLEN);

    fprintf(out_file,"\n(IPv6 Event)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
            "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
            "\tpriority: %u\tip source: %s\t",
             event.sensor_id, event.event_id,
             event.event_second, event.event_microsecond,
             event.signature_id, event.generator_id,
             event.signature_revision, event.classification_id,
             event.priority_id, ip6buf);


    inet_ntop(AF_INET6, &event.ip_destination, ip6buf, INET6_ADDRSTRLEN);
    fprintf(out_file,"ip destination: %s\n"
            "\tsrc port: %u\tdest port: %u\tprotocol: %u\timpact_flag: %u\tblocked: %u\n",
             ip6buf, event.sport_itype,
             event.dport_icode, event.protocol,
             event.impact_flag, event.blocked);
}



static void event2_dump(const u2record *record, FILE *out_file) {
    uint8_t *field;
    int i;

    Serial_Unified2IDSEvent event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEvent));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first 11 fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<11; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    field +=6;
    *(uint32_t*)field = ntohl(*(uint32_t*)field); /* mpls_label */
    field += 4;
    /* policy_id and vlanid */
    for(i=0; i<2; i++, field+=2) {
        *(uint16_t*)field = ntohs(*(uint16_t*)field);
    }
    /* done changing the network ordering */


    fprintf(out_file,"\n(Event)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
            "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
            "\tpriority: %u\tip source: %u.%u.%u.%u\tip destination: %u.%u.%u.%u\n"
            "\tsrc port: %u\tdest port: %u\tprotocol: %u\timpact_flag: %u\tblocked: %u\n"
            "\tmpls label: %u\tvland id: %u\tpolicy id: %u\n",
             event.sensor_id, event.event_id,
             event.event_second, event.event_microsecond,
             event.signature_id, event.generator_id,
             event.signature_revision, event.classification_id,
             event.priority_id, TO_IP(event.ip_source),
             TO_IP(event.ip_destination), event.sport_itype,
             event.dport_icode, event.protocol,
             event.impact_flag, event.blocked,
             event.mpls_label, event.vlanId, event.pad2);

}

static void event2_6_dump(const u2record *record,FILE *out_file) {
    uint8_t *field;
    int i;
    char ip6buf[INET6_ADDRSTRLEN+1];
    Serial_Unified2IDSEventIPv6 event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEventIPv6));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<9; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    field +=6;
    *(uint32_t*)field = ntohl(*(uint32_t*)field); /* mpls_label */
    field += 4;
    /* policy_id and vlanid */
    for(i=0; i<2; i++, field+=2) {
        *(uint16_t*)field = ntohs(*(uint16_t*)field);
    }
    /* done changing the network ordering */

    inet_ntop(AF_INET6, &event.ip_source, ip6buf, INET6_ADDRSTRLEN);

    fprintf(out_file,"\n(IPv6 Event)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
            "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
            "\tpriority: %u\tip source: %s\t",
             event.sensor_id, event.event_id,
             event.event_second, event.event_microsecond,
             event.signature_id, event.generator_id,
             event.signature_revision, event.classification_id,
             event.priority_id, ip6buf);


    inet_ntop(AF_INET6, &event.ip_destination, ip6buf, INET6_ADDRSTRLEN);
    fprintf(out_file,"ip destination: %s\n"
            "\tsrc port: %u\tdest port: %u\tprotocol: %u\timpact_flag: %u\tblocked: %u\n"
            "\tmpls label: %u\tvland id: %u\tpolicy id: %u\n",
             ip6buf, event.sport_itype,
             event.dport_icode, event.protocol,
             event.impact_flag, event.blocked,
             event.mpls_label, event.vlanId,event.pad2);

}

#define LOG_CHARS 16

static void LogBuffer (const uint8_t* p, unsigned n,FILE *out_file)
{
    char hex[(3*LOG_CHARS)+1];
    char txt[LOG_CHARS+1];
    unsigned odx = 0, idx = 0, at = 0;

    for ( idx = 0; idx < n; idx++)
    {
        uint8_t byte = p[idx];
        sprintf(hex + 3*odx, "%2.02X ", byte);
        txt[odx++] = isprint(byte) ? byte : '.';

        if ( odx == LOG_CHARS )
        {
            txt[odx] = hex[3*odx] = '\0';
            fprintf(out_file,"[%5u] %s %s\n", at, hex, txt);
            at = idx + 1;
            odx = 0;
        }
    }
    if ( odx )
    {
        txt[odx] = hex[3*odx] = '\0';
        fprintf(out_file,"[%5u] %-48.48s %s\n", at, hex, txt);
    }
}

static void packet_dump(const u2record *record,FILE *out_file) {
    uint32_t counter;
    uint8_t *field;

    unsigned offset = sizeof(Serial_Unified2Packet)-4;
    unsigned reclen = record->length - offset;

    Serial_Unified2Packet packet;
    memcpy(&packet, record->data, sizeof(Serial_Unified2Packet));

    /* network to host ordering */
    /* The first 7 fields need to be convertted */
    field = (uint8_t*)&packet;
    for(counter=0; counter<7; counter++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }
    /* done changing from network ordering */

    fprintf(out_file,"\nPacket\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
            "\tpacket second: %u\tpacket microsecond: %u\n"
            "\tlinktype: %u\tpacket_length: %u\n",
            packet.sensor_id, packet.event_id, packet.event_second,
            packet.packet_second, packet.packet_microsecond, packet.linktype,
            packet.packet_length);

    
    if ( record->length <= offset )
        return;

    if ( packet.packet_length != reclen )
    {
        fprintf(out_file,"ERROR: logged %u but packet_length = %u\n",
            record->length-offset, packet.packet_length);

        if ( packet.packet_length < reclen )
        {
            reclen = packet.packet_length;
            s_off = reclen + offset;
        }
    }
    LogBuffer(record->data+offset, reclen,out_file);
}

int u2dump(const u2record *record, FILE *out_file) {
    if(record->type == UNIFIED2_IDS_EVENT) event_dump(record, out_file);
    else if(record->type == UNIFIED2_IDS_EVENT_VLAN) event2_dump(record,out_file);
    else if(record->type == UNIFIED2_PACKET) packet_dump(record,out_file);
    else if(record->type == UNIFIED2_IDS_EVENT_IPV6) event6_dump(record,out_file);
    else if(record->type == UNIFIED2_IDS_EVENT_IPV6_VLAN) event2_6_dump(record,out_file);
    else if(record->type == UNIFIED2_EXTRA_DATA) extradata_dump(record,out_file);

    return 0;
}