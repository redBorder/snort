/*
 * Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 * Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
 * Author: Ryan Jordan <ryan.jordan@sourcefire.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "u2boat.h"
#include "u2spewfoo.h"

#define FAILURE -1
#define SUCCESS 0

#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define PCAP_TIMEZONE 0
#define PCAP_SIGFIGS 0
#define PCAP_SNAPLEN 65535
#define ETHERNET 1
#define PCAP_LINKTYPE ETHERNET
#define MAX_U2RECORD_DATA_LENGTH 65536

struct filters {
    uint64_t lower_timestamp;
    uint64_t upper_timestamp;
    uint32_t signature_id;
    uint32_t generator_id;

    int src_ip_family,dst_ip_family;
    uint8_t src_ip[sizeof(struct in6_addr)], dst_ip[sizeof(struct in6_addr)];
    char *src_ip_str,*dst_ip_str;
};

#define DEFAULT_FILTERS_INITIALIZER {0,0,0,0}

static int ConvertLog(FILE *input, FILE *output, char *format, struct filters *defined_filters);
static int GetRecord(FILE *input, u2record *rec);
static int PcapInitOutput(FILE *output);
static int PcapConversion(const u2record *rec, FILE *output);
static int isEvent(const u2record *record);
static int FamilyOfRecord(const u2record *record);
static const u2event *ExtendedRecordOf(const u2record *record);

/* Filtering prototypes */
static int EventPassFilters(const struct filters *defined_filters,const u2record *record);
static int EventPassIPFilters(const struct filters *defined_filters,const u2record *record);
static int IPPassSourceIpFilter(const struct filters *defined_filters,const u2record *record);
static int IPPassDestinationIPFilter(const struct filters *defined_filters,const u2record *record);
static const u2ipv4event *IPv4EventOf(const u2record *record);
static const u2ipv6event *IPv6EventOf(const u2record *record);
static int IsEqualIPv4(const struct in_addr *a,const uint32_t b);
static int IsEqualIPv6(const struct in6_addr *a,const struct in6_addr *b);
static int SmartInetpton(int *family,const char *str,void *buffer);

static int ConvertLog(FILE *input, FILE *output, char *format, struct filters *defined_filters)
{
    u2record tmp_record;
    int filters_passed = 1;

    /* Determine conversion function */
    int (* ConvertRecord)(const u2record *, FILE *) = NULL;

    /* This will become an if/else series once more formats are supported.
     * Callbacks are used so that this comparison only needs to happen once. */
    if (strcmp(format, "pcap") == 0)
    {
        ConvertRecord = PcapConversion;
    }
    if (strcmp(format, "text") == 0)
    {
        ConvertRecord = u2dump;
    }

    if (ConvertRecord == NULL)
    {
        fprintf(stderr, "Error setting conversion routine, aborting...\n");
        return FAILURE;
    }

    /* Initialize the record's data pointer */
    tmp_record.data = malloc(MAX_U2RECORD_DATA_LENGTH * sizeof(uint8_t));
    if (tmp_record.data == NULL)
    {
        fprintf(stderr, "Error allocating memory, aborting...\n");
        return FAILURE;
    }

    /* Run through input file and convert records */
    while ( !(feof(input) || ferror(input) || ferror(output)) )
    {
        if (GetRecord(input, &tmp_record) == FAILURE)
        {
            break;
        }

        /* if is event, update filters_passed status */
        if(isEvent(&tmp_record))
            filters_passed = EventPassFilters(defined_filters,&tmp_record);

        if(filters_passed == 0)
            continue;

        if (ConvertRecord(&tmp_record, output) == FAILURE)
        {
            break;
        }
    }
    if (tmp_record.data != NULL)
    {
        free(tmp_record.data);
        tmp_record.data = NULL;
    }
    if (ferror(input))
    {
        fprintf(stderr, "Error reading input file, aborting...\n");
        return FAILURE;
    }
    if (ferror(output))
    {
        fprintf(stderr, "Error reading output file, aborting...\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* Create and write the pcap file's global header */
static int PcapInitOutput(FILE *output)
{
    size_t ret;
    struct pcap_file_header hdr;

    hdr.magic = PCAP_MAGIC_NUMBER;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = PCAP_TIMEZONE;
    hdr.sigfigs = PCAP_SIGFIGS;
    hdr.snaplen = PCAP_SNAPLEN;
    hdr.linktype = PCAP_LINKTYPE;

    ret = fwrite( (void *)&hdr, sizeof(struct pcap_file_header), 1, output );
    if (ret < 1)
    {
        fprintf(stderr, "Error: Unable to write pcap file header\n");
        return FAILURE;
    }
    return SUCCESS;
}

static int isEvent(const u2record *record)
{
    return record->type == UNIFIED2_IDS_EVENT
        || record->type == UNIFIED2_IDS_EVENT_IPV6
        || record->type == UNIFIED2_IDS_EVENT_VLAN
        || record->type == UNIFIED2_IDS_EVENT_IPV6_VLAN;
}

/* Obtains the extended version of unified2 record, that can be used to 
filtering */
static const u2event *ExtendedRecordOf(const u2record *record)
{
    if(isEvent(record))
    {
        return (u2event *)record->data;
    }
    else
    {
        return NULL;
    }
}

static int SmartInetpton(int *family,const char *str,void *dst){
    const int pfamily = strchr(str,':') ? AF_INET6 : AF_INET;
    const int rc = inet_pton(pfamily,str,dst);
    if(rc <= 0)
        return rc;

    if(family)
        *family = pfamily;

    return pfamily;
}

/* Check if an event pass the filters. If no filter is set (value==0), it pass 
the filter */
static int EventPassFilters(const struct filters *defined_filters,
    const u2record *record)
{
    int filters_passed = 1; // Assume true as default

    const u2event *extended_record = ExtendedRecordOf(record);
    if(extended_record)
    {
        if(defined_filters->lower_timestamp > 0 
            && ntohl(extended_record->event_second) < defined_filters->lower_timestamp)
        {
            filters_passed = 0;
        }
        if(defined_filters->upper_timestamp > 0 
            && ntohl(extended_record->event_second) > defined_filters->upper_timestamp)
        {
            filters_passed = 0;
        }
        if(defined_filters->signature_id != 0 
            && ntohl(extended_record->signature_id) != defined_filters->signature_id)
        {
            filters_passed = 0;
        }
        if(defined_filters->generator_id != 0
            && ntohl(extended_record->generator_id) != defined_filters->generator_id)
        {
            filters_passed = 0;
        }

        if(filters_passed)
        {
            filters_passed = EventPassIPFilters(defined_filters,record);
        }
    }

    return filters_passed;
}

static int EventPassIPFilters(const struct filters *defined_filters,const u2record *record)
{
    int filters_passed = 1;

    if(filters_passed && defined_filters->src_ip_str)
    {
        if(defined_filters->src_ip_family != FamilyOfRecord(record))
        {
            filters_passed = 0;
        }
        else
        {
            filters_passed = IPPassSourceIpFilter(defined_filters,record);
        }
    }
    if(filters_passed && defined_filters->dst_ip_str)
    {
        if(defined_filters->dst_ip_family != FamilyOfRecord(record))
        {
            filters_passed = 0;
        }
        else
        {
            filters_passed = IPPassDestinationIPFilter(defined_filters,record);
        }
    }

    return filters_passed;
}

static int IPPassSourceIpFilter(const struct filters *defined_filters,const u2record *record)
{
    int filters_passed = 1;

    if(filters_passed && FamilyOfRecord(record) == AF_INET)
    {
        const u2ipv4event *ipv4Event = IPv4EventOf(record);
        if(ipv4Event)
        {
            filters_passed = IsEqualIPv4((struct in_addr *)defined_filters->src_ip,ipv4Event->ip_source);
        }
        else
        {
            filters_passed = 0;
        }
    }
    
    if(filters_passed && FamilyOfRecord(record) == AF_INET6)
    {
        const u2ipv6event *ipv6Event = IPv6EventOf(record);
        if(ipv6Event)
        {
            filters_passed = IsEqualIPv6((struct in6_addr *)defined_filters->src_ip,&ipv6Event->ip_source);
        }
        else
        {
            filters_passed = 0;
        }
    }

    return filters_passed;
}

static int IPPassDestinationIPFilter(const struct filters *defined_filters,const u2record *record){
        int filters_passed = 1;

    if(filters_passed && FamilyOfRecord(record) == AF_INET)
    {
        const u2ipv4event *ipv4Event = IPv4EventOf(record);
        if(ipv4Event)
        {
            filters_passed = IsEqualIPv4((struct in_addr *)defined_filters->dst_ip,ipv4Event->ip_destination);
        }
        else
        {
            filters_passed = 0;
        }
    }
    
    if(filters_passed && FamilyOfRecord(record) == AF_INET6)
    {
        const u2ipv6event *ipv6Event = IPv6EventOf(record);
        if(ipv6Event)
        {
            filters_passed = IsEqualIPv6((struct in6_addr *)defined_filters->dst_ip,&ipv6Event->ip_destination);
        }
        else
        {
            filters_passed = 0;
        }
    }

    return filters_passed;
}

/* return the ip family related to the record */
static int FamilyOfRecord(const u2record *record)
{
    if(record->type == UNIFIED2_IDS_EVENT_IPV6 || record->type == UNIFIED2_IDS_EVENT_IPV6_VLAN)
    {
        return AF_INET6;
    }
    else if(record->type == UNIFIED2_IDS_EVENT || record->type == UNIFIED2_IDS_EVENT_VLAN)
    {
        return AF_INET;
    }
    else
    {
        return 0;
    }
}

static const u2ipv4event *IPv4EventOf(const u2record *record){
    return FamilyOfRecord(record) == AF_INET ? (u2ipv4event *)record->data : NULL;
}

static const u2ipv6event *IPv6EventOf(const u2record *record){
    return FamilyOfRecord(record) == AF_INET6 ? (u2ipv6event *)record->data : NULL;
}

static int IsEqualIPv4(const struct in_addr *a,const uint32_t b){
    return !memcmp(&a->s_addr,&b,sizeof(b));
}

static int IsEqualIPv6(const struct in6_addr *a,const struct in6_addr *b){
    return !memcmp(a->s6_addr,b->s6_addr,sizeof(a->s6_addr));
}

/* Convert a unified2 packet record to pcap format, then dump */
static int PcapConversion(const u2record *rec, FILE *output)
{
    Serial_Unified2Packet packet;
    struct pcap_pkthdr pcap_hdr;
    uint32_t *field;
    uint8_t *pcap_data;
    static int packet_found = 0;

    /* Ignore IDS Events. We are only interested in Packets. */
    if (rec->type != UNIFIED2_PACKET)
    {
        return SUCCESS;
    }

    /* Initialize the pcap file if this is the first packet */
    if (!packet_found)
    {
        if (PcapInitOutput(output) == FAILURE)
        {
            return FAILURE;
        }
        packet_found = 1;
    }

    /* Fill out the Serial_Unified2Packet */
    memcpy(&packet, rec->data, sizeof(Serial_Unified2Packet));

    /* Unified 2 records are always stored in network order.
     * Convert all fields except packet data to host order */
    field = (uint32_t *)&packet;
    while(field < (uint32_t *)packet.packet_data)
    {
        *field = ntohl(*field);
        field++;
    }

    /* Create a pcap packet header */
    pcap_hdr.ts.tv_sec = packet.packet_second;
    pcap_hdr.ts.tv_usec = packet.packet_microsecond;
    pcap_hdr.caplen = packet.packet_length;
    pcap_hdr.len = packet.packet_length;

    /* Write to the pcap file */
    pcap_data = rec->data + sizeof(Serial_Unified2Packet) - 4;
    pcap_dump( (u_char *)output, &pcap_hdr, (u_char *)pcap_data );

    return SUCCESS;
}

/* Retrieve a single unified2 record from input file */
static int GetRecord(FILE *input, u2record *rec)
{
    uint32_t items_read;
    static uint32_t buffer_size = MAX_U2RECORD_DATA_LENGTH;
    uint8_t *tmp;

    if (!input || !rec)
        return FAILURE;

    items_read = fread(rec, sizeof(uint32_t), 2, input);
    if (items_read != 2)
    {
        if ( !feof(input) ) /* Not really an error if at EOF */
        {
            fprintf(stderr, "Error: incomplete record.\n");
        }
        return FAILURE;
    }
    /* Type and Length are stored in network order */
    rec->type = ntohl(rec->type);
    rec->length = ntohl(rec->length);

    /* Read in the data portion of the record */
    if (rec->length > buffer_size)
    {
        tmp = malloc(rec->length * sizeof(uint8_t));
        if (tmp == NULL)
        {
            fprintf(stderr, "Error: memory allocation failed.\n");
            return FAILURE;
        }
        else
        {
            if (rec->data != NULL)
            {
                free(rec->data);
            }
            rec->data = tmp;
            buffer_size = rec->length;
        }
    }
    items_read = fread(rec->data, sizeof(uint8_t), rec->length, input);
    if (items_read != rec->length)
    {
        fprintf(stderr, "Error: incomplete record. %d of %u bytes read.\n",
                items_read, rec->length);
        return FAILURE;
    }

    return SUCCESS;
}

int main (int argc, char *argv[])
{
    char *input_filename = NULL;
    char *output_filename = NULL;
    char *output_type = NULL;

    FILE *input_file = NULL;
    FILE *output_file = NULL;

    int c, i, errnum;
    opterr = 0;

    struct filters defined_filters = DEFAULT_FILTERS_INITIALIZER;

    /* Use Getopt to parse options */
    while ((c = getopt (argc, argv, "g:s:l:o:d:u:t:")) != -1)
    {
        switch (c)
        {
            case 't':
                output_type = optarg;
                break;
            case '?':
                if (optopt == 't')
                    fprintf(stderr,
                            "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf(stderr, "Unknown option -%c.\n", optopt);
                return FAILURE;
            case 'g':
                defined_filters.generator_id = atol(optarg);
                break;
            case 's':
                defined_filters.signature_id = atol(optarg);
                break;
            case 'u':
                defined_filters.upper_timestamp = atol(optarg);
                break;
            case 'l':
                defined_filters.lower_timestamp = atol(optarg);
                break;
            case 'o':
                defined_filters.src_ip_str = optarg;
                break;
            case 'd':
                defined_filters.dst_ip_str = optarg;
                break;
            default:
                abort();
        }
    }

    /* At this point, there should be two filenames remaining. */
    if (optind != (argc - 2))
    {
        fprintf(stderr, "Usage: u2boat [-t type] <infile> <outfile>\n");
        fprintf(stderr, "Filter options:\n");
        fprintf(stderr, "\t-o : origin (source) ip\n");
        fprintf(stderr, "\t-d : destination ip\n");
        fprintf(stderr, "\t-s : sid\n");
        fprintf(stderr, "\t-g : gid\n");
        fprintf(stderr, "\t-l : lower timestamp\n");
        fprintf(stderr, "\t-u : upper timestamp\n");
        return FAILURE;
    }

    input_filename = argv[optind];
    output_filename = argv[optind+1];

    /* Check inputs */
    if (input_filename == NULL)
    {
        fprintf(stderr, "Error: Input filename must be specified.\n");
        return FAILURE;
    }
    if (output_type == NULL)
    {
        fprintf(stdout, "Defaulting to pcap output.\n");
        output_type = "pcap";
    }
    else
    {
        for (i = 0; i < (int)strlen(output_type); i++)
            output_type[i] = tolower(output_type[i]);
    }
    if (!strcmp(output_type, "pcap") && !strcmp(output_type,"text"))
    {
        fprintf(stderr, "Invalid output type. Valid types are: pcap, stdout\n");
        return FAILURE;
    }
    if (output_filename == NULL)
    {
        fprintf(stderr, "Error: Output filename must be specified.\n");
        return FAILURE;
    }

    /* Open the files */
    if ((input_file = fopen(input_filename, "r")) == NULL)
    {
        fprintf(stderr, "Unable to open file: %s\n", input_filename);
        return FAILURE;
    }
    if ((output_file = fopen(output_filename, "w")) == NULL)
    {
        fprintf(stderr, "Unable to open/create file: %s\n", output_filename);
        return FAILURE;
    }

    /* Convert ip to numeric (and faster) versions */
    if (defined_filters.src_ip_str != NULL)
    {
        const int rc = SmartInetpton( &defined_filters.src_ip_family,
            defined_filters.src_ip_str,defined_filters.src_ip);
        if(rc <= 0)
        {
            if(rc == 0)
            {
                fprintf(stderr,"Source ip filter not in a presentation format.\n");
            }
            else
            {
                perror("Source ip filter conversion");
            }
            return FAILURE;
        }
    }
    if (defined_filters.dst_ip_str != NULL)
    {
        const int rc = SmartInetpton( &defined_filters.dst_ip_family,
            defined_filters.dst_ip_str,defined_filters.dst_ip);
        if(rc <= 0)
        {
            if(rc == 0)
            {
                fprintf(stderr,"Destination ip filter not in a presentation format.\n");
            }
            else
            {
                perror("Destination ip filter conversion");
            }
            return FAILURE;
        }
    }

    ConvertLog(input_file, output_file, output_type, &defined_filters);

    if (fclose(input_file) != 0)
    {
        errnum = errno;
        fprintf(stderr, "Error closing input: %s\n", strerror(errnum));
    }
    if (fclose(output_file) != 0)
    {
        errnum = errno;
        fprintf(stderr, "Error closing output: %s\n", strerror(errnum));
    }

    return 0;
}
