/* $Id */

/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
 * Definitions, structs, function prototype(s) for
 *		the file preprocessor.
 * Author: Hui Cao
 */

#ifndef SPP_FILE_INSPECT_CONFIG_H
#define SPP_FILE_INSPECT_CONFIG_H

#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include "snort_bounds.h"
#include "file_sha.h"
#include "sfxhash.h"

#if HAVE_S3FILE
//#include "src/sfutil/sfxhash.h"
#include <libs3.h>
#endif

#define FILE_CAPTURE_QUEUE_SIZE_DEFAULT       3000 /*files*/
#define FILE_CAPTURE_DISK_SIZE_DEFAULT        300  /*MB*/
#define SHA256_CACHE_TABLE_ROWS_DEFAULT     65536
#define SHA256_CACHE_TABLE_ROWS_MAX        262144
#define SHA256_CACHE_TABLE_MAXMEM_M_MAX (16*1024) /* MB */

typedef struct _FileSigInfo
{
    File_Verdict verdict;
} FileSigInfo;

/*
 * Global File preprocessor configuration.
 *
 */
typedef struct _fileInspectConfig
{
    bool file_type_enabled;
    bool file_signature_enabled;
    bool file_capture_enabled;
#ifdef HAVE_EXTRADATA_FILE
    bool file_extradata_enabled;
#endif
    uint32_t file_capture_queue_size;
    char *capture_dir;
    int ref_count;
    char *hostname;
    int portno;
    ShaHash *sig_table;
    SFXHASH *sha256_cache;
/* #ifdef CONTROL_SOCKET */
    /* Needed to reload via control socket */
    /* Can't use conditional compilation since file_agent.c does not compile with
       this flag
    */
    char *blacklist_path;
    char *greylist_path;
    char *seenlist_path;
/* #endif */
    bool dont_save_blacklist;
#if defined(DEBUG_MSGS) || defined (REG_TEST)
    int verdict_delay; /* used for debug, mimic delay to get verdicts */
#endif
#if HAVE_S3FILE
    struct s3_info {
        char *bucket;
        char *cluster;
        char *access_key;
        char *secret_key;
    } s3;
#endif
    uint32_t capture_disk_size;  /* In megabytes*/
#ifdef HAVE_EXTRADATA_FILE
    uint32_t xtra_file_sha256_id;
    uint32_t xtra_file_size_id;
    uint32_t xtra_file_name_id;
    uint32_t xtra_file_hostname_id;
    uint32_t xtra_file_mailfrom_id;
    uint32_t xtra_file_rcptto_id;
    uint32_t xtra_file_headers_id;
#endif

    uint32_t sha256_cache_table_rows;
    uint32_t sha256_cache_table_maxmem_m;
} FileInspectConf;


void file_config_parse(FileInspectConf*, const u_char* );

int file_config_signature(char *filename, FileSigInfo *sig_info,
        FileInspectConf *config, int allow_fatal);

int file_config_setup_seenlist(char *seenList,FileInspectConf *config,
    int allow_fatal);

/* Return values
 *  0: equal
 *  -1: no the same
 */
int file_config_compare(FileInspectConf*  , FileInspectConf* );

/* Release resource of file configruation*/
void file_config_free(FileInspectConf*);

#endif /* SPP_FILE_INSPECT_CONFIG_H */
