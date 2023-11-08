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

#include "sf_types.h"
#include "file_inspect_config.h"
#include "file_agent.h"
#include "spp_file.h"
#include <errno.h>

#ifdef HAVE_S3FILE
//#include "src/sfutil/sfxhash.h"
#include <libs3.h>
#endif

/*
 * File preprocessor configurations
 * Author: Hui Cao
 *
 */

#define FILE_CONF_SECTION_SEPERATORS     ",;"
#define FILE_CONF_VALUE_SEPERATORS       " "
#define FILE_SEPARATORS                  " \t\r\n"

#define FILE_INSPECT_TYPE                "type_id"
#define FILE_INSPECT_SIG                 "signature"
#define FILE_INSPECT_CAPTURE_MEMORY      "capture_memory"
#define FILE_INSPECT_CAPTURE_DISK        "capture_disk"
#define FILE_INSPECT_CAPTURE_NETWORK     "capture_network"
#define FILE_INSPECT_CAPTURE_QUEUE_SIZE  "capture_queue_size"
#define FILE_INSPECT_DONT_SAVE_BLACKLIST "dont_save_blacklist"
#define FILE_INSPECT_BLACKLIST           "blacklist"
#define FILE_INSPECT_GREYLIST            "greylist"
#define FILE_INSPECT_SEENLIST            "seenlist"
#define FILE_INSPECT_SHA_CACHE_MIN_ROWS  "sha_cache_min_rows"
#define FILE_INSPECT_SHA_CACHE_MAX_SIZE_M "sha_cache_max_size_m"

#ifdef HAVE_MIME_DROP
#define FILE_INSPECT_MAX_FILE_SIZE       "max_file_size"
#define FILE_INSPECT_ENABLE_DROP         "enable_drop_on_byte_match"
#define FILE_INSPECT_MIME_BLACKLIST      "file_capture_mime_blacklist"
#endif

#ifdef HAVE_S3FILE
#define FILE_INSPECT_S3_BUCKET           "s3_bucket"
#define FILE_INSPECT_S3_CLUSTER          "s3_cluster"
#define FILE_INSPECT_S3_ACCESS_KEY       "s3_access_key"
#define FILE_INSPECT_S3_SECRET_KEY       "s3_secret_key"
#endif

#ifdef HAVE_EXTRADATA_FILE
#define FILE_INSPECT_TRACK_EXTRADATA     "track_extradata"
#endif

#if defined(DEBUG_MSGS) || defined (REG_TEST)
#define FILE_INSPECT_VERDICT_DELAY       "verdict_delay"
#endif

#define MAX_SIG_LINE_LENGTH    8192

static FileSigInfo blackList = {FILE_VERDICT_BLOCK};
static FileSigInfo greyList = {FILE_VERDICT_LOG};
/*
 * Function: UpdatePathToFile
 *
 * Update the path to a file, if using relative path.
 * The relative path is based on config file directory.
 *
 * Arguments:
 *  full_path_filename: file name string
 *  max_size: ?
 *  char *filename: ?
 *
 * Returns:
 *  1 successful
 *  0 fail
 *
 */
static int UpdatePathToFile(char *full_path_filename, unsigned int max_size,
        char *filename)
{

    char *snort_conf_dir = *(_dpd.snort_conf_dir);

    if (!snort_conf_dir || !(*snort_conf_dir) || !filename)
    {
        DynamicPreprocessorFatalMessage(" %s(%d) => can't create path.\n",
                *(_dpd.config_file), *(_dpd.config_line));
        return 0;
    }
    /*filename is too long*/
    if ( max_size < strlen(filename) )
    {
        DynamicPreprocessorFatalMessage(" %s(%d) => the file name length %u "
                "is longer than allowed %u.\n",
                *(_dpd.config_file), *(_dpd.config_line),
                strlen(filename), max_size);
        return 0;
    }

    /* If an absolute path is specified, then use that.*/
#ifndef WIN32
    if(filename[0] == '/')
    {
        snprintf(full_path_filename, max_size, "%s", filename);
    }
    else
    {
        /* Set up the file name directory.*/
        if (snort_conf_dir[strlen(snort_conf_dir) - 1] == '/')
        {
            snprintf(full_path_filename,max_size,
                    "%s%s", snort_conf_dir, filename);
        }
        else
        {
            snprintf(full_path_filename, max_size,
                    "%s/%s", snort_conf_dir, filename);
        }
    }
#else
    if(strlen(filename)>3 && filename[1]==':' && filename[2]=='\\')
    {
        snprintf(full_path_filename, max_size, "%s", filename);
    }
    else
    {
        /* Set up the file name directory */
        if (snort_conf_dir[strlen(snort_conf_dir) - 1] == '\\' ||
                snort_conf_dir[strlen(snort_conf_dir) - 1] == '/' )
        {
            snprintf(full_path_filename,max_size,
                    "%s%s", snort_conf_dir, filename);
        }
        else
        {
            snprintf(full_path_filename, max_size,
                    "%s\\%s", snort_conf_dir, filename);
        }
    }
#endif
    return 1;
}
/*
 * Load file list signature file
 *
 * Arguments:
 *  filename: file name string
 *  FileSigInfo *:  The file signature information.
 *  FileInspectConf *:  The configuration to be update.
 *
 * Returns:
 *  None
 */
int file_config_signature(char *filename, FileSigInfo *sig_info,
        FileInspectConf *config, int allow_fatal)
{
    FILE *fp = NULL;
    char linebuf[MAX_SIG_LINE_LENGTH];
    char full_path_filename[PATH_MAX+1];
    int line_number = 0;

    void (*fatal_err_fn)(const char *,...) = allow_fatal ? FILE_FATAL_ERROR : _dpd.errMsg;

    /* check table first, create one if not exist*/

    if (config->sig_table == NULL)
    {
        config->sig_table = sha_table_new(SHA256_HASH_SIZE);
    }
    if (config->sig_table == NULL)
    {
        fatal_err_fn("%s(%d) Could not create file signature hash.\n",
                *(_dpd.config_file), *(_dpd.config_line));
        return -1;
    }

    /* parse the file line by line, each signature one entry*/
    _dpd.logMsg("File inspect: processing file %s\n", filename);

    UpdatePathToFile(full_path_filename, PATH_MAX, filename);

    if((fp = fopen(full_path_filename, "r")) == NULL)
    {
        char errBuf[STD_BUF];
#ifdef WIN32
        snprintf(errBuf, STD_BUF, "%s", strerror(errno));
#else
        strerror_r(errno, errBuf, STD_BUF);
#endif
        errBuf[STD_BUF-1] = '\0';
        fatal_err_fn("%s(%d) => Unable to open signature file %s, "
                "Error: %s\n",
                *(_dpd.config_file), *(_dpd.config_line), filename, errBuf);
        return -1;
    }

    while( fgets(linebuf, MAX_SIG_LINE_LENGTH, fp) )
    {
        char *cmt = NULL;
        char *sha256;
        FileSigInfo *old_info;

        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "File signatures: %s\n",linebuf ););

        line_number++;

        /* Remove comments */
        if( (cmt = strchr(linebuf, '#')) )
            *cmt = '\0';

        /* Remove newline as well, prevent double newline in logging.*/
        if( (cmt = strchr(linebuf, '\n')) )
            *cmt = '\0';

        if (!strlen(linebuf))
            continue;

        sha256 = malloc(SHA256_HASH_SIZE);

        if (!sha256)
        {
            fatal_err_fn("%s(%d) => No memory for file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
            return -1;
        }

        if (str_to_sha(linebuf, sha256, strlen(linebuf)) < 0)
        {
            fatal_err_fn("%s(%d) => signature format at file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
            return -1;
        }

        old_info = (FileSigInfo *)sha_table_find(config->sig_table, sha256);

        if (old_info)
        {
            free(sha256);
            _dpd.errMsg("%s(%d) => signature redefined at file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
        }
        else
        {
            sha_table_add(config->sig_table, sha256, sig_info);
        }
    }
    return 0;
}

/*
 * Load seen file list signature file
 *
 * Arguments:
 *  filename: file name string
 *  hashtable: Hash table to store results
 *
 * Returns:
 *  None
 *
 * TODO:
 *  Join with file_config_signature.
 */
static void file_config_signature_sfxhash(char *filename, SFXHASH *hashtable)
{
    FILE *fp = NULL;
    char linebuf[MAX_SIG_LINE_LENGTH];
    char full_path_filename[PATH_MAX+1];
    int line_number = 0;
    int no_memory = 0;

    /* parse the file line by line, each signature one entry*/
    _dpd.logMsg("File inspect: processing file %s\n", filename);

    UpdatePathToFile(full_path_filename, PATH_MAX, filename);

    if((fp = fopen(full_path_filename, "r")) == NULL)
    {
        char errBuf[STD_BUF];
#ifdef WIN32
        snprintf(errBuf, STD_BUF, "%s", strerror(errno));
#else
        strerror_r(errno, errBuf, STD_BUF);
#endif
        errBuf[STD_BUF-1] = '\0';
        FILE_FATAL_ERROR("%s(%d) => Unable to open signature file %s, "
                "Error: %s\n",
                *(_dpd.config_file), *(_dpd.config_line), filename, errBuf);
        return;
    }

    while( fgets(linebuf, MAX_SIG_LINE_LENGTH, fp) )
    {
        char *cmt = NULL;
        char *sha256;

        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "File signatures: %s\n",linebuf ););

        if(no_memory)
        {
            break;
        }

        line_number++;

        /* Remove comments */
        if( (cmt = strchr(linebuf, '#')) )
            *cmt = '\0';

        /* Remove newline as well, prevent double newline in logging.*/
        if( (cmt = strchr(linebuf, '\n')) )
            *cmt = '\0';

        if (!strlen(linebuf))
            continue;

        sha256 = malloc(SHA256_HASH_SIZE);

        if (!sha256)
        {
            FILE_FATAL_ERROR("%s(%d) => No memory for file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
        }

        if (str_to_sha(linebuf, sha256, strlen(linebuf)) < 0)
        {
            FILE_FATAL_ERROR("%s(%d) => signature format at file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
        }

        const int rc = sfxhash_add(hashtable, sha256, NULL);
        switch(rc) {
        case SFXHASH_NOMEM:
            _dpd.errMsg("%s(%d) => No memory to save signature at file %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);

            no_memory = true;

            break;

        case SFXHASH_OK:
            break;

        case SFXHASH_INTABLE:
            _dpd.errMsg("%s(%d) => signature redefined at file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    filename, line_number, linebuf);
            sfxhash_remove(hashtable, sha256);
            break;

        default:
            _dpd.errMsg("%s(%d) => sha_table_add return unknown error %d at"
                    " file: %s (%d), \n"
                    "signature: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line),
                    rc,
                    filename, line_number, linebuf);
            break;
        };
    }
}

/* Display the configuration for the File preprocessor.
 *
 * PARAMETERS:
 *
 *   FileInspectConf *config: pointer to configuration
 *
 * RETURNS: Nothing.
 */
static void DisplayFileConfig(FileInspectConf *config)
{

    if (config == NULL)
        return;

    _dpd.logMsg("File config: \n");
    _dpd.logMsg("    file type: %s\n",
            config->file_type_enabled ? "ENABLED":"DISABLED (Default)");
    _dpd.logMsg("    file signature: %s\n",
            config->file_signature_enabled ? "ENABLED":"DISABLED (Default)");
    _dpd.logMsg("    file capture: %s\n",
            config->file_capture_enabled ? "ENABLED":"DISABLED (Default)");
    if (config->file_capture_enabled)
    {
        _dpd.logMsg("    file capture directory: %s\n",
                config->capture_dir ?
                        config->capture_dir:"not saved, memory only");
        _dpd.logMsg("    file capture disk size: %u %s\n",
                config->capture_disk_size,
                config->capture_disk_size == FILE_CAPTURE_DISK_SIZE_DEFAULT?
                        "(Default) megabytes":"megabytes");
    }

    _dpd.logMsg("    file sent to host: %s, port number: %d\n",
            config->hostname ? config->hostname:"DISABLED (Default)",
                    config->portno);
#ifdef HAVE_EXTRADATA_FILE
    _dpd.logMsg("    file extradata: %s\n",
            config->file_extradata_enabled ? "ENABLED":"DISABLED (Default)");
#endif
#ifdef HAVE_S3FILE
    _dpd.logMsg("    file -> S3: ENABLED\n");
#endif
#ifdef HAVE_MIME_DROP
    _dpd.logMsg("    file MIME drop and max size drop: ENABLED\n");
#endif
}

/* Creates a new hash table, memory limited, to store SHA signatures
 *
 * PARAMETERS:
 *   rows: Hashtable rows
 *   mem_m: Memory, in MB, that table can allocate
 *
 * RETURNS: New hashtable
 */
static SFXHASH * hash_table_s3_cache_new(const int rows,const size_t mem_m)
{
    SFXHASH *hts3cache = NULL;
    hts3cache = sfxhash_new(/*number of rows in hash table*/ rows,
                            /*key size in bytes, same for all keys*/ SHA256_HASH_SIZE,
                            /*datasize in bytes, zero indicates user manages data*/ 0,
                            /*maximum memory to use in bytes*/ mem_m*1024*1024,
                            /*Automatic Node Recovery boolean flag*/ 1,
                            /*users Automatic Node Recovery memory release function*/ NULL,
                            /* Auto free function */ NULL,
                            /* Recycle nodes */ 1
                            );
    if (hts3cache == NULL)
    {
        _dpd.logMsg("File inspect: Failed to create s3 cache hash table \n");
    }
    return hts3cache;
}

int file_config_setup_seenlist(char *seenList,FileInspectConf *config,
    int allow_fatal)
{
    void (*fatal_err_fn)(const char *,...) = allow_fatal ? FILE_FATAL_ERROR : _dpd.errMsg;

    if(config->sha256_cache_table_maxmem_m > 0)
    {
        config->sha256_cache = hash_table_s3_cache_new(
            config->sha256_cache_table_rows,
            config->sha256_cache_table_maxmem_m);

        if (NULL == config->sha256_cache)
        {
            fatal_err_fn("%s(%d) => Couldn't create sha256 cache. Please "
                "decrease rows or increase maxmem?)\n",
                *(_dpd.config_file), *(_dpd.config_line));
            return -1;
        }

        if(seenList)
        {
            file_config_signature_sfxhash(seenList, config->sha256_cache);
        }
    }

    return 0;
}

/* Parses and processes the configuration arguments
 * supplied in the File preprocessor rule.
 *
 * PARAMETERS:
 *   FileInspectConf *config: pointer to configuration
 *   argp:        Pointer to string containing the config arguments.
 *
 * RETURNS:     Nothing.
 */
void file_config_parse(FileInspectConf *config, const u_char* argp)
{
    char* cur_sectionp = NULL;
    char* next_sectionp = NULL;
    char* argcpyp = NULL;
    char* seenList = NULL;
    if (config == NULL)
        return;

    config->capture_disk_size = FILE_CAPTURE_DISK_SIZE_DEFAULT;
    config->sha256_cache_table_rows = SHA256_CACHE_TABLE_ROWS_DEFAULT;

    /* Sanity check(s) */
    if (!argp)
    {
        DisplayFileConfig(config);
        return;
    }

    argcpyp = strdup((char*) argp);

    if (!argcpyp)
    {
        FILE_FATAL_ERROR("Could not allocate memory to "
                "parse File options.\n");
        return;
    }

    cur_sectionp = strtok_r(argcpyp, FILE_CONF_SECTION_SEPERATORS,
            &next_sectionp);
    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Arguments token: %s\n",
            cur_sectionp ););

    while (cur_sectionp)
    {

        char* cur_config;
        unsigned long value;

        char* cur_tokenp =  strtok(cur_sectionp, FILE_CONF_VALUE_SEPERATORS);

        if (!cur_tokenp)
        {
            cur_sectionp = strtok_r(next_sectionp, FILE_CONF_SECTION_SEPERATORS,
                    &next_sectionp);
            continue;
        }
        cur_config = cur_tokenp;

        if (!strcasecmp(cur_tokenp, FILE_INSPECT_TYPE))
        {
            config->file_type_enabled = true;
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_SIG))
        {
            config->file_signature_enabled = true;
        }
#ifdef HAVE_EXTRADATA_FILE
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_TRACK_EXTRADATA))
        {
            config->file_extradata_enabled = true;
        }
#endif
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_BLACKLIST))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify list file!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

#ifdef CONTROL_SOCKET
            config->blacklist_path = strdup(cur_tokenp);
#endif

            file_config_signature(cur_tokenp, &blackList, config, 
                1 /* allow_fatal*/ );
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_SEENLIST))
        {
            /* Seenlist could be huge, so it's better to save it in memory
             * controlled cache
             */
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify list file!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

            seenList = strdup(cur_tokenp);
            if(!seenList)
            {
                FILE_FATAL_ERROR("%s(%d) => Couldn't strdup!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

#ifdef CONTROL_SOCKET
            config->seenlist_path = strdup(seenList);
#endif

        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_DONT_SAVE_BLACKLIST))
        {
            config->dont_save_blacklist = true;
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_GREYLIST))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify list file!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

#ifdef CONTROL_SOCKET
            config->greylist_path = strdup(cur_tokenp);
#endif

            file_config_signature(cur_tokenp, &greyList, config,
                1 /* allow_fatal */ );
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_CAPTURE_MEMORY))
        {
            config->file_capture_enabled = true;
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_CAPTURE_DISK))
        {

            config->file_capture_enabled = true;

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify directory!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

            if (strlen(cur_tokenp) > FILE_NAME_LEN)
            {
                FILE_FATAL_ERROR("%s(%d) => Directory string is too long!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
                return;
            }

            if (!(config->capture_dir = strdup(cur_tokenp)))
            {
                FILE_FATAL_ERROR("Could not allocate memory to parse "
                        "file options.\n");
                return;
            }

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if (cur_tokenp)
            {
                _dpd.checkValueInRange(cur_tokenp,
                        FILE_INSPECT_CAPTURE_DISK,
                        0, 65536, &value);

                config->capture_disk_size = (int)value;
            }
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_CAPTURE_NETWORK))
        {
            config->file_capture_enabled = true;

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify hostname!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

            if (!(config->hostname = strdup(cur_tokenp)))
            {
                FILE_FATAL_ERROR("Could not allocate memory to parse "
                        "file options.\n");
                return;
            }

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_CAPTURE_NETWORK,
                    0, 65536, &value);

            config->portno = (int)value;
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_CAPTURE_QUEUE_SIZE))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_CAPTURE_QUEUE_SIZE,
                    0, UINT32_MAX, &value);
            config->file_capture_queue_size = (uint32_t) value;
        }
#ifdef HAVE_MIME_DROP
        else if(!strcasecmp(cur_tokenp, FILE_INSPECT_MAX_FILE_SIZE))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_MAX_FILE_SIZE,
                    0, UINT32_MAX, &value);
            _dpd.logMsg("File inspect: File-Max-Size set\n");
            config->mime.file_capture_max_file_size = (uint32_t) value;

        }
        else if(!strcasecmp(cur_tokenp, FILE_INSPECT_ENABLE_DROP))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            _dpd.logMsg("File inspect: File-Drop enabled\n");
            config->mime.file_capture_enable_drop = true;
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_MIME_BLACKLIST))
        {
            _dpd.logMsg("File inspect: loading mime blacklist into mem\n");
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify mime blacklist array!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            config->mime.file_capture_mime_blacklist = strdup(cur_tokenp);
            _dpd.logMsg("File inspect: loaded mime blacklist into mem %s\n", config->mime.file_capture_mime_blacklist);
        }
#endif
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_SHA_CACHE_MIN_ROWS))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify cache min rows!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            else
            {
                _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_SHA_CACHE_MIN_ROWS,
                        1, SHA256_CACHE_TABLE_ROWS_MAX, &value);
                config->sha256_cache_table_rows = (uint32_t) value;
            }
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_SHA_CACHE_MAX_SIZE_M))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify cache max memory size!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            else
            {
                _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_SHA_CACHE_MIN_ROWS,
                        1, SHA256_CACHE_TABLE_MAXMEM_M_MAX, &value);
                config->sha256_cache_table_maxmem_m = (uint32_t) value;
            }
        }
#if defined(DEBUG_MSGS) || defined (REG_TEST)
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_VERDICT_DELAY))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            _dpd.checkValueInRange(cur_tokenp, FILE_INSPECT_VERDICT_DELAY,
                    0, UINT32_MAX, &value);
            config->verdict_delay = (uint32_t) value;
        }
#endif
#if HAVE_S3FILE
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_S3_BUCKET) )
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify s3 bucket!\n");
            }
            config->s3.bucket = strdup(cur_tokenp);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_S3_CLUSTER) )
        {
            config->file_capture_enabled = true;

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify s3 cluster!\n");
            }
            config->s3.cluster = strdup(cur_tokenp);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_S3_ACCESS_KEY) )
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify s3 access_key!\n");
            }
            config->s3.access_key = strdup(cur_tokenp);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_S3_SECRET_KEY) )
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp )
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify s3 secret_key!\n");
            }
            config->s3.secret_key = strdup(cur_tokenp);
        }
#endif
        else
        {
            FILE_FATAL_ERROR(" %s(%d) => Invalid argument: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line), cur_tokenp);
            return;
        }
        /*Check whether too many parameters*/
        if (NULL != strtok(NULL, FILE_CONF_VALUE_SEPERATORS))
        {
            FILE_FATAL_ERROR("%s(%d) => Too many arguments: %s\n",
                    *(_dpd.config_file), *(_dpd.config_line), cur_config);
        }

        cur_sectionp = strtok_r(next_sectionp, FILE_CONF_SECTION_SEPERATORS,
                &next_sectionp);
        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Arguments token: %s\n",
                cur_sectionp ););
    }

    file_config_setup_seenlist(seenList,config, 1 /* allow_fatal */);

    if(seenList)
    {
        free(seenList);
    }

    DisplayFileConfig(config);
    free(argcpyp);
}

/*Return values
 *  0: equal
 *  -1: no the same
 */

static inline int _cmp_config_str(char *str1, char *str2)
{
    if (!str1 && !str2)
        return 0;

    if (!str1 || !str2)
        return -1;

    return (strcmp(str1, str2));

}
/*Return values
 *  0: equal
 *  -1: no the same
 */
int file_config_compare(FileInspectConf* conf1 , FileInspectConf* conf2)
{
    if (_cmp_config_str(conf1->capture_dir, conf2->capture_dir)
            ||(conf1->file_capture_enabled != conf2->file_capture_enabled)
            ||(conf1->file_capture_queue_size != conf2->file_capture_queue_size)
            ||(conf1->capture_disk_size != conf2->capture_disk_size)
            ||(conf1->file_signature_enabled != conf2->file_signature_enabled)
            ||(conf1->file_type_enabled != conf2->file_type_enabled)
            || _cmp_config_str(conf1->hostname, conf2->hostname)
            ||(conf1->portno != conf2->portno))
    {
        return -1;
    }

    return 0;
}

void file_config_free(FileInspectConf* config)
{

    if (config->capture_dir)
    {
        free(config->capture_dir);
        config->capture_dir = NULL;
    }

    if (config->hostname)
    {
        free(config->hostname);
        config->hostname = NULL;
    }

    if (config->sig_table != NULL)
    {
        sha_table_delete(config->sig_table);
        config->sig_table  = NULL;
    }

    if(config->sha256_cache)
    {
        sfxhash_delete(config->sha256_cache);
        config->sha256_cache = NULL;
    }
#ifdef HAVE_MIME_DROP
    if(config->mime.file_capture_mime_blacklist){
        free(config->mime.file_capture_mime_blacklist);
        config->mime.file_capture_mime_blacklist = NULL;
    }
#endif

#if HAVE_S3FILE
    if(config->s3.bucket)
    {
        free(config->s3.bucket);
        config->s3.bucket = NULL;
    }

    if(config->s3.cluster)
    {
        free(config->s3.cluster);
        config->s3.cluster = NULL;
    }

    if(config->s3.access_key)
    {
        free(config->s3.access_key);
        config->s3.access_key = NULL;
    }

    if(config->s3.secret_key)
    {
        free(config->s3.secret_key);
        config->s3.secret_key = NULL;
    }
#endif

#ifdef CONTROL_SOCKET
    if (config->blacklist_path)
    {
        free(config->blacklist_path);
        config->blacklist_path = NULL;
    }
    if (config->greylist_path)
    {
        free(config->greylist_path);
        config->greylist_path = NULL;
    }
    if (config->seenlist_path)
    {
        free(config->seenlist_path);
        config->seenlist_path = NULL;
    }

#endif /* CONTROL_SOCKET */
}

