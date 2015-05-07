/* $Id */

/*
 ** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
#define FILE_INSPECT_BLACKLIST           "blacklist"
#define FILE_INSPECT_GREYLIST            "greylist"

#ifdef HAVE_S3FILE
#define FILE_INSPECT_KAFKA_BROKERS       "kafka_brokers"
#define FILE_INSPECT_KAFKA_TOPIC         "kafka_topic"
#define FILE_INSPECT_KAFKA_PARTITION     "kafka_partition"
#define FILE_INSPECT_RDKAFKA_CONFIG      "rdkafka_config"

#define FILE_INSPECT_S3_BUCKET           "s3_bucket"
#define FILE_INSPECT_S3_CLUSTER          "s3_cluster"
#define FILE_INSPECT_S3_ACCESS_KEY       "s3_access_key"
#define FILE_INSPECT_S3_SECRET_KEY       "s3_secret_key"
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
static void file_config_signature(char *filename, FileSigInfo *sig_info,
        FileInspectConf *config)
{
    FILE *fp = NULL;
    char linebuf[MAX_SIG_LINE_LENGTH];
    char full_path_filename[PATH_MAX+1];
    int line_number = 0;

    /* check table first, create one if not exist*/

    if (config->sig_table == NULL)
    {
        config->sig_table = sha_table_new(SHA256_HASH_SIZE);
    }
    if (config->sig_table == NULL)
    {
        FILE_FATAL_ERROR("%s(%d) Could not create file signature hash.\n",
                *(_dpd.config_file), *(_dpd.config_line));
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
        FILE_FATAL_ERROR("%s(%d) => Unable to open signature file %s, "
                "Error: %s\n",
                *(_dpd.config_file), *(_dpd.config_line), filename, errBuf);
        return;
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
    _dpd.logMsg("\n");
}

#ifdef HAVE_S3FILE
static int parse_rdkafka_config(const char *_config,
    rd_kafka_conf_t *conf,rd_kafka_topic_conf_t *topic_conf)
{
    char errstr[512];
    if ( NULL == _config )
        FILE_FATAL_ERROR("%s function called with NULL _config",__FUNCTION__);
    if ( NULL == topic_conf )
        FILE_FATAL_ERROR("%s function called with NULL topic_conf",__FUNCTION__);
    if ( NULL == conf )
        FILE_FATAL_ERROR("%s function called with NULL conf",__FUNCTION__);

    char *name = strdup(_config);
    if ( NULL == name )
        FILE_FATAL_ERROR("Not enough memory to strdup config");

    char *val = strchr(name, '=');
    if ( NULL == val ) {
        FILE_FATAL_ERROR("%s(%d) Expected rdkafka_conf property=value, not "
            "rdkafka_conf %s\n", *(_dpd.config_file), *(_dpd.config_line), 
            _config);
        exit(1);
    }

    *val = '\0';
    val++;

    rd_kafka_conf_res_t res = RD_KAFKA_CONF_UNKNOWN;
    /* Try "topic." prefixed properties on topic
     * conf first, and then fall through to global if
     * it didnt match a topic configuration property. */
    if (!strncmp(name, "topic.", strlen("topic.")))
        res = rd_kafka_topic_conf_set(topic_conf,
                          name+
                          strlen("topic."),
                          val,
                          errstr,
                          sizeof(errstr));

    if (res == RD_KAFKA_CONF_UNKNOWN)
        res = rd_kafka_conf_set(conf, name, val,
                    errstr, sizeof(errstr));

    if (res != RD_KAFKA_CONF_OK) {
        FILE_FATAL_ERROR("%s(%d) Error setting rdkafka conf: %s\n",
            *(_dpd.config_file), *(_dpd.config_line), errstr);
        exit(1);
    }

    free(name);

    return 0;
}

static void kafka_log_callback(const rd_kafka_t *rk, int level,
                                const char *fac, const char *buf)
{
    _dpd.logMsg("File capture kafka: %s, %s\n",fac,buf);
}

static void dr_callback(rd_kafka_t *rk, void *payload, size_t len,
                                    rd_kafka_resp_err_t err,
                                    void *opaque, void *msg_opaque)
{
    if(err)
        kafka_log_callback(rk,4 /* LOG_ERR*/,"Message delivery failed",
            rd_kafka_err2str(err));
}

static int create_rdkafka_config_if_not_exists(FileInspectConf *config) {
    if(NULL == config->kafka.conf)
        config->kafka.conf = rd_kafka_conf_new();
        rd_kafka_conf_set_dr_cb(config->kafka.conf, dr_callback);
    if(NULL == config->kafka.conf) {
        FILE_FATAL_ERROR("%s(%d) Error creating default rdkafka conf"
            "(out of memory?)\n",*(_dpd.config_file), *(_dpd.config_line));
    }



    if(NULL == config->kafka.tconf)
        config->kafka.tconf = rd_kafka_topic_conf_new();
    if(NULL == config->kafka.conf) {
        FILE_FATAL_ERROR("%s(%d) Error creating default rdkafka topic conf"
            "(out of memory?)\n",*(_dpd.config_file), *(_dpd.config_line));
    }

    return 1;
}

#endif

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


    if (config == NULL)
        return;

    config->capture_disk_size = FILE_CAPTURE_DISK_SIZE_DEFAULT;
#if HAVE_S3FILE
    config->kafka.partition = RD_KAFKA_PARTITION_UA;
#endif

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
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_BLACKLIST))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify list file!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

            file_config_signature(cur_tokenp, &blackList, config);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_GREYLIST))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if(cur_tokenp == NULL)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify list file!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }

            file_config_signature(cur_tokenp, &greyList, config);
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
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_KAFKA_BROKERS))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if (NULL == cur_tokenp)
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify kafka brokers!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            config->kafka.brokers = strdup(cur_tokenp);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_KAFKA_TOPIC))
        {
            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if (NULL == cur_tokenp)            
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify kafka topic!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            config->kafka.topic = strdup(cur_tokenp);
        }
        else if (!strcasecmp(cur_tokenp, FILE_INSPECT_RDKAFKA_CONFIG))
        {
            create_rdkafka_config_if_not_exists(config);

            cur_tokenp = strtok(NULL, FILE_CONF_VALUE_SEPERATORS);
            if( NULL == cur_tokenp ) 
            {
                FILE_FATAL_ERROR("%s(%d) => Please specify kafka configuration!\n",
                        *(_dpd.config_file), *(_dpd.config_line));
            }
            parse_rdkafka_config(cur_tokenp,config->kafka.conf,config->kafka.tconf);
        }
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

#ifdef HAVE_S3FILE
    if( config->kafka.brokers && NULL == config->kafka.topic ) {
        FILE_FATAL_ERROR("%s(%d) => Broker given but no topic given",
            *(_dpd.config_file),*(_dpd.config_line));
    }

    if( NULL == config->kafka.brokers && config->kafka.topic ) {
        FILE_FATAL_ERROR("%s(%d) => Broker given but no topic given",
            *(_dpd.config_file),*(_dpd.config_line));
    }

    if( config->kafka.brokers && config->kafka.topic ) {
        config->file_capture_enabled = true;
        char errstr[512];
        create_rdkafka_config_if_not_exists(config);

        config->kafka.rk = rd_kafka_new(RD_KAFKA_PRODUCER, 
                    config->kafka.conf,errstr, sizeof(errstr));
        if ( NULL == config->kafka.rk ) {
            FILE_FATAL_ERROR("%s(%d) => Can't create kafka handler: %s",
                *(_dpd.config_file),*(_dpd.config_line),errstr);
        }
        rd_kafka_set_logger(config->kafka.rk, kafka_log_callback);

        const int brokers_added = rd_kafka_brokers_add(config->kafka.rk, 
                                                config->kafka.brokers);
        if ( brokers_added == 0 ) {
            FILE_FATAL_ERROR("%s(%d) => No valid kafka brokers specified\n",
                *(_dpd.config_file),*(_dpd.config_line));
        }

        config->kafka.rkt = rd_kafka_topic_new(config->kafka.rk, 
                                            config->kafka.topic, 
                                            config->kafka.tconf);
        if( NULL == config->kafka.rkt ) {
            FILE_FATAL_ERROR("%s(%d) => Can't create topic %s",
                *(_dpd.config_file),*(_dpd.config_line),config->kafka.topic);
        }
    }

#endif

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

#if HAVE_S3FILE
    if (config->kafka.rkt)
    {
        rd_kafka_topic_destroy(config->kafka.rkt);
    }

    if (config->kafka.rk)
    {
        rd_kafka_destroy(config->kafka.rk);
        // rd_kafka_wait_destroyed(2000);
    }

#if 0
    if (config->kafka.tconf)
    {
        rd_kafka_topic_conf_destroy(config->kafka.tconf);
    }

    if (config->kafka.conf)
    {
        rd_kafka_conf_destroy(config->kafka.conf);
    }
#endif


    if (config->kafka.brokers)
    {
        free(config->kafka.brokers);
    }

    if (config->kafka.topic)
    {
        free(config->kafka.topic);
    }
#endif
    
}

