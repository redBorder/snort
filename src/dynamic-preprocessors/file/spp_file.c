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
 * File preprocessor
 * Author: Hui Cao
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */

#include "sf_types.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"
#include "snort_debug.h"

#include "preprocids.h"
#include "spp_file.h"
#include "sf_preproc_info.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifndef WIN32
#include <strings.h>
#include <sys/time.h>
#endif
#include <stdlib.h>
#include <ctype.h>
#include "file_agent.h"
#include "file_inspect_config.h"

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;
const char *PREPROC_NAME = "SF_FILE";
#define FILE_PREPROC_NAME  "file_inspect"

#define SetupFileInspect DYNAMIC_PREPROC_SETUP

#define CS_TYPE_SIGNATURE_SHAREMEM             ((GENERATOR_FILE_SIGNATURE *10) + 1)
#define CS_TYPE_SIGNATURE_DATABASE_LOOKUP      ((GENERATOR_FILE_SIGNATURE *10) + 2)

/*
 * Function prototype(s)
 */

static void FileInit( struct _SnortConfig*, char* );

static void print_file_stats(int exiting);

static void FileFreeConfig(tSfPolicyUserContextId config);
static int FileCheckConfig(struct _SnortConfig *);
static void FileCleanExit(int, void *);
static void FileUpdateConfig(FileInspectConf *, tSfPolicyUserContextId);


/** File configuration per Policy
 */
tSfPolicyUserContextId file_config = NULL;

#ifdef SNORT_RELOAD
static void FileReload(struct _SnortConfig *, char *, void **);
static int FileReloadVerify(struct _SnortConfig *, void *);
static void * FileReloadSwap(struct _SnortConfig *, void *);
static void FileReloadSwapFree(void *);
#endif

#ifdef CONTROL_SOCKET
static int File_Signature_PreControl(uint16_t type, const uint8_t *data,
    uint32_t length, void **new_config, char *statusBuf, int statusBufLen);
static int File_Signature_CS_Lookup(uint16_t type, const uint8_t *data,
    uint32_t length, void **new_config, char *statusBuf, int statusBufLen);
#endif

File_Stats file_inspect_stats;

/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:	None.
 *
 * RETURNS:	Nothing.
 *
 */
void SetupFileInspect(void)
{
    /* Link preprocessor keyword to initialization function
     * in the preprocessor list. */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc( "file_inspect", FileInit );
#else
    _dpd.registerPreproc("file_inspect", FileInit, FileReload, FileReloadVerify,
            FileReloadSwap, FileReloadSwapFree);
#endif

#ifdef CONTROL_SOCKET
    _dpd.controlSocketRegisterHandler(CS_TYPE_SIGNATURE_SHAREMEM,
        &File_Signature_PreControl, /*&File_Signature_Control*/ NULL,
        /*&File_Signature_PostControl*/ NULL);
    _dpd.controlSocketRegisterHandler(CS_TYPE_SIGNATURE_DATABASE_LOOKUP,
        &File_Signature_CS_Lookup, NULL, NULL);
#endif
}

/* Initializes the File preprocessor module and registers
 * it in the preprocessor list.
 *
 * PARAMETERS:
 *
 * argp:        Pointer to argument string to process for config
 *                      data.
 *
 * RETURNS:     Nothing.
 */
static void FileInit(struct _SnortConfig *sc, char *argp)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    FileInspectConf *pPolicyConfig = NULL;

    if (file_config == NULL)
    {
        /*create a context*/
        file_config = sfPolicyConfigCreate();
        if (file_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for File config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupFile(): The Stream preprocessor must be enabled.\n");
        }

        _dpd.addPreprocConfCheck(sc, FileCheckConfig);
        _dpd.registerPreprocStats(FILE_PREPROC_NAME, print_file_stats);
        _dpd.addPreprocExit(FileCleanExit, NULL, PRIORITY_LAST, PP_FILE_INSPECT);

    }

    sfPolicyUserPolicySet (file_config, policy_id);
    pPolicyConfig = (FileInspectConf *)sfPolicyUserDataGetCurrent(file_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("File preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (FileInspectConf *)calloc(1, sizeof(FileInspectConf));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "File preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(file_config, pPolicyConfig);

    file_config_parse(pPolicyConfig, (u_char *)argp);
    FileUpdateConfig(pPolicyConfig, file_config);
    file_agent_init(pPolicyConfig);
    _dpd.addPostConfigFunc(sc, file_agent_thread_init, pPolicyConfig);

}

static void FileUpdateConfig(FileInspectConf *pPolicyConfig, tSfPolicyUserContextId context)
{

    FileInspectConf *defaultConfig =
            (FileInspectConf *)sfPolicyUserDataGetDefault(context);

    if (pPolicyConfig == defaultConfig)
    {
        if (!pPolicyConfig->file_capture_queue_size)
            pPolicyConfig->file_capture_queue_size = FILE_CAPTURE_QUEUE_SIZE_DEFAULT;
        if (!pPolicyConfig->capture_disk_size)
            pPolicyConfig->capture_disk_size = FILE_CAPTURE_DISK_SIZE_DEFAULT;
    }
    else if (defaultConfig == NULL)
    {
        if (pPolicyConfig->file_capture_queue_size)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => File inspect: "
                    "file capture queue size must be configured "
                    "in the default config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }
    }
    else
    {
        pPolicyConfig->file_capture_queue_size = defaultConfig->file_capture_queue_size;

    }
}

static int FileFreeConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    FileInspectConf *pPolicyConfig = (FileInspectConf *)pData;

    //do any housekeeping before freeing FileInspectConf
    file_config_free(pPolicyConfig);
    sfPolicyUserDataClear (config, policyId);
    free(pPolicyConfig);
    return 0;
}

static void FileFreeConfig(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataFreeIterate (config, FileFreeConfigPolicy);
    sfPolicyConfigDelete(config);
}

static int FileCheckPolicyConfig(struct _SnortConfig *sc,
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData)
{
    _dpd.setParserPolicy(sc, policyId);

    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        DynamicPreprocessorFatalMessage("FileCheckPolicyConfig(): The Stream preprocessor must be enabled.\n");
    }
    return 0;
}

static int FileCheckConfig(struct _SnortConfig *sc)
{
    int rval;
    if ((rval = sfPolicyUserDataIterate (sc, file_config, FileCheckPolicyConfig)))
        return rval;
    return 0;
}

static void FileCleanExit(int signal, void *data)
{
    if (file_config != NULL)
    {
        file_agent_close();
        FileFreeConfig(file_config);
        file_config = NULL;
    }
}

#ifdef SNORT_RELOAD
static void FileReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId file_swap_config = (tSfPolicyUserContextId)*new_config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    FileInspectConf * pPolicyConfig = NULL;

    if (file_swap_config == NULL)
    {
        //create a context
        file_swap_config = sfPolicyConfigCreate();
        if (file_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for File config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupFile(): The Stream preprocessor must be enabled.\n");
        }

        *new_config = (void *)file_swap_config;
    }

    sfPolicyUserPolicySet (file_swap_config, policy_id);
    pPolicyConfig = (FileInspectConf *)sfPolicyUserDataGetCurrent(file_swap_config);

    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("File preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (FileInspectConf *)calloc(1, sizeof(FileInspectConf));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "File preprocessor configuration.\n");
    }
    sfPolicyUserDataSetCurrent(file_swap_config, pPolicyConfig);

    file_config_parse(pPolicyConfig, (u_char *)args);
    FileUpdateConfig(pPolicyConfig, file_config);

}

static int FileReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId file_swap_config = (tSfPolicyUserContextId)swap_config;
    FileInspectConf * pPolicyConfig = NULL;
    FileInspectConf * pCurrentConfig = NULL;

    if (file_swap_config == NULL)
        return 0;

    pPolicyConfig = (FileInspectConf *)sfPolicyUserDataGet(file_swap_config, _dpd.getDefaultPolicy());

    if (!pPolicyConfig)
        return 0;


    if (file_config != NULL)
    {
        pCurrentConfig = (FileInspectConf *)sfPolicyUserDataGet(file_config, _dpd.getDefaultPolicy());
    }

    if (!pCurrentConfig)
        return 0;

    if (file_config_compare(pCurrentConfig, pPolicyConfig))
    {
        _dpd.errMsg("File inspect reload: Changing file settings requires a restart.\n");
        return -1;
    }

    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("SetupFile(): The Stream preprocessor must be enabled.\n");
        return -1;
    }

    return 0;
}

static int FileFreeUnusedConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    FileInspectConf *pPolicyConfig = (FileInspectConf *)pData;

    //do any housekeeping before freeing FileInspectConf
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        free(pPolicyConfig);
    }
    return 0;
}

static void * FileReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId file_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = file_config;

    if (file_swap_config == NULL)
        return NULL;

    file_config = file_swap_config;

    file_swap_config = NULL;

    sfPolicyUserDataFreeIterate (old_config, FileFreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_config;
    }

    return NULL;
}

static void FileReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    FileFreeConfig((tSfPolicyUserContextId)data);
}
#endif

static void print_file_stats(int exiting)
{
    _dpd.logMsg("File Preprocessor Statistics\n");

    _dpd.logMsg("  Total file type callbacks:            "FMTu64("-10")" \n",
            file_inspect_stats.file_types_total);
    _dpd.logMsg("  Total file signature callbacks:       "FMTu64("-10")" \n",
            file_inspect_stats.file_signatures_total);
    _dpd.logMsg("  Total files would saved to disk:      "FMTu64("-10")" \n",
            file_inspect_stats.files_to_disk_total);
    _dpd.logMsg("  Total files saved to disk:            "FMTu64("-10")" \n",
            file_inspect_stats.files_saved);
    _dpd.logMsg("  Total file data saved to disk:        "FMTu64("-10")"bytes\n",
            file_inspect_stats.file_data_to_disk);
    _dpd.logMsg("  Total files duplicated:               "FMTu64("-10")" \n",
            file_inspect_stats.file_duplicates_total);
    _dpd.logMsg("  Total files duplicated in cbuffer:    "FMTu64("-10")" \n",
            file_inspect_stats.file_cbuffer_duplicates_total);
    _dpd.logMsg("  Total files reserving failed:         "FMTu64("-10")" \n",
            file_inspect_stats.file_reserve_failures);
    _dpd.logMsg("  Total file capture min:               "FMTu64("-10")" \n",
            file_inspect_stats.file_capture_min);
    _dpd.logMsg("  Total file capture max:               "FMTu64("-10")" \n",
            file_inspect_stats.file_capture_max);
    _dpd.logMsg("  Total file capture memcap:            "FMTu64("-10")" \n",
            file_inspect_stats.file_capture_memcap);
    _dpd.logMsg("  Total files reading failed:           "FMTu64("-10")" \n",
            file_inspect_stats.file_read_failures);
    _dpd.logMsg("  Total file agent memcap failures:     "FMTu64("-10")" \n",
            file_inspect_stats.file_agent_memcap_failures);
    _dpd.logMsg("  Total files sent:                     "FMTu64("-10")" \n",
            file_inspect_stats.files_to_host_total);
    _dpd.logMsg("  Total file data sent:                 "FMTu64("-10")" \n",
            file_inspect_stats.file_data_to_host);
    _dpd.logMsg("  Total file transfer failures:         "FMTu64("-10")" \n",
            file_inspect_stats.file_transfer_failures);
#if HAVE_S3FILE
    _dpd.logMsg("  Total file s3 transfer failures:      "FMTu64("-10")" \n",
        file_inspect_stats.files_to_s3_failures);
    _dpd.logMsg("  Total file s3 transfer:               "FMTu64("-10")" \n",
        file_inspect_stats.files_to_s3);
#endif


}

#ifdef CONTROL_SOCKET

static int File_Signature_PreControl(uint16_t type, const uint8_t *data, uint32_t length, void **new_config,
        char *statusBuf, int statusBufLen)
{
    static FileSigInfo blackList = {FILE_VERDICT_BLOCK};
    static FileSigInfo greyList = {FILE_VERDICT_LOG};

    int rc = 0;
    FileInspectConf *pDefaultPolicyConfig = NULL;
    FileInspectConf *nextConfig = NULL;

    statusBuf[0] = 0;

    pDefaultPolicyConfig = (FileInspectConf *)sfPolicyUserDataGetDefault(file_config);

    if (!pDefaultPolicyConfig)
    {
        *new_config = NULL;
        return -1;
    }

    nextConfig = (FileInspectConf *)calloc(1, sizeof(FileInspectConf));

    if (!nextConfig)
    {
        *new_config = NULL;
        return -1;
    }

    /* Update new SHA files */
    if (pDefaultPolicyConfig->blacklist_path)
    {
        const int rc = file_config_signature(pDefaultPolicyConfig->blacklist_path,
            &blackList, nextConfig, 0 /* allow_fatal */);
        if (0 == rc)
        {
            _dpd.logMsg("    File Preprocessor: Received new blacklist\n");
        }
    }

    if (0 == rc && pDefaultPolicyConfig->greylist_path)
    {
        const int rc = file_config_signature(pDefaultPolicyConfig->greylist_path,
            &greyList, nextConfig, 0 /* allow_fatal */);
        if (0 == rc)
        {
            _dpd.logMsg("    File Preprocessor: Received new greylist\n");
        }
    }

    if (0 == rc && pDefaultPolicyConfig->seenlist_path)
    {
        nextConfig->sha256_cache_table_rows = pDefaultPolicyConfig->sha256_cache_table_rows;
        nextConfig->sha256_cache_table_maxmem_m = pDefaultPolicyConfig->sha256_cache_table_maxmem_m;

        file_config_setup_seenlist(pDefaultPolicyConfig->seenlist_path,nextConfig, 0 /* allow_fatal */);
        _dpd.logMsg("    File Preprocessor: Received new seenlist\n");
    }

    if (0 == rc)
    {
        *new_config = nextConfig;
    }
    else
    {
        /* Error. Clean & exit */
        file_config_free(nextConfig);
        *new_config = NULL;
        return -1;
    }

    return 0;
}

static int File_Signature_CS_Lookup(uint16_t type, const uint8_t *data,
    uint32_t length, void **new_config, char *statusBuf, int statusBufLen)
{
    char sha256[SHA256_HASH_SIZE];
    FileSigInfo *pfile_verdict = NULL;
    int file_verdict;
    char *tokstr, *save, *data_copy;
    FileInspectConf *conf = (FileInspectConf *)sfPolicyUserDataGetCurrent(file_config);
    CSMessageDataHeader *msg_hdr = (CSMessageDataHeader *)data;

    statusBuf[0] = 0;

    if (length <= sizeof(*msg_hdr))
    {
        return -1;
    }
    length -= sizeof(*msg_hdr);
    if (length != (uint32_t)ntohs(msg_hdr->length))
    {
        return -1;
    }

    data += sizeof(*msg_hdr);
    data_copy = malloc(length + 1);
    if (data_copy == NULL)
    {
        return -1;
    }
    memcpy(data_copy, data, length);
    data_copy[length] = 0;

    tokstr = strtok_r(data_copy, " \t\n", &save);
    if (tokstr == NULL)
    {
        free(data_copy);
        return -1;
    }

    /* Convert tokstr to sha256 type */
    if (str_to_sha(tokstr, sha256, save - tokstr) != 0)
    {
        free(data_copy);
        return -1;
    }

    /* Get the SHA256 verdict info */
    if (conf->sig_table)
    {
        pfile_verdict = (FileSigInfo *)sha_table_find(conf->sig_table, sha256);
    }

    if (!pfile_verdict && conf->sha256_cache)
    {
        /* 2nd chance: seen files table. No need to footprints here. */
        void *n = sfxhash_find_node(conf->sha256_cache, sha256);
        if (n)
        {
            file_verdict = FILE_VERDICT_STOP;
            conf->sha256_cache->find_success--;
        }
        else
        {
            file_verdict = FILE_VERDICT_UNKNOWN;
            conf->sha256_cache->find_fail--;
        }
    }
    else
    {
        file_verdict = FILE_VERDICT_UNKNOWN;
    }

    const char *decision;

    switch (file_verdict)
    {
        case FILE_VERDICT_LOG:
        decision = "LOG";
        break;

        case FILE_VERDICT_STOP:
        decision = "STOP";
        break;

        case FILE_VERDICT_BLOCK:
        decision = "BLOCK";
        break;

        case FILE_VERDICT_REJECT:
        decision = "REJECT";
        break;

        case FILE_VERDICT_PENDING:
        decision = "PENDING";
        break;

        case FILE_VERDICT_STOP_CAPTURE:
        decision = "STOP_CAPTURE";
        break;

        case FILE_VERDICT_UNKNOWN:
        case FILE_VERDICT_MAX:
        default:
        decision = "UNKNOWN";
        break;
    };

    snprintf(statusBuf, statusBufLen,
        "SHA256 signature %s with verdict %s",
        tokstr, decision
        );

    free(data_copy);
    return 0;
}

#endif
