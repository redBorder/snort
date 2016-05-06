/*
 **
 **
 **  Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 **  Copyright (C) 2012-2013 Sourcefire, Inc.
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
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  5.25.12 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "sf_types.h"
#include <sys/types.h>
#include "file_api.h"
#include "file_config.h"
#include "file_mime_config.h"
#include "file_capture.h"
#include "file_stats.h"

#include "session_api.h"
#include "stream_api.h"
#include "mstring.h"
#include "preprocids.h"
#include "detect.h"
#include "plugbase.h"
#include "active.h"

#include "file_mime_process.h"
#include "file_resume_block.h"
#include "snort_httpinspect.h"
#include "file_service.h"
#include "file_segment_process.h"

#ifdef HAVE_EXTRADATA_FILE
#include "Unified2_common.h"
#endif

static bool file_type_id_enabled = false;
static bool file_signature_enabled = false;
static bool file_capture_enabled = false;
static bool file_processing_initiated = false;
static bool file_type_force = false;
#ifdef HAVE_EXTRADATA_FILE
static bool file_extradata_enabled = false;
#endif

static uint32_t file_config_version = 0;
static File_policy_callback_func file_policy_cb = NULL;
File_type_callback_func  file_type_cb = NULL;
File_signature_callback_func file_signature_cb = NULL;
Log_file_action_func log_file_action = NULL;

/*Main File Processing functions */
static int file_process(void* ssnptr, uint8_t* file_data, int data_size,
        FilePosition position, bool upload, bool suspend_block_verdict);

/*File properties*/
static int get_file_name(void* ssnptr, uint8_t **fname, uint32_t *name_size);
#ifdef HAVE_EXTRADATA_FILE
static int get_file_hostname(void* ssnptr, uint8_t **fname, uint32_t *name_size);
static int get_file_mailfrom(void* ssnptr, uint8_t **fname, uint32_t *name_size);
static int get_file_rcptto(void* ssnptr, uint8_t **fname, uint32_t *name_size);
static int get_file_headers(void* ssnptr, uint8_t **fname, uint32_t *name_size);

static int get_file_ftp_user(void* ssnptr, uint8_t **fuser, uint32_t *user_size);

static int get_file_smb_user_id(void* ssnptr, uint8_t **fuser, uint32_t *user_size);
#endif
static uint64_t get_file_size(void* ssnptr);
static uint64_t get_file_processed_size(void* ssnptr);
static bool get_file_direction(void* ssnptr);
static uint8_t *get_file_sig_sha256(void* ssnptr);

static void set_file_name(void* ssnptr, uint8_t * fname, uint32_t name_size,
        bool save_in_context);
#ifdef HAVE_EXTRADATA_FILE
static void set_file_hostname(void* ssnptr, uint8_t * fname, uint32_t name_size);
static void set_file_mailfrom(void* ssnptr, uint8_t * fname, uint32_t name_size);
static void set_file_rcptto(void* ssnptr, uint8_t * fname, uint32_t name_size);
static void set_file_headers(void* ssnptr, uint8_t * fname, uint32_t name_size);
static void set_file_ftp_user(void* ssnptr, uint8_t * fuser, uint32_t user_size);

static void set_file_smb_user_id(void* ssnptr, uint8_t *fuser, uint32_t user_size);
static void set_file_smb_is_upload(void* ssnptr, uint8_t is_upload);
#endif
static void set_file_direction(void* ssnptr, bool upload);

static void set_file_policy_callback(File_policy_callback_func);
static void enable_file_type(File_type_callback_func );
static void enable_file_signature (File_signature_callback_func);
static void enable_file_capture(File_signature_callback_func );
#ifdef HAVE_EXTRADATA_FILE
static void FileRegisterXtraDataFuncs(FileConfig *pFileConfig);
static void enable_file_extradata();
static int GetFileSHA256(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileSize(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileName(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileHostname(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileMailFrom(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileRcptTo(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileHeaders(void *data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileFtpUser(void* data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileSmbUserId(void* data, uint8_t **buf, uint32_t *len, uint32_t *type);
static int GetFileSmbIsUpload(void* data, uint8_t **buf, uint32_t *len, uint32_t *type);
#endif
static void set_file_action_log_callback(Log_file_action_func);

static int64_t get_max_file_depth(void);

static uint32_t str_to_hash(uint8_t *str, int length );

static void file_signature_lookup(void* p, bool is_retransmit);
static void file_signature_callback(Packet* p);

static inline void finish_signature_lookup(FileContext *context);
static File_Verdict get_file_verdict(void *ssnptr);
static void render_block_verdict(void *ctx, void *p);

static bool is_file_service_enabled(void);
static uint32_t get_file_type_id(void *ssnptr);
static uint32_t get_new_file_instance(void *ssnptr);

/* File context based file processing*/
FileContext* create_file_context(void *ssnptr);
static void init_file_context(void *ssnptr, bool upload, FileContext *context);
bool set_current_file_context(void *ssnptr, FileContext *ctx);
FileContext* get_current_file_context(void *ssnptr);
FileContext* get_main_file_context(void *ssnptr);
static int process_file_context(FileContext *ctx, void *p, uint8_t *file_data,
        int data_size, FilePosition position, bool suspend_block_verdict);
static FilePosition get_file_position(void *pkt);
static bool check_paf_abort(void* ssn);
static int64_t get_max_file_capture_size(void *ssn);
static void file_session_free(void *session_data);
extern FileEntry *file_cache_get(FileCache *fileCache, void* p, uint64_t file_id);

FileAPI fileAPI;
FileAPI* file_api = NULL;

static unsigned s_cb_id = 0;

void init_fileAPI(void)
{
    fileAPI.version = FILE_API_VERSION;
    fileAPI.is_file_service_enabled = &is_file_service_enabled;
    fileAPI.file_process = &file_process;
    fileAPI.get_file_name = &get_file_name;
#ifdef HAVE_EXTRADATA_FILE
    fileAPI.get_file_hostname = &get_file_hostname;
    fileAPI.get_file_mailfrom = &get_file_mailfrom;
    fileAPI.get_file_rcptto = &get_file_rcptto;
    fileAPI.get_file_headers = &get_file_headers;
    fileAPI.get_file_ftp_user = &get_file_ftp_user;
#endif
    fileAPI.get_file_size = &get_file_size;
    fileAPI.get_file_processed_size = &get_file_processed_size;
    fileAPI.get_file_direction = &get_file_direction;
    fileAPI.get_sig_sha256 = &get_file_sig_sha256;
    fileAPI.set_file_name = &set_file_name;
#ifdef HAVE_EXTRADATA_FILE
    fileAPI.set_file_hostname = &set_file_hostname;
    fileAPI.set_file_mailfrom = &set_file_mailfrom;
    fileAPI.set_file_rcptto = &set_file_rcptto;
    fileAPI.set_file_headers = &set_file_headers;
    fileAPI.set_file_ftp_user = &set_file_ftp_user;
    fileAPI.set_file_smb_user_id = &set_file_smb_user_id;
    fileAPI.set_file_smb_is_upload = &set_file_smb_is_upload;
#endif
    fileAPI.set_file_direction = &set_file_direction;
    fileAPI.set_file_policy_callback = &set_file_policy_callback;
    fileAPI.enable_file_type = &enable_file_type;
    fileAPI.enable_file_signature = &enable_file_signature;
    fileAPI.enable_file_capture = &enable_file_capture;
#ifdef HAVE_EXTRADATA_FILE
    fileAPI.enable_file_extradata = &enable_file_extradata;
#endif
    fileAPI.set_file_action_log_callback = &set_file_action_log_callback;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    fileAPI.set_log_buffers = &set_log_buffers;
    fileAPI.init_mime_mempool = &init_mime_mempool;
    fileAPI.init_log_mempool=  &init_log_mempool;
    fileAPI.file_resume_block_add_file = &file_resume_block_add_file;
    fileAPI.file_resume_block_check = &file_resume_block_check;
    fileAPI.str_to_hash = &str_to_hash;
    fileAPI.file_signature_lookup = &file_signature_lookup;
    fileAPI.set_mime_decode_config_defauts = &set_mime_decode_config_defauts;
    fileAPI.set_mime_log_config_defauts = &set_mime_log_config_defauts;
    fileAPI.parse_mime_decode_args = &parse_mime_decode_args;
    fileAPI.process_mime_data = &process_mime_data;
    fileAPI.free_mime_session = &free_mime_session;
    fileAPI.is_decoding_enabled = &is_decoding_enabled;
    fileAPI.is_decoding_conf_changed = &is_decoding_conf_changed;
    fileAPI.check_decoding_conf = &check_decode_config;
    fileAPI.is_mime_log_enabled = &is_mime_log_enabled;
    fileAPI.finalize_mime_position = &finalize_mime_position;
    fileAPI.get_file_verdict = &get_file_verdict;
    fileAPI.render_block_verdict = &render_block_verdict;
    fileAPI.reserve_file = &file_capture_reserve;
    fileAPI.read_file = &file_capture_read;
    fileAPI.release_file = &file_capture_release;
    fileAPI.get_file_capture_size = &file_capture_size;
    fileAPI.get_file_type_id = &get_file_type_id;
    fileAPI.get_new_file_instance = &get_new_file_instance;

    fileAPI.create_file_context = &create_file_context;
    fileAPI.init_file_context = &init_file_context;
    fileAPI.set_current_file_context = &set_current_file_context;
    fileAPI.get_current_file_context = &get_current_file_context;
    fileAPI.get_main_file_context = &get_main_file_context;
    fileAPI.process_file = &process_file_context;
    fileAPI.get_file_position = &get_file_position;
    fileAPI.reset_mime_paf_state = &reset_mime_paf_state;
    fileAPI.process_mime_paf_data = &process_mime_paf_data;
    fileAPI.check_data_end = check_data_end;
    fileAPI.check_paf_abort = &check_paf_abort;
    fileAPI.get_max_file_capture_size = get_max_file_capture_size;
    fileAPI.file_cache_update_entry = &file_cache_update_entry;
    fileAPI.file_segment_process = &file_segment_process;
    fileAPI.file_cache_create = &file_cache_create;
    fileAPI.file_cache_free = &file_cache_free;
    fileAPI.file_cache_status = &file_cache_status;
    file_api = &fileAPI;
    init_mime();
}

void FileAPIPostInit (void)
{
    FileConfig *file_config = (FileConfig *)(snort_conf->file_config);

    if (file_type_id_enabled || file_signature_enabled || file_capture_enabled)
    {
        if (!file_config)
        {
            file_config =  file_service_config_create();
            snort_conf->file_config = file_config;
        }
#ifdef HAVE_EXTRADATA_FILE
        if (file_extradata_enabled)
            FileRegisterXtraDataFuncs(file_config);
#endif
    }

    if ( file_capture_enabled)
        file_capture_init_mempool(file_config->file_capture_memcap,
                file_config->file_capture_block_size);

    if ( stream_api && file_signature_enabled )
        s_cb_id = stream_api->register_event_handler(file_signature_callback);

#ifdef SNORT_RELOAD
    file_sevice_reconfig_set(false);
#endif

}

#ifdef HAVE_EXTRADATA_FILE
static void FileRegisterXtraDataFuncs(FileConfig *file_config)
{
    if ((stream_api == NULL) || !file_config)
        return;
    file_config->xtra_file_sha256_id = stream_api->reg_xtra_data_cb(GetFileSHA256);
    file_config->xtra_file_size_id = stream_api->reg_xtra_data_cb(GetFileSize);
    file_config->xtra_file_name_id = stream_api->reg_xtra_data_cb(GetFileName);
    file_config->xtra_file_hostname_id = stream_api->reg_xtra_data_cb(GetFileHostname);
    file_config->xtra_file_mailfrom_id = stream_api->reg_xtra_data_cb(GetFileMailFrom);
    file_config->xtra_file_rcptto_id = stream_api->reg_xtra_data_cb(GetFileRcptTo);
    file_config->xtra_file_headers_id = stream_api->reg_xtra_data_cb(GetFileHeaders);
    file_config->xtra_file_ftp_user_id = stream_api->reg_xtra_data_cb(GetFileFtpUser);
    file_config->xtra_file_smb_user_id_id = stream_api->reg_xtra_data_cb(GetFileSmbUserId);
    file_config->xtra_file_smb_is_upload_id = stream_api->reg_xtra_data_cb(GetFileSmbIsUpload);
}

static int GetFileSHA256(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    if (data == NULL)
        return 0;

    *buf = get_file_sig_sha256(data);
    *len = SHA256_HASH_SIZE;
    *type = EVENT_INFO_FILE_SHA256;
    return 1;
}

static int GetFileSize(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_size > 0)
    {
        *buf = (uint8_t *) (context->file_size_str);
        *len = snprintf(context->file_size_str, sizeof(context->file_size_str), "%lu", context->file_size);
        *type = EVENT_INFO_FILE_SIZE;
        return 1;
    }

    return 0;
}

static int GetFileName(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_name_size > 0)
    {
        *buf = context->file_name;
        *len = context->file_name_size;
        *type = EVENT_INFO_FILE_NAME;
        return 1;
    }

    return 0;
}

static int GetFileHostname(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->hostname_size > 0)
    {
        *buf = context->hostname;
        *len = context->hostname_size;
        *type = EVENT_INFO_FILE_HOSTNAME;
        return 1;
    }

    return 0;
}

static int GetFileMailFrom(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_mailfrom_size > 0)
    {
        *buf = context->file_mailfrom;
        *len = context->file_mailfrom_size;
        *type = EVENT_INFO_FILE_MAILFROM;
        return 1;
    }

    return 0;
}

static int GetFileRcptTo(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_rcptto_size > 0)
    {
        *buf = context->file_rcptto;
        *len = context->file_rcptto_size;
        *type = EVENT_INFO_FILE_RCPTTO;
        return 1;
    }

    return 0;
}

static int GetFileHeaders(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_headers_size > 0)
    {
        *buf = context->file_headers;
        *len = context->file_headers_size;
        *type = EVENT_INFO_FILE_EMAIL_HDRS;
        return 1;
    }

    return 0;
}

static int GetFileFtpUser(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_ftp_user_size > 0)
    {
        *buf = context->file_ftp_user;
        *len = context->file_ftp_user_size;
        *type = EVENT_INFO_FILE_FTP_USER;
        return 1;
    }

    return 0;
}

static int GetFileSmbUserId(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_smb_user_id_size > 0)
    {
        *buf = context->file_smb_user_id;
        *len = context->file_smb_user_id_size;
        *type = EVENT_INFO_FILE_SMB_USER_ID;
        return 1;
    }

    return 0;
}

static int GetFileSmbIsUpload(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    FileContext * context = NULL;

    if (data == NULL)
        return 0;

    context = get_current_file_context(data);

    if(context == NULL)
        return 0;

    if (context->file_smb_is_upload_valid > 0)
    {
        *buf = &context->file_smb_is_upload;
        *len = sizeof(context->file_smb_is_upload);
        *type = EVENT_INFO_FILE_SMB_IS_UPLOAD;
        return 1;
    }

    return 0;
}
#endif

static void start_file_processing(void)
{
    if (!file_processing_initiated)
    {
        file_resume_block_init();
        RegisterPreprocStats("file", print_file_stats);
        file_processing_initiated = true;
    }
}

void free_file_config(void *conf)
{
    file_config_version++;
    file_rule_free(conf);
    file_identifiers_free(conf);
    free(conf);
}

void close_fileAPI(void)
{
    file_resume_block_cleanup();
    free_mime();
    file_caputure_close();
}

FileSession* get_file_session(void *ssnptr)
{
    return ((FileSession*)session_api->get_application_data(ssnptr, PP_FILE));
}

static inline FileSession* get_create_file_session(void *ssnptr)
{
    FileSession *file_session = get_file_session(ssnptr);
    if(!file_session)
    {
        file_session = (FileSession *)SnortAlloc(sizeof(*file_session));
        if (session_api->set_application_data(ssnptr, PP_FILE, file_session,
                file_session_free))
        {
            free(file_session);
            return NULL;
        }
    }
    return(file_session);
}

/*Get the current working file context*/
FileContext* get_current_file_context(void *ssnptr)
{
    FileSession *file_session = get_file_session (ssnptr);
    if (file_session)
        return file_session->current_context;
    else
        return NULL;
}

/*Get the current main file context*/
FileContext* get_main_file_context(void *ssnptr)
{
    FileSession *file_session = get_file_session (ssnptr);
    if (file_session)
        return file_session->main_context;
    else
        return NULL;
}

/*Get the current working file context*/
static inline void save_to_pending_context(void *ssnptr)
{
    FileSession *file_session = get_create_file_session (ssnptr);
    /* Save to pending_context */
    if (!file_session)
        return;

    if (file_session->main_context)
    {
        if (file_session->pending_context != file_session->main_context)
            file_context_free(file_session->pending_context);
        file_session->pending_context = file_session->main_context;
    }
    else
    {
        file_session->pending_context = file_session->current_context;
    }
}

/*Set the current working file context*/
bool set_current_file_context(void *ssnptr, FileContext *ctx)
{
    FileSession *file_session = get_create_file_session (ssnptr);

    if (!file_session)
    {
        return false;
    }

    file_session->current_context = ctx;
    return true;
}

static void file_session_free(void *session_data)
{
    FileSession *file_session = (FileSession *)session_data;
    if (!file_session)
        return;

    /*Clean up all the file contexts*/
    if (file_session->main_context)
    {
        if ( file_session->pending_context &&
                (file_session->main_context != file_session->pending_context))
        {
            file_context_free(file_session->pending_context);
        }

        file_context_free(file_session->main_context);
    }

    free(file_session);
}

static void init_file_context(void *ssnptr, bool upload, FileContext *context)
{
    context->file_type_enabled = file_type_id_enabled;
    context->file_signature_enabled = file_signature_enabled;
    context->file_capture_enabled = file_capture_enabled;
    file_direction_set(context,upload);
    file_stats.files_total++;
#ifdef TARGET_BASED
    /* Check file policy to see whether we want to do either file type, file
     * signature,  or file capture
     * Note: this happen only on the start of session*/
    if (file_policy_cb)
    {
        uint32_t policy_flags = 0;
        context->app_id = session_api->get_application_protocol_id(ssnptr);

        policy_flags = file_policy_cb(ssnptr, context->app_id, upload);

        if ( !file_type_force && !(policy_flags & ENABLE_FILE_TYPE_IDENTIFICATION) )
                context->file_type_enabled = false;

        if ( !(policy_flags & ENABLE_FILE_SIGNATURE_SHA256) )
            context->file_signature_enabled = false;

        if ( !(policy_flags & ENABLE_FILE_CAPTURE) )
            context->file_capture_enabled = false;
    }
#endif
}

FileContext* create_file_context(void *ssnptr)
{
    FileContext *context = file_context_create();

#ifdef HAVE_EXTRADATA_FILE
    if (snort_conf != NULL && snort_conf->file_config != NULL)
    {
        context->xtra_file_sha256_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_sha256_id;
        context->xtra_file_size_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_size_id;
        context->xtra_file_name_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_name_id;
        context->xtra_file_hostname_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_hostname_id;
        context->xtra_file_mailfrom_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_mailfrom_id;
        context->xtra_file_rcptto_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_rcptto_id;
        context->xtra_file_headers_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_headers_id;
        context->xtra_file_ftp_user_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_ftp_user_id;
        context->xtra_file_smb_user_id_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_smb_user_id_id;
        context->xtra_file_smb_is_upload_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_smb_is_upload_id;
    }
#endif

    /* Create file session if not yet*/
    get_create_file_session (ssnptr);

    return context;
}

static inline FileContext* find_main_file_context(void* p, FilePosition position,
        bool upload)
{
    FileContext* context = NULL;
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;
    FileSession *file_session = get_file_session (ssnptr);

    /* Attempt to get a previously allocated context. */
    if (file_session)
        context  = file_session->main_context;

    if (context && ((position == SNORT_FILE_MIDDLE) ||
            (position == SNORT_FILE_END)))
        return context;
    else if (context)
    {
        /*Push file event when there is another file in the same packet*/
        if (pkt->packet_flags & PKT_FILE_EVENT_SET)
        {
            SnortEventqLog(snort_conf->event_queue, p);
            SnortEventqReset();
            pkt->packet_flags &= ~PKT_FILE_EVENT_SET;
        }

        if (context->verdict != FILE_VERDICT_PENDING)
        {
            /* Reuse the same context */
            file_context_reset(context);

#ifdef HAVE_EXTRADATA_FILE
            if (snort_conf != NULL && snort_conf->file_config != NULL)
            {
                context->xtra_file_sha256_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_sha256_id;
                context->xtra_file_size_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_size_id;
                context->xtra_file_name_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_name_id;
                context->xtra_file_hostname_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_hostname_id;
                context->xtra_file_mailfrom_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_mailfrom_id;
                context->xtra_file_rcptto_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_rcptto_id;
                context->xtra_file_headers_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_headers_id;
                context->xtra_file_ftp_user_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_ftp_user_id;
                context->xtra_file_smb_user_id_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_smb_user_id_id;
                context->xtra_file_smb_is_upload_id = ((FileConfig *)(snort_conf->file_config))->xtra_file_smb_is_upload_id;
            }
#endif

            init_file_context(ssnptr, upload, context);
            context->file_id = file_session->max_file_id++;
            return context;
        }
    }

    context = create_file_context(ssnptr);
    file_session = get_create_file_session (ssnptr);
    file_session->main_context = context;
    init_file_context(ssnptr, upload, context);
    context->file_id = file_session->max_file_id++;
    return context;
}

static inline void updateFileSize(FileContext* context, int data_size,
        FilePosition position)
{
    context->processed_bytes += data_size;
    if ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL))
    {
        if (get_max_file_depth() == (int64_t)context->processed_bytes)
            context->file_size = 0;
        else
            context->file_size = context->processed_bytes;
        context->processed_bytes = 0;
    }
}

int file_eventq_add(uint32_t gid, uint32_t sid, char *msg, RuleType type)
{
    OptTreeNode *otn;
    RuleTreeNode *rtn;

    otn = GetApplicableOtn(gid, sid, 1, 0, 3, msg);
    if (otn == NULL)
        return 0;

    rtn = getRtnFromOtn(otn, getIpsRuntimePolicy());
    if (rtn == NULL)
    {
        return 0;
    }

    rtn->type = type;

    return SnortEventqAdd(gid, sid, 1, 0, 3, msg, otn);
}

static inline void add_file_to_block(Packet *p, File_Verdict verdict,
        uint32_t file_type_id, uint8_t *signature)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    Packet *pkt = (Packet *)p;
    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

    Active_ForceDropPacket();
    DisableAllDetect( p );
    pkt->packet_flags |= PKT_FILE_EVENT_SET;

    /*Use URI as the identifier for file*/
    if (GetHttpUriData(p->ssnptr, &buf, &len, &type))
    {
        file_sig = str_to_hash(buf, len);
        file_resume_block_add_file(p, file_sig,
                (uint32_t)file_config->file_block_timeout,
                verdict, file_type_id, signature);
    }
}
/*
 * Check HTTP partial content header
 * Return: 1: partial content header
 *         0: not http partial content header
 */
static inline int check_http_partial_content(Packet *p)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    const HttpBuffer* hb = GetHttpBuffer(HTTP_BUFFER_STAT_CODE);

    /*Not HTTP response, return*/
    if ( !hb )
        return 0;

    /*Not partial content, return*/
    if ( (hb->length != 3) || strncmp((const char*)hb->buf, "206", 3) )
        return 0;

    /*Use URI as the identifier for file*/
    if (GetHttpUriData(p->ssnptr, &buf, &len, &type))
    {
        file_sig = str_to_hash(buf, len);
        file_resume_block_check(p, file_sig);
    }

    return 1;
}

/* File signature lookup at the end of file
 * File signature callback can be used for malware lookup, file capture etc
 */
static inline void _file_signature_lookup(FileContext* context,
        void* p, bool is_retransmit, bool suspend_block_verdict)
{
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;

    if (file_signature_cb)
    {
        verdict = file_signature_cb(p, ssnptr, context->sha256,
                context->file_size, &(context->file_state), context->upload,
                context->file_id);
        file_stats.verdicts_signature[verdict]++;
    }

    if (suspend_block_verdict)
        context->suspend_block_verdict = true;

    context->verdict = verdict;

    if (verdict == FILE_VERDICT_LOG )
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__ALERT);
        pkt->packet_flags |= PKT_FILE_EVENT_SET;
        context->file_signature_enabled = false;
    }
    else if (verdict == FILE_VERDICT_PENDING)
    {
        /*Can't decide verdict, drop packet and waiting...*/
        if (is_retransmit)
        {
            FileConfig *file_config =  (FileConfig *)context->file_config;
            /*Drop packets if not timeout*/
            if (pkt->pkth->ts.tv_sec <= context->expires)
            {
                if( !Active_DAQRetryPacket(pkt) )
                    Active_ForceDropPacket();

                return;
            }
            /*Timeout, let packet go through OR block based on config*/
            context->file_signature_enabled = false;
            if (file_config && file_config->block_timeout_lookup)
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                        FILE_SIGNATURE_SHA256_STR, RULE_TYPE__REJECT);
            else
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                        FILE_SIGNATURE_SHA256_STR, RULE_TYPE__ALERT);
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else
        {
            FileConfig *file_config =  (FileConfig *)context->file_config;
            if (file_config)
                context->expires = (time_t)(file_config->file_lookup_timeout + pkt->pkth->ts.tv_sec);

            if( !Active_DAQRetryPacket(pkt) )
                Active_ForceDropPacket();

            stream_api->set_event_handler(ssnptr, s_cb_id, SE_REXMIT);
            save_to_pending_context(ssnptr);
            return;
        }
    }
    else if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
    {
        if (!context->suspend_block_verdict)
            render_block_verdict(context, p);
        context->file_signature_enabled = false;
        return;
    }

    finish_signature_lookup(context);
}

static inline void finish_signature_lookup(FileContext *context)
{
    if (context->sha256)
    {
        context->file_signature_enabled = false;
        file_capture_stop(context);
        file_stats.signatures_processed[context->file_type_id][context->upload]++;
#ifdef TARGET_BASED
        file_stats.signatures_by_proto[context->app_id]++;
#endif
    }
}

static File_Verdict get_file_verdict(void *ssnptr)
{
    FileContext *context = get_current_file_context(ssnptr);

    if (context == NULL)
        return FILE_VERDICT_UNKNOWN;

    return context->verdict;
}

static void render_block_verdict(void *ctx, void *p)
{
    FileContext *context = (FileContext *)ctx;
    Packet *pkt = (Packet *)p;

    if (p == NULL)
        return;

    if (context == NULL)
    {
        context = get_current_file_context(pkt->ssnptr);
        if (context == NULL)
            return;
    }

    if (context->verdict == FILE_VERDICT_BLOCK)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__DROP);
        add_file_to_block(p, context->verdict, context->file_type_id,
                context->sha256);
    }
    else if (context->verdict == FILE_VERDICT_REJECT)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__REJECT);
        add_file_to_block(p, context->verdict, context->file_type_id,
                context->sha256);
    }

    finish_signature_lookup(context);
}

static uint32_t get_file_type_id(void *ssnptr)
{
    // NOTE: 'ssnptr' NULL checked in get_application_data
    FileContext *context = get_current_file_context(ssnptr);

    if ( !context )
        return FILE_VERDICT_UNKNOWN;

    return context->file_type_id;
}

static uint32_t get_new_file_instance(void *ssnptr)
{
    FileSession *file_session = get_create_file_session (ssnptr);

    if (file_session)
    {
        return file_session->max_file_id++;
    }
    else
    {
        return 0;
    }
}

static void file_signature_lookup(void* p, bool is_retransmit)
{
    Packet *pkt = (Packet *)p;

    FileContext* context  = get_current_file_context(pkt->ssnptr);

    if (context && context->file_signature_enabled && context->sha256)
    {
        _file_signature_lookup(context, p, is_retransmit, false);
    }
}

static void file_signature_callback(Packet* p)
{
    /* During retransmission */
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;
    FileSession *file_session;
    FileEntry *fileEntry;

    if (!ssnptr)
        return;
    file_session = get_file_session (ssnptr);
    if (!file_session)
        return;

    if(file_session->file_cache)
    {
        fileEntry = file_cache_get(file_session->file_cache, p, file_session->file_id);
        if (!fileEntry)
            return;
        if (fileEntry->context)
        {
            if(fileEntry->context->verdict == FILE_VERDICT_PENDING)
            {
                file_session->current_context = fileEntry->context;
            }
            file_signature_lookup(p, 1);
        }
    }
    else
    {
        if(file_session->pending_context)
        {
            file_session->current_context = file_session->pending_context;
        }
        file_signature_lookup(p, 1);
    }
}

static bool is_file_service_enabled()
{
    return (file_type_id_enabled || file_signature_enabled);
}

/*
 * Return:
 *    1: continue processing/log/block this file
 *    0: ignore this file
 */
static int process_file_context(FileContext *context, void *p, uint8_t *file_data,
        int data_size, FilePosition position, bool suspend_block_verdict)
{
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;

    if (!context)
        return 0;

    set_current_file_context(ssnptr, context);
    file_stats.file_data_total += data_size;

#ifdef HAVE_EXTRADATA_FILE
    pkt->xtradata_mask |= BIT(context->xtra_file_sha256_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_size_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_name_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_hostname_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_mailfrom_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_rcptto_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_headers_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_ftp_user_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_smb_user_id_id);
    pkt->xtradata_mask |= BIT(context->xtra_file_smb_is_upload_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_sha256_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_size_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_name_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_hostname_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_mailfrom_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_rcptto_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_headers_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_ftp_user_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_smb_user_id_id);
    //stream_api->set_extra_data(pkt->ssnptr, pkt, context->xtra_file_smb_is_upload_id);
#endif

    if ((!context->file_type_enabled) && (!context->file_signature_enabled))
    {
        updateFileSize(context, data_size, position);
        return 0;
    }

    /* if file config is changed, update it*/
    if ((context->file_config != snort_conf->file_config) ||
            (context->file_config_version != file_config_version))
    {
        context->file_config = snort_conf->file_config;
        context->file_config_version = file_config_version;
        /* Reset file type context that relies on file_conf.
         * File type id will become UNKNOWN after file_type_id()
         * if in the middle of file and file type is CONTINUE (undecided) */
        context->file_type_context = NULL;
    }

    if(check_http_partial_content(p))
    {
        context->file_type_enabled = false;
        context->file_signature_enabled = false;
        return 0;
    }

    /*file type id*/
    if (context->file_type_enabled)
    {
        File_Verdict verdict = FILE_VERDICT_UNKNOWN;

        file_type_id(context, file_data, data_size, position);

        /*Don't care unknown file type*/
        if (context->file_type_id == SNORT_FILE_TYPE_UNKNOWN)
        {
            context->file_type_enabled = false;
            context->file_signature_enabled = false;
            updateFileSize(context, data_size, position);
            file_capture_stop(context);
            return 0;
        }

        if (context->file_type_id != SNORT_FILE_TYPE_CONTINUE)
        {
            if (file_type_cb)
            {
                verdict = file_type_cb(p, ssnptr, context->file_type_id,
                        context->upload, context->file_id);
                file_stats.verdicts_type[verdict]++;
                context->verdict = verdict;
            }
            context->file_type_enabled = false;
            file_stats.files_processed[context->file_type_id][context->upload]++;
#ifdef TARGET_BASED
            file_stats.files_by_proto[context->app_id]++;
#endif
        }

        if (verdict == FILE_VERDICT_LOG )
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_type_name(context->file_config, context->file_type_id),
                    RULE_TYPE__ALERT);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else if (verdict == FILE_VERDICT_BLOCK)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_type_name(context->file_config, context->file_type_id),
                    RULE_TYPE__DROP);
            updateFileSize(context, data_size, position);
            context->file_signature_enabled = false;
            add_file_to_block(p, verdict, context->file_type_id, NULL);
            return 1;
        }
        else if (verdict == FILE_VERDICT_REJECT)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_type_name(context->file_config, context->file_type_id),
                    RULE_TYPE__REJECT);
            updateFileSize(context, data_size, position);
            context->file_signature_enabled = false;
            add_file_to_block(p, verdict, context->file_type_id, NULL);
            return 1;
        }
        else if (verdict == FILE_VERDICT_STOP)
        {
            context->file_signature_enabled = false;
        }
        else if (verdict == FILE_VERDICT_STOP_CAPTURE)
        {
            file_capture_stop(context);
        }
    }

    /* file signature calculation */
    if (context->file_signature_enabled)
    {
        if (!context->sha256)
            file_signature_sha256(context, file_data, data_size, position);
        file_stats.data_processed[context->file_type_id][context->upload]
                                                         += data_size;
        updateFileSize(context, data_size, position);

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (context->file_capture_enabled &&
                file_capture_process(context, file_data, data_size, position))
        {
            file_capture_stop(context);
            _file_signature_lookup(context, p, false, suspend_block_verdict);
            if (context->verdict != FILE_VERDICT_UNKNOWN)
                return 1;
        }

        /*Either get SHA or exceeding the SHA limit, need lookup*/

        if (context->file_state.sig_state == FILE_SIG_DEPTH_FAIL)
        {
            file_stats.files_sig_depth++;
            _file_signature_lookup(context, p, false, suspend_block_verdict);

            /* Add the event with the File Type after signature process finishes,
               no matter if sig_state is either DONE or DEPTH_FAIL. If it is DONE,
               the event will include the SHA256 file as ExtraData. If it is DEPTH_FAIL,
               the event won't include it. */
            if (!(pkt->packet_flags & PKT_FILE_EVENT_SET) &&
                context->file_type_id != SNORT_FILE_TYPE_CONTINUE &&
                context->file_type_id != SNORT_FILE_TYPE_UNKNOWN)
            {
                file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                        file_type_name(context->file_config, context->file_type_id),
                        RULE_TYPE__ALERT);
                pkt->packet_flags |= PKT_FILE_EVENT_SET;
            }
        }
        else if ((context->file_state.sig_state == FILE_SIG_DONE) && isFileEnd(position))
        {
            FILE_REG_DEBUG_WRAP(if (context->sha256) file_sha256_print(context->sha256);)
            _file_signature_lookup(context, p, false, suspend_block_verdict);
        }

    }
#ifdef HAVE_EXTRADATA_FILE //(check to delete this piece of code since it will be mandatory enable signature from conf is sha256 is wanted in extradata)
    else if (context->xtra_file_sha256_id)
    {
        file_signature_sha256(context, file_data, data_size, position);
        file_stats.data_processed[context->file_type_id][context->upload]
                                                         += data_size;
        updateFileSize(context, data_size, position);
        // (During the tests, including the lines before should be considered)
        //FILE_REG_DEBUG_WRAP(if (context->sha256) file_sha256_print(context->sha256);)
        //Either get SHA or exceeding the SHA limit, need lookup
        //if (context->file_state.sig_state != FILE_SIG_PROCESSING)
        //{
        //    if (context->file_state.sig_state == FILE_SIG_DEPTH_FAIL)
        //        file_stats.files_sig_depth++;
        //    _file_signature_lookup(context, p, false, suspend_block_verdict);
        //}
    }
#endif
    else
    {
        updateFileSize(context, data_size, position);
    }
    return 1;
}

/*
 * Return:
 *    1: continue processing/log/block this file
 *    0: ignore this file
 */
static int file_process( void* p, uint8_t* file_data, int data_size,
        FilePosition position, bool upload, bool suspend_block_verdict)
{
    FileContext* context;

    /* if both disabled, return immediately*/
    if (!is_file_service_enabled())
        return 0;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return 0;

    FILE_REG_DEBUG_WRAP(DumpHexFile(stdout, file_data, data_size);)

    context = find_main_file_context(p, position, upload);
    return process_file_context(context, p, file_data, data_size, position,
            suspend_block_verdict);
}

static void set_file_name (void* ssnptr, uint8_t* fname, uint32_t name_size,
        bool save_in_context)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_name_set(context, fname, name_size, save_in_context);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

/* Return 1: file name available,
 *        0: file name is unavailable
 */
static int get_file_name (void* ssnptr, uint8_t **fname, uint32_t *name_size)
{
    return file_name_get(get_current_file_context(ssnptr), fname, name_size);
}

#ifdef HAVE_EXTRADATA_FILE
static void set_file_hostname (void* ssnptr, uint8_t* fhostname, uint32_t hostname_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_hostname_set(context, fhostname, hostname_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_hostname (void* ssnptr, uint8_t **fhostname, uint32_t *hostname_size)
{
    return file_hostname_get(get_current_file_context(ssnptr), fhostname, hostname_size);
}

static void set_file_mailfrom (void* ssnptr, uint8_t* fmailfrom, uint32_t mailfrom_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_mailfrom_set(context, fmailfrom, mailfrom_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_mailfrom (void* ssnptr, uint8_t **fmailfrom, uint32_t *mailfrom_size)
{
    return file_mailfrom_get(get_current_file_context(ssnptr), fmailfrom, mailfrom_size);
}

static void set_file_rcptto (void* ssnptr, uint8_t* frcptto, uint32_t rcptto_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_rcptto_set(context, frcptto, rcptto_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_rcptto (void* ssnptr, uint8_t **frcptto, uint32_t *rcptto_size)
{
    return file_rcptto_get(get_current_file_context(ssnptr), frcptto, rcptto_size);
}

static void set_file_headers (void* ssnptr, uint8_t* fheaders, uint32_t headers_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_headers_set(context, fheaders, headers_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_headers (void* ssnptr, uint8_t **fheaders, uint32_t *headers_size)
{
    return file_headers_get(get_current_file_context(ssnptr), fheaders, headers_size);
}

static void set_file_ftp_user(void* ssnptr, uint8_t *fuser, uint32_t user_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_ftp_user_set(context, fuser, user_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_ftp_user(void* ssnptr, uint8_t **fuser, uint32_t *user_size)
{
    return file_ftp_user_get(get_current_file_context(ssnptr), fuser, user_size);
}

static void set_file_smb_user_id(void* ssnptr, uint8_t *user_id, uint32_t user_id_size)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_smb_user_id_set(context, user_id, user_id_size);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}

static int get_file_smb_user_id(void* ssnptr, uint8_t **user_id, uint32_t *user_id_size)
{
    return file_smb_user_id_get(get_current_file_context(ssnptr), user_id, user_id_size);
}

static void set_file_smb_is_upload(void* ssnptr, uint8_t is_upload)
{
    FileContext* context = get_current_file_context(ssnptr);
    file_smb_is_upload_set(context, is_upload);
    FILE_REG_DEBUG_WRAP(printFileContext(context);)
}
#endif

static uint64_t  get_file_size(void* ssnptr)
{
    return file_size_get(get_current_file_context(ssnptr));
}

static uint64_t  get_file_processed_size(void* ssnptr)
{
    FileContext *context = get_main_file_context(ssnptr);
    if (context)
        return (context->processed_bytes);
    else
        return 0;
}

static void set_file_direction(void* ssnptr, bool upload)
{
    file_direction_set(get_current_file_context(ssnptr),upload);
}

static bool get_file_direction(void* ssnptr)
{
    return file_direction_get(get_current_file_context(ssnptr));
}

static uint8_t *get_file_sig_sha256(void* ssnptr)
{
    return file_sig_sha256_get(get_current_file_context(ssnptr));
}

static void set_file_policy_callback(File_policy_callback_func policy_func_cb)
{
    file_policy_cb = policy_func_cb;
}

/*
 * - Only accepts 1 (ONE) callback being registered.
 *
 * - Call with NULL callback to "force" (guarantee) file type identification.
 *
 * TBD: Remove per-context "file_type_enabled" checking to simplify implementation.
 *
 */
static void enable_file_type(File_type_callback_func callback)
{
    if (!file_type_id_enabled)
    {
        file_type_id_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        start_file_processing();
        LogMessage("File service: file type enabled.\n");
    }

    if ( callback == NULL )
    {
        file_type_force = true;
    }
    else if ( file_type_cb == NULL )
    {
        file_type_cb = callback;
    }
    else if ( file_type_cb != callback )
    {
        FatalError("Attempt to register multiple file_type callbacks.");
    }
}

/* set file signature callback function*/
static inline void _update_file_sig_callback(File_signature_callback_func cb)
{
    if(!file_signature_cb)
    {
        file_signature_cb = cb;
    }
    else if (file_signature_cb != cb)
    {
        WarningMessage("File service: signature callback redefined.\n");
    }
}

static void enable_file_signature(File_signature_callback_func callback)
{
    _update_file_sig_callback(callback);

    if (!file_signature_enabled)
    {
        file_signature_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        start_file_processing();
        LogMessage("File service: file signature enabled.\n");
    }
}

/* Enable file capture, also enable file signature */
static void enable_file_capture(File_signature_callback_func callback)
{
    if (!file_capture_enabled)
    {
        file_capture_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        LogMessage("File service: file capture enabled.\n");
        /* Enable file signature*/
        enable_file_signature(callback);
    }
}

#ifdef HAVE_EXTRADATA_FILE
static void enable_file_extradata()
{
    if (!file_extradata_enabled)
    {
        file_extradata_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        LogMessage("File service: file extradata enabled.\n");
    }
}
#endif

static void set_file_action_log_callback(Log_file_action_func log_func)
{
    log_file_action = log_func;
}

/* Get maximal file depth based on configuration
 * This function must be called after all file services are configured/enabled.
 */
static int64_t get_max_file_depth(void)
{
    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

    if (!file_config)
        return -1;

    if (file_config->file_depth)
        return file_config->file_depth;

    file_config->file_depth = -1;

    if (file_type_id_enabled)
    {
        file_config->file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled)
    {
        if (file_config->file_signature_depth > file_config->file_depth)
            file_config->file_depth = file_config->file_signature_depth;
    }

    if (file_config->file_depth > 0)
    {
        /*Extra byte for deciding whether file data will be over limit*/
        file_config->file_depth++;
        return (file_config->file_depth);
    }
    else
    {
        return -1;
    }
}

static FilePosition get_file_position(void *pkt)
{
    FilePosition position = SNORT_FILE_POSITION_UNKNOWN;
    Packet *p = (Packet *)pkt;

    if(ScPafEnabled())
    {
        if (PacketHasFullPDU(p))
            position = SNORT_FILE_FULL;
        else if (PacketHasStartOfPDU(p))
            position = SNORT_FILE_START;
        else if (p->packet_flags & PKT_PDU_TAIL)
            position = SNORT_FILE_END;
        else if (get_file_processed_size(p->ssnptr))
            position = SNORT_FILE_MIDDLE;
    }

    return position;
}

/*
 *  This function determines whether we shold abort PAF.  Will return
 *  true if the current packet is midstream, or unestablisted session
 *
 *  PARAMS:
 *      uint32_t - session flags passed in to callback.
 *
 *  RETURNS:
 *      true - if we should abort paf
 *      false - if we should continue using paf
 */
static bool check_paf_abort(void* ssn)
{
    uint32_t flags = session_api->get_session_flags(ssn);
    if (flags & SSNFLAG_MIDSTREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,
                "Aborting PAF because of midstream pickup.\n"));
        return true;
    }
    else if (!(flags & SSNFLAG_ESTABLISHED))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,
                "Aborting PAF because of unestablished session.\n"));
        return true;
    }
    return false;
}

static int64_t get_max_file_capture_size(void *ssn)
{
    FileConfig * file_config;
    FileContext * file_context = get_current_file_context(ssn);

    if (!file_context)
        return 0;

    file_config = file_context->file_config;
    return file_config->file_capture_max_size;
}

static uint32_t str_to_hash(uint8_t *str, int length )
{
    uint32_t a,b,c,tmp;
    int i,j,k,l;
    a = b = c = 0;
    for (i=0,j=0;i<length;i+=4)
    {
        tmp = 0;
        k = length - i;
        if (k > 4)
            k=4;

        for (l=0;l<k;l++)
        {
            tmp |= *(str + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }
    final(a,b,c);
    return c;
}
