/*
 ** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2013-2013 Sourcefire, Inc.
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
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  4.11.2013 - Initial Source Code. Hcao
 **
 **  File agent uses a separate thread to store files and also sends out
 **  to network. It uses file APIs and provides callbacks.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include "sf_types.h"
#include "spp_file.h"
#include "file_agent.h"
#include "mempool.h"
#include "sf_dynamic_preprocessor.h"
#include "circular_buffer.h"
#include "file_sha.h"
#include "sfPolicy.h"

int sockfd = 0;
int using_s3 = 0;

/*Use circular buffer to synchronize writer/reader threads*/
static CircularBuffer* file_list;

static volatile bool stop_file_capturing = false;
static volatile bool capture_thread_running = false;

static bool file_type_enabled = false;
static bool file_signature_enabled = false;
static bool file_capture_enabled = false;

pthread_t capture_thread_tid;
static pid_t capture_thread_pid;
uint64_t capture_disk_avaiable; /* bytes available */

static pthread_cond_t file_available_cond  = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t file_list_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _FILE_MESSAGE_HEADER
{
    /* All values must be in network byte order */
    uint16_t version;
    uint16_t type;
    uint32_t length;    /* Does not include the header */
    char filename[FILE_NAME_LEN];

} FileMessageHeader;

#define FILE_HEADER_VERSION   0x0001
#define FILE_HEADER_DATA      0x0009

#ifdef HAVE_S3FILE
#define KAFKA_MESSAGE_LEN 1024
#define S3_PATH "mdata/input"
#endif

static int file_agent_save_file (FileInfo *, char *);
static int file_agent_send_file (FileInfo *);
#ifdef HAVE_S3FILE
static int file_agent_send_s3(const FileInfo *,struct s3_info*);
#endif
static FileInfo* file_agent_get_file(void);
static FileInfo *file_agent_finish_file(void);
static File_Verdict file_agent_type_callback(void*, void*, uint32_t, bool,uint32_t);
static File_Verdict file_agent_signature_callback(void*, void*, uint8_t*,
        uint64_t, FileState *, bool, uint32_t);
static int file_agent_queue_file(void*, void *);
static int file_agent_init_socket(char *hostname, int portno);

/* Initialize sockets for file transfer to other host
 *
 * Args:
 *   char *hostname: host name or IP address of receiver
 *   int portno: port number of receiver
 */
int file_agent_init_socket(char *hostname, int portno)
{
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        FILE_FATAL_ERROR("File inspect: ERROR creating socket!\n");
        return -1;
    }

    /*get the address info by either host name or IP address*/

    server = gethostbyname(hostname);

    if (server == NULL)
    {
        _dpd.errMsg("File inspect: ERROR, no such host\n");
        close(sockfd);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
    {
        _dpd.errMsg("File inspect: ERROR connecting host %s: %d!\n",
                hostname, portno);
        close(sockfd);
        return -1;
    }

    _dpd.logMsg("File inspect: Connection established on host: %s, port: %d\n",
            hostname, portno);

    return 0;
}

/*Send file data to other host*/
static void file_agent_send_data(int socket_fd, const uint8_t *resp,
        uint32_t len)
{
    ssize_t numsent;
    unsigned total_len = len;
    unsigned total = 0;

    do
    {
        numsent = write(socket_fd, (*(uint8_t **)&resp) + total,
                total_len - total);
        if (!numsent)
            return;
        else if (numsent > 0)
            total += numsent;
        else if (errno != EINTR && errno != EAGAIN)
        {
            file_inspect_stats.file_transfer_failures++;
            return;
        }
    } while (total < total_len);
}

/* Process all the files in the file queue*/
#ifdef HAVE_S3FILE
static inline void file_agent_process_files(CircularBuffer *file_list,
        char *capture_dir, char *hostname, struct s3_info *s3)
#else
static inline void file_agent_process_files(CircularBuffer *file_list,
        char *capture_dir, char *hostname)
#endif
{
    while (!cbuffer_is_empty(file_list))
    {
        FileInfo *file;
        file = file_agent_get_file();

        if (file && file->sha256)
        {
            /* Save to disk */
            if (capture_dir)
                file_agent_save_file(file, capture_dir);
            /* Send to other host */
            if (hostname)
                file_agent_send_file(file);
#ifdef HAVE_S3FILE
            /* Send to S3 */
            if (s3 && s3->cluster) {
                file_agent_send_s3(file,s3);
            }
#endif
            /* Default, memory only */
        }

        file = file_agent_finish_file();

        if (file)
        {
            _dpd.fileAPI->release_file(file->file_mem);
            free(file);
        }
    }
}
/* This is the main thread for file capture,
 * either store to disk or send to network based on setting
 */
static void* FileCaptureThread(void *arg)
{
    FileInspectConf* conf = (FileInspectConf*) arg;
    char *capture_dir = NULL;
    char *hostname = NULL;
#ifdef HAVE_S3FILE
    struct s3_info s3 = {
        .bucket = NULL, .cluster = NULL,
        .access_key = NULL, .secret_key = NULL,
    };
#endif

#if defined(LINUX) && defined(SYS_gettid)
    capture_thread_pid =  syscall(SYS_gettid);
#else
    capture_thread_pid = getpid();
#endif

    capture_thread_running = true;

    capture_disk_avaiable = conf->capture_disk_size<<20;

    if (conf->capture_dir)
        capture_dir = strdup(conf->capture_dir);
    if (conf->hostname)
        hostname = strdup(conf->hostname);
#ifdef HAVE_S3FILE
    if (conf->s3.bucket)
        s3.bucket = strdup(conf->s3.bucket);
    if (conf->s3.cluster)
        s3.cluster = strdup(conf->s3.cluster);
    if (conf->s3.access_key)
        s3.access_key = strdup(conf->s3.access_key);
    if (conf->s3.secret_key)
        s3.secret_key = strdup(conf->s3.secret_key);
#endif

    while(1)
    {
#ifdef HAVE_S3FILE
        file_agent_process_files(file_list, capture_dir, hostname, &s3);
#else
        file_agent_process_files(file_list, capture_dir, hostname);
#endif

        if (stop_file_capturing)
            break;

        pthread_mutex_lock(&file_list_mutex);
        if (cbuffer_is_empty(file_list))
            pthread_cond_wait(&file_available_cond, &file_list_mutex);
        pthread_mutex_unlock(&file_list_mutex);
    }

    if (conf->capture_dir)
        free(capture_dir);
    if (conf->hostname)
        free(hostname);
#ifdef HAVE_S3FILE
    if (conf->s3.bucket)
        free(s3.bucket);
    if (conf->s3.cluster)
        free(s3.cluster);
    if (conf->s3.access_key)
        free(s3.access_key);
    if (conf->s3.secret_key)
        free(s3.secret_key);
#endif
    capture_thread_running = false;
    return NULL;
}

void file_agent_init(void *config)
{
    FileInspectConf* conf = (FileInspectConf *)config;

    /*Need to check configuration to decide whether to enable them*/

    if (conf->file_type_enabled)
    {
        _dpd.fileAPI->enable_file_type(file_agent_type_callback);
        file_type_enabled = true;
    }
    if (conf->file_signature_enabled)
    {
        _dpd.fileAPI->enable_file_signature(file_agent_signature_callback);
        file_signature_enabled = true;
    }

    if (conf->file_capture_enabled)
    {
        _dpd.fileAPI->enable_file_capture(file_agent_signature_callback);
        file_capture_enabled = true;
    }

#ifdef HAVE_EXTRADATA_FILE
    if (conf->file_extradata_enabled)
        _dpd.fileAPI->enable_file_extradata();
#endif

    if (conf->hostname)
    {
        file_agent_init_socket(conf->hostname, conf->portno);
    }
}

/* Add another thread for file capture to disk or network
 * When settings are changed, snort must be restarted to get it applied
 */
void file_agent_thread_init(struct _SnortConfig *sc, void *config)
{
    int rval;
    const struct timespec thread_sleep = { 0, 100 };
    sigset_t mask;
    FileInspectConf* conf = (FileInspectConf *)config;

    /* Spin off the file capture handler thread. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGURG);
    sigaddset(&mask, SIGVTALRM);

    pthread_sigmask(SIG_SETMASK, &mask, NULL);

#ifdef HAVE_S3FILE
    if( conf->s3.cluster && 
        (conf->s3.bucket== NULL || conf->s3.access_key == NULL
            || conf->s3.secret_key == NULL) ) {
        FILE_FATAL_ERROR("%s(%d) S3 cluster specified but no %s specified",
            conf->s3.bucket == NULL     ? "bucket" :
            conf->s3.access_key == NULL ? "access key" : "secret key");
    }

    if ( conf->s3.cluster ) {
        const S3Status init_rc = S3_initialize("s3", S3_INIT_ALL,
            conf->s3.cluster);
        if (init_rc != S3StatusOK) {
            FILE_FATAL_ERROR("Can't initialize libs3: %s",
                S3_get_status_name(init_rc));
        }

        using_s3 = 1;
    }
#endif

    file_list = cbuffer_init(conf->file_capture_queue_size);

    if(!file_list)
    {
        FILE_FATAL_ERROR("File capture: Unable to create file capture queue!");
    }

    if ((rval = pthread_create(&capture_thread_tid, NULL,
            &FileCaptureThread, conf)) != 0)
    {
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);
        FILE_FATAL_ERROR("File capture: Unable to create a "
                "processing thread: %s", strerror(rval));
    }

    while (!capture_thread_running)
        nanosleep(&thread_sleep, NULL);

    sigemptyset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
    _dpd.logMsg("File capture thread started tid=%p (pid=%u)\n",
            (void *) capture_thread_tid, capture_thread_pid);

}

/*
 * Files are queued in a list
 * Add one file to the list
 */
static int file_agent_queue_file(void* ssnptr, void *file_mem)
{
    FileInfo *finfo;
    char *sha256;

    if (cbuffer_is_full(file_list))
    {
        return -1;
    }

    finfo = calloc(1, sizeof (*finfo));

    if (!finfo)
    {
        return -1;
    }

    sha256 = (char *) _dpd.fileAPI->get_sig_sha256(ssnptr);

    if (!sha256)
    {
        free(finfo);
        return -1;
    }

    memcpy(finfo->sha256, sha256, SHA256_HASH_SIZE);
    finfo->file_mem = file_mem;
    finfo->file_size = _dpd.fileAPI->get_file_capture_size(file_mem);

    pthread_mutex_lock(&file_list_mutex);

    if(cbuffer_write(file_list, finfo))
    {
        pthread_mutex_unlock(&file_list_mutex);
        free(finfo);
        return -1;
    }

    pthread_cond_signal(&file_available_cond);
    pthread_mutex_unlock(&file_list_mutex);

    return 0;
}

/*
 * Files are queued in a list
 * Get one file from the list
 */
static FileInfo* file_agent_get_file(void)
{
    ElemType file;

    if(cbuffer_peek(file_list, &file))
    {
        return NULL;
    }

    return (FileInfo*) file;
}

/*
 * Files are queued in a list
 * Remove one file from the list
 * The file in head is removed
 */
static FileInfo* file_agent_finish_file(void)
{
    ElemType file;

    if(cbuffer_read(file_list, &file))
    {
        return NULL;
    }

    return (FileInfo*) file;
}

/*
 * writing file to the disk.
 *
 * In the case of interrupt errors, the write is retried, but only for a
 * finite number of times.
 *
 * Arguments
 *  uint8_t *: The buffer containing the data to write
 *  size_t:  The length of the data to write
 *  FILE *fh:  File handler
 *
 * Returns: None
 *
 */
static void file_agent_write(uint8_t *buf, size_t buf_len, FILE *fh)
{
    int max_retries = 3;
    size_t bytes_written = 0;
    int err;

    /* Nothing to write or nothing to write to */
    if ((buf == NULL) || (fh == NULL))
        return;

    /* writing several times */
    do
    {
        size_t bytes_left = buf_len - bytes_written;

        bytes_written += fwrite(buf + bytes_written, 1, bytes_left, fh);

        err = ferror(fh);
        if (err && (err != EINTR) && (err != EAGAIN))
        {
            break;
        }

        max_retries--;

    } while ((max_retries > 0) && (bytes_written < buf_len));

    if (bytes_written < buf_len)
    {
        _dpd.errMsg("File inspect: disk writing error - %s!\n", strerror(err));
    }
}

/* Store files on local disk
 */
static int file_agent_save_file(FileInfo *file,  char *capture_dir)
{
    FILE *fh;
    struct stat   buffer;
    char filename[FILE_NAME_LEN + 1];
    int filename_len;
    char *findex = filename;
    uint8_t *buff;
    int size;
    void *file_mem;

    filename_len = snprintf(filename, FILE_NAME_LEN, "%s", capture_dir);

    if (filename_len >= FILE_NAME_LEN )
    {
        free(file);
        return -1;
    }

    file_inspect_stats.files_to_disk_total++;

    findex += filename_len;

    filename_len = sha_to_str(file->sha256, findex,
            FILE_NAME_LEN - filename_len);

    /*File exists*/
    if(stat (filename, &buffer) == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "File exist: %s\n", filename););
        file_inspect_stats.file_duplicates_total++;
        return -1;
    }

    if (!capture_disk_avaiable)
    {
        return -1;
    }
    else if (capture_disk_avaiable < file->file_size)
    {
        capture_disk_avaiable = 0;
        _dpd.errMsg("File inspect: exceeding allocated disk size, "
                "can't store file!\n");
        return -1;
    }
    else
    {
        capture_disk_avaiable -= file->file_size;
    }

    fh = fopen(filename, "w");
    if (!fh )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Can't create file: %s\n",
                filename););
        return -1;
    }

    file_mem = file->file_mem;

    /*Check the file buffer*/
    while (file_mem)
    {
        file_mem = _dpd.fileAPI->read_file(file_mem, &buff, &size);
        /*Get file from file buffer*/
        if (!buff || !size )
        {
            file_inspect_stats.file_read_failures++;
            _dpd.logMsg("File inspect: can't read file!\n");
            return -1;
        }

        file_agent_write(buff, size, fh);
    }

    fclose(fh);

    file_inspect_stats.files_saved++;
    file_inspect_stats.file_data_to_disk += file->file_size;

    return 0;
}

/* Send file data to other host*/
static int file_agent_send_file(FileInfo *file)
{
    /*Save the file*/
    FileMessageHeader fheader;

    void *file_mem;
    uint8_t *buff;
    int size;

    if (!sockfd)
    {
        return 0;
    }

    /*Send the file name*/
    fheader.version = htons(FILE_HEADER_VERSION);
    fheader.type = htons(FILE_HEADER_DATA);
    fheader.length = htonl(file->file_size);

    memset(fheader.filename, 0, sizeof(fheader.filename));

    sha_to_str(file->sha256, fheader.filename, sizeof (fheader.filename));

    file_agent_send_data (sockfd, (uint8_t *)&fheader, sizeof(fheader));

    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "sent file: %s, with size: %d\n",
            fheader.filename, file->file_size););

    file_mem = file->file_mem;

    /*Check the file buffer*/
    while (file_mem)
    {
        file_mem = _dpd.fileAPI->read_file(file_mem, &buff, &size);
        /*Get file from file buffer*/
        if (!buff || !size )
        {
            file_inspect_stats.file_read_failures++;
            _dpd.logMsg("File inspect: can't read file!\n");
            return -1;
        }

        file_agent_send_data(sockfd, buff, size);
    }

    file_inspect_stats.files_to_host_total++;
    file_inspect_stats.file_data_to_host += file->file_size;

    return 0;
}

#ifdef HAVE_S3FILE
struct s3_transference {
    S3Status status;
    
    uint8_t *cur_buf;
    int cur_buf_size;
    int cur_buf_remaining;

    void *file_mem;
    char err[4096];
};

static size_t min_size(size_t a,size_t b){
    return a>b?b:a;
}

static void responseCompleteCallback(S3Status status,
    const S3ErrorDetails *error,void *callbackData) {

    struct s3_transference *transference = (struct s3_transference *)callbackData;
    transference->status = status;

    int len = 0;
    if (error && error->message) {
        len += snprintf(&(transference->err[len]), sizeof(transference->err) - len,
                        "  Message: %s\n", error->message);
    }
    if (error && error->resource) {
        len += snprintf(&(transference->err[len]), sizeof(transference->err) - len,
                        "  Resource: %s\n", error->resource);
    }
    if (error && error->furtherDetails) {
        len += snprintf(&(transference->err[len]), sizeof(transference->err) - len,
                        "  Further Details: %s\n", error->furtherDetails);
    }
    if (error && error->extraDetailsCount) {
        len += snprintf(&(transference->err[len]), sizeof(transference->err) - len,
                        "%s", "  Extra Details:\n");
        int i;
        for (i = 0; i < error->extraDetailsCount; i++) {
            len += snprintf(&(transference->err[len]), 
                            sizeof(transference->err) - len, "    %s: %s\n", 
                            error->extraDetails[i].name,
                            error->extraDetails[i].value);
        }
    }

}

static int putObjectDataCallback(int bufferSize, char *buffer, 
                                 void *callbackData) {
    struct s3_transference *transference = callbackData;

    if(!transference->cur_buf && transference->file_mem)
    {
        /* First call, need to load first file_mem */
        transference->file_mem = _dpd.fileAPI->read_file(
                        transference->file_mem, 
                        &transference->cur_buf, &transference->cur_buf_size);
        transference->cur_buf_remaining = transference->cur_buf_size;
    }

    if(!transference->cur_buf && !transference->file_mem)
    {
        /* Last call, returning 0 to indicate all data transferred */
        return 0;
    }

    const size_t to_transfer = min_size(bufferSize,
                                              transference->cur_buf_remaining);
    const uint8_t *cursor = transference->cur_buf 
              + (transference->cur_buf_size - transference->cur_buf_remaining);
    memcpy(buffer,cursor,to_transfer);
    transference->cur_buf_remaining -= to_transfer;

    /* Need to load next file info? */
    if(transference->cur_buf_remaining == 0)
    {
        if(transference->file_mem)
        {
            transference->file_mem = _dpd.fileAPI->read_file(
                        transference->file_mem, 
                        &transference->cur_buf, &transference->cur_buf_size);
            transference->cur_buf_remaining = transference->cur_buf_size;
        }
        else
        {
            transference->cur_buf = NULL;
            transference->cur_buf_size = 0;
        }
    }

    return to_transfer;
}

static void str_tolower(char *str,size_t str_len) {
    for(;*str;++str)
        *str = tolower(*str);
}

static int file_agent_send_s3(const FileInfo *file,struct s3_info *s3) {
    char sha256[SHA256_HASH_SIZE];
    char fsha[FILE_NAME_LEN];
    char path[FILE_NAME_LEN];

    struct s3_transference transference;
    memset(&transference,0,sizeof(transference));
    transference.file_mem = file->file_mem;

    memcpy(sha256,file->sha256,sizeof(sha256));
    sha_to_str(sha256, fsha, sizeof(fsha));
    str_tolower(fsha,sizeof(fsha));
    snprintf(path,sizeof(path),S3_PATH "/%s",fsha);

    S3BucketContext bucketContext = {
        0,
        s3->bucket,
        S3ProtocolHTTPS,
        S3UriStylePath /* or S3UriStyleVirtualHost */,
        s3->access_key,
        s3->secret_key
    };

    S3PutProperties putProperties = {
        NULL /* contentType */,
        NULL /* md5 */,
        NULL /* cacheControl */,
        NULL /* contentDispositionFilename */,
        NULL /* contentEncoding */,
        0    /* expires */,
        S3CannedAclPrivate /* cannedAcl */,
        0    /* metaPropertiesCount */,
        NULL /* metaPropertie */
    };

    S3PutObjectHandler putObjectHandler = {
        { NULL /* responsePropertiesCallback */, &responseCompleteCallback },
        &putObjectDataCallback
    };

    //do {
        S3_put_object(&bucketContext, path, file->file_size, &putProperties,
                      0, 0, &putObjectHandler, &transference );
    //}while(S3_status_is_retryable(transference.status));

    if(transference.status != S3StatusOK)
    {
        /* Extracted directly from S3 example */
        if (transference.status < S3StatusErrorAccessDenied)
        {
            _dpd.logMsg("File inspect: can't upload a file to S3: %s\n",
                S3_get_status_name(transference.status));
        }
        else 
        {
            _dpd.logMsg("File inspect: can't upload a file to S3: %s,%s\n",
                S3_get_status_name(transference.status),transference.err);
        }

        file_inspect_stats.files_to_s3_failures++;
    }
    else
    {
        file_inspect_stats.files_to_s3++;
    }
    
    return 0;
}
#endif

/* Close file agent
 * 1) stop capture thread: waiting all files queued to be captured
 * 2) free file queue
 * 3) free sha256 cache
 * 4) close socket
 * 5) close s3
 */
void file_agent_close(void)
{
    int rval;

    stop_file_capturing = true;

    pthread_mutex_lock(&file_list_mutex);
    pthread_cond_signal(&file_available_cond);
    pthread_mutex_unlock(&file_list_mutex);

    if ((rval = pthread_join(capture_thread_tid, NULL)) != 0)
    {
        FILE_FATAL_ERROR("Thread termination returned an error: %s\n",
                strerror(rval));
    }

    while(capture_thread_running)
        sleep(1);

    cbuffer_free(file_list);
    
    if (sockfd)
    {
        close(sockfd);
        sockfd = 0;
    }

#ifdef HAVE_S3FILE
    if ( using_s3 )
        S3_deinitialize();
#endif
}

/*
 * File type callback when file type is identified
 *
 * For file capture or file signature, FILE_VERDICT_PENDING must be returned
 */
static File_Verdict file_agent_type_callback(void* p, void* ssnptr,
        uint32_t file_type_id, bool upload, uint32_t file_id)
{
    file_inspect_stats.file_types_total++;
    if (file_signature_enabled || file_capture_enabled)
        return FILE_VERDICT_UNKNOWN;
    else
        return FILE_VERDICT_LOG;
}

static inline int file_agent_capture_error(FileCaptureState capture_state)
{
    if (capture_state != FILE_CAPTURE_SUCCESS)
    {
        file_inspect_stats.file_reserve_failures++;

        _dpd.logMsg("File inspect: can't reserve file!\n");
        switch(capture_state)
        {
        case FILE_CAPTURE_MIN:
            file_inspect_stats.file_capture_min++;
            break;
        case FILE_CAPTURE_MAX:
            file_inspect_stats.file_capture_max++;
            break;
        case FILE_CAPTURE_MEMCAP:
            file_inspect_stats.file_capture_memcap++;
            break;
        default:
            break;
        }
        return 1;
    }
    return 0;
}

/*
 * File signature callback when file transfer is completed
 * or capture/singature is aborted
 */
static File_Verdict file_agent_signature_callback (void* p, void* ssnptr,
        uint8_t* file_sig, uint64_t file_size, FileState *state, bool upload, uint32_t file_id)
{
    FileCaptureInfo *file_mem = NULL;
    FileCaptureState capture_state;
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;
    FileInspectConf *conf = sfPolicyUserDataGetDefault(file_config);
    uint64_t capture_file_size;

    SFSnortPacket *pkt = (SFSnortPacket*)p;

    file_inspect_stats.file_signatures_total++;

    if (conf && file_sig)
    {
        FileSigInfo *file_verdict;
        file_verdict = (FileSigInfo *)sha_table_find(conf->sig_table, file_sig);
        if (file_verdict)
        {
#if defined(DEBUG_MSGS) || defined (REG_TEST)
            static int verdict_delay = 0;
            if ((verdict_delay++) < conf->verdict_delay)
            {
                verdict = FILE_VERDICT_PENDING;
            }
            else
#endif
                verdict = file_verdict->verdict;
        }
    }

    if (!file_capture_enabled)
        return verdict;

    /* File blacklisted and we do not want to save it, since we already know
    what file is */
    if(conf->dont_save_blacklist && verdict == FILE_VERDICT_BLOCK)
        return verdict;

    /* Check whether there is any error during processing file*/
    if (state->capture_state != FILE_CAPTURE_SUCCESS)
    {
        if (state->sig_state != FILE_SIG_PROCESSING)
            file_agent_capture_error(state->capture_state);
        return verdict;
    }

    /* Reserve buffer for file capture */
    capture_state = _dpd.fileAPI->reserve_file(ssnptr, &file_mem);

    /*Check whether there is any error for the last piece of file*/
    if (file_agent_capture_error(capture_state))
    {
        return verdict;
    }

    /* Check file size */
    capture_file_size = _dpd.fileAPI->get_file_capture_size(file_mem);
    if (file_size != capture_file_size)
    {
        _dpd.logMsg("File inspect: file size error %d != %d\n",
                file_size, capture_file_size);
    }

    if(NULL != conf->sha256_cache)
    {
        /* See if we have sha256 cache configured, and if it already contains
         * the file
         *
         * sfxhash_get_node will create a new node if it does not exists, so we
         * have to know if we hit with "find_success"
         */
        const unsigned before_find_success = sfxhash_find_success(conf->sha256_cache);
        const void *sfxhash_get_rc = sfxhash_get_node(conf->sha256_cache, file_sig);
        if(NULL == sfxhash_get_rc)
        {
            _dpd.errMsg("File inspect: Can't get a node from cache!\n");
        }
        else if(sfxhash_find_success(conf->sha256_cache) == before_find_success + 1)
        {
            file_inspect_stats.file_cbuffer_duplicates_total++;
            /* Don't want to queue, so we just return */
            return verdict;
        }
    }

    /*Save the file to our file queue*/
    if (file_agent_queue_file(pkt->stream_session, file_mem) < 0)
    {
        file_inspect_stats.file_agent_memcap_failures++;
        _dpd.logMsg("File inspect: can't queue file!\n");
        return verdict;
    }

    return verdict;
}

