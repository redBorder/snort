/****************************************************************************
 * Copyright (C) 2008-2013 Sourcefire, Inc.
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
 *
 ****************************************************************************
 *
 ****************************************************************************/

#ifndef _SMB_H_
#define _SMB_H_

#ifdef HAVE_CONFIG_H
#include "config.h"  /* For WORDS_BIGENDIAN */
#endif

#include "snort_debug.h"   /* For inline */
#include "sf_types.h"

/********************************************************************
 * Macros
 ********************************************************************/
#define NBSS_SESSION_TYPE__MESSAGE            0x00
#define NBSS_SESSION_TYPE__REQUEST            0x81
#define NBSS_SESSION_TYPE__POS_RESPONSE       0x82
#define NBSS_SESSION_TYPE__NEG_RESPONSE       0x83
#define NBSS_SESSION_TYPE__RETARGET_RESPONSE  0x84
#define NBSS_SESSION_TYPE__KEEP_ALIVE         0x85

// SMB dialects
#define SMB_DIALECT_PCLAN10         "PCLAN1.0"  // Core Protocol
#define SMB_DIALECT_PC_NET_PROG10   "PC NETWORK PROGRAM 1.0" // Core Protocol
#define SMB_DIALECT_XENIX11         "xenix1.1"  // Xenix Extensions
#define SMB_DIALECT_XENIX_CORE      "XENIX CORE"  // Xenix Extensions
#define SMB_DIALECT_MS_NET103       "MICROSOFT NETWORKS 1.03"  // CorePlus
#define SMB_DIALECT_LANMAN10        "LANMAN1.0"  // LAN Manager 1.0
#define SMB_DIALECT_MS_NET30        "MICROSOFT NETWORKS 3.0"   // DOS LAN Manager 1.0
#define SMB_DIALECT_WIN_FOR_WKGS31a "Windows for Workgroups 3.1a"  // Not documented in MS-CIFS but always used
#define SMB_DIALECT_LANMAN12        "LANMAN1.2"  // LAN Manager 1.2
#define SMB_DIALECT_DOS_LM12X002    "DOS LM1.2X002"  // DOS LAN Manager 2.0
#define SMB_DIALECT_LM12X002        "LM1.2X002"  // LAN Manager 2.0
#define SMB_DIALECT_DOS_LANMAN21    "DOS LANMAN2.1"  // DOS LAN Manager 2.1
#define SMB_DIALECT_LANMAN21        "LANMAN2.1"  // LAN Manager 2.1
#define SMB_DIALECT_SAMBA           "Samba"  // Some Samba specific thing
#define SMB_DIALECT_NT_LANMAN10     "NT LANMAN 1.0"  // Only seen with Samba
#define SMB_DIALECT_NT_LM_012       "NT LM 0.12"  // NT LAN Manager
#define SMB_DIALECT_SMB_2002        "SMB 2.002"  // SMB 2.002
#define SMB_DIALECT_SMB_212         "SMB 2.???"  // SMB 2.1 or 2.2

#define SMB_FLG__TYPE  0x80
#define SMB_TYPE__REQUEST   0
#define SMB_TYPE__RESPONSE  1

#define SMB_FLG2__UNICODE      0x8000
#define SMB_FLG2__NT_CODES     0x4000

#define SMB_NT_STATUS_SEVERITY__SUCCESS        0
#define SMB_NT_STATUS_SEVERITY__INFORMATIONAL  1
#define SMB_NT_STATUS_SEVERITY__WARNING        2
#define SMB_NT_STATUS_SEVERITY__ERROR          3

#define SMB_NT_STATUS__SUCCESS                0x00000000
#define SMB_NT_STATUS__INVALID_DEVICE_REQUEST 0xc0000010 
#define SMB_NT_STATUS__PIPE_BROKEN            0xc000014b 
#define SMB_NT_STATUS__PIPE_DISCONNECTED      0xc00000b0

#define SMB_ERROR_CLASS__SUCCESS  0x00
#define SMB_ERROR_CLASS__ERRDOS   0x01
#define SMB_ERROR_CLASS__ERRSRV   0x02
#define SMB_ERROR_CLASS__ERRHRD   0x03
#define SMB_ERROR_CLASS__ERRXOS   0x04
#define SMB_ERROR_CLASS__ERRMX1   0xe1
#define SMB_ERROR_CLASS__ERRMX2   0xe2
#define SMB_ERROR_CLASS__ERRMX3   0xe3
#define SMB_ERROR_CLASS__ERRCMD   0xff

#define SMB_ERRDOS__BAD_PIPE            0x00e6
#define SMB_ERRDOS__PIPE_NOT_CONNECTED  0x00e9
#define SMB_ERRDOS__MORE_DATA           0x00ea


/* SMB formats (smb_fmt) Dialect, Pathname and ASCII are all
 * NULL terminated ASCII strings unless Unicode is specified
 * in the NT LM 1.0 SMB header in which case they are NULL
 * terminated unicode strings
 */
#define SMB_FMT__DATA_BLOCK  1
#define SMB_FMT__DIALECT     2
#define SMB_FMT__ASCII       4

static inline bool SmbFmtDataBlock(uint8_t fmt)
{
    return fmt == SMB_FMT__DATA_BLOCK ? true : false;
}

static inline bool SmbFmtDialect(uint8_t fmt)
{
    return fmt == SMB_FMT__DIALECT ? true : false;
}

static inline bool SmbFmtAscii(uint8_t fmt)
{
    return fmt == SMB_FMT__ASCII ? true : false;
}

/* SMB command codes */
#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_MPX_SECONDARY 0x1F
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F
#define SMB_COM_NEW_FILE_SIZE 0x30
#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_SECURITY_PACKAGE_ANDX 0x7E
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_FIND_CLOSE 0x84
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_NT_RENAME 0xA5
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3
#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA
#define SMB_COM_INVALID 0xFE
#define SMB_COM_NO_ANDX_COMMAND 0xFF

#define SMB_MAX_NUM_COMS   256

/* Size of word count field + Word count * 2 bytes + Size of byte count field */
#define SMB_COM_SIZE(wct)  (sizeof(uint8_t) + ((wct) * sizeof(uint16_t)) + sizeof(uint16_t))

/********************************************************************
 * Enums
 ********************************************************************/
typedef enum _SmbAndXCom
{
    SMB_ANDX_COM__NONE,
    SMB_ANDX_COM__OPEN_ANDX,
    SMB_ANDX_COM__READ_ANDX,
    SMB_ANDX_COM__WRITE_ANDX,
    SMB_ANDX_COM__TREE_CONNECT_ANDX,
    SMB_ANDX_COM__SESSION_SETUP_ANDX,
    SMB_ANDX_COM__LOGOFF_ANDX,
    SMB_ANDX_COM__NT_CREATE_ANDX,
    SMB_ANDX_COM__MAX

} SmbAndXCom;

typedef enum _SmbTransactionSubcommand
{
    TRANS_UNKNOWN_0000             = 0x0000,
    TRANS_SET_NMPIPE_STATE         = 0x0001,
    TRANS_UNKNOWN_0002             = 0x0002,
    TRANS_UNKNOWN_0003             = 0x0003,
    TRANS_UNKNOWN_0004             = 0x0004,
    TRANS_UNKNOWN_0005             = 0x0005,
    TRANS_UNKNOWN_0006             = 0x0006,
    TRANS_UNKNOWN_0007             = 0x0007,
    TRANS_UNKNOWN_0008             = 0x0008,
    TRANS_UNKNOWN_0009             = 0x0009,
    TRANS_UNKNOWN_000A             = 0x000A,
    TRANS_UNKNOWN_000B             = 0x000B,
    TRANS_UNKNOWN_000C             = 0x000C,
    TRANS_UNKNOWN_000D             = 0x000D,
    TRANS_UNKNOWN_000E             = 0x000E,
    TRANS_UNKNOWN_000F             = 0x000F,
    TRANS_UNKNOWN_0010             = 0x0010,
    TRANS_RAW_READ_NMPIPE          = 0x0011,
    TRANS_UNKNOWN_0012             = 0x0012,
    TRANS_UNKNOWN_0013             = 0x0013,
    TRANS_UNKNOWN_0014             = 0x0014,
    TRANS_UNKNOWN_0015             = 0x0015,
    TRANS_UNKNOWN_0016             = 0x0016,
    TRANS_UNKNOWN_0017             = 0x0017,
    TRANS_UNKNOWN_0018             = 0x0018,
    TRANS_UNKNOWN_0019             = 0x0019,
    TRANS_UNKNOWN_001A             = 0x001A,
    TRANS_UNKNOWN_001B             = 0x001B,
    TRANS_UNKNOWN_001C             = 0x001C,
    TRANS_UNKNOWN_001D             = 0x001D,
    TRANS_UNKNOWN_001E             = 0x001E,
    TRANS_UNKNOWN_001F             = 0x001F,
    TRANS_UNKNOWN_0020             = 0x0020,
    TRANS_QUERY_NMPIPE_STATE       = 0x0021,
    TRANS_QUERY_NMPIPE_INFO        = 0x0022,
    TRANS_PEEK_NMPIPE              = 0x0023,
    TRANS_UNKNOWN_0024             = 0x0024,
    TRANS_UNKNOWN_0025             = 0x0025,
    TRANS_TRANSACT_NMPIPE          = 0x0026,
    TRANS_UNKNOWN_0027             = 0x0027,
    TRANS_UNKNOWN_0028             = 0x0028,
    TRANS_UNKNOWN_0029             = 0x0029,
    TRANS_UNKNOWN_002A             = 0x002A,
    TRANS_UNKNOWN_002B             = 0x002B,
    TRANS_UNKNOWN_002C             = 0x002C,
    TRANS_UNKNOWN_002D             = 0x002D,
    TRANS_UNKNOWN_002E             = 0x002E,
    TRANS_UNKNOWN_002F             = 0x002F,
    TRANS_UNKNOWN_0030             = 0x0030,
    TRANS_RAW_WRITE_NMPIPE         = 0x0031,
    TRANS_UNKNOWN_0032             = 0x0032,
    TRANS_UNKNOWN_0033             = 0x0033,
    TRANS_UNKNOWN_0034             = 0x0034,
    TRANS_UNKNOWN_0035             = 0x0035,
    TRANS_READ_NMPIPE              = 0x0036,
    TRANS_WRITE_NMPIPE             = 0x0037,
    TRANS_UNKNOWN_0038             = 0x0038,
    TRANS_UNKNOWN_0039             = 0x0039,
    TRANS_UNKNOWN_003A             = 0x003A,
    TRANS_UNKNOWN_003B             = 0x003B,
    TRANS_UNKNOWN_003C             = 0x003C,
    TRANS_UNKNOWN_003D             = 0x003D,
    TRANS_UNKNOWN_003E             = 0x003E,
    TRANS_UNKNOWN_003F             = 0x003F,
    TRANS_UNKNOWN_0040             = 0x0040,
    TRANS_UNKNOWN_0041             = 0x0041,
    TRANS_UNKNOWN_0042             = 0x0042,
    TRANS_UNKNOWN_0043             = 0x0043,
    TRANS_UNKNOWN_0044             = 0x0044,
    TRANS_UNKNOWN_0045             = 0x0045,
    TRANS_UNKNOWN_0046             = 0x0046,
    TRANS_UNKNOWN_0047             = 0x0047,
    TRANS_UNKNOWN_0048             = 0x0048,
    TRANS_UNKNOWN_0049             = 0x0049,
    TRANS_UNKNOWN_004A             = 0x004A,
    TRANS_UNKNOWN_004B             = 0x004B,
    TRANS_UNKNOWN_004C             = 0x004C,
    TRANS_UNKNOWN_004D             = 0x004D,
    TRANS_UNKNOWN_004E             = 0x004E,
    TRANS_UNKNOWN_004F             = 0x004F,
    TRANS_UNKNOWN_0050             = 0x0050,
    TRANS_UNKNOWN_0051             = 0x0051,
    TRANS_UNKNOWN_0052             = 0x0052,
    TRANS_WAIT_NMPIPE              = 0x0053,
    TRANS_CALL_NMPIPE              = 0x0054,
    TRANS_SUBCOM_MAX               = 0x0055

} SmbTransactionSubcommand;

typedef enum _SmbTransaction2Subcommand
{
    TRANS2_OPEN2                        = 0x0000,
    TRANS2_FIND_FIRST2                  = 0x0001,
    TRANS2_FIND_NEXT2                   = 0x0002,
    TRANS2_QUERY_FS_INFORMATION         = 0x0003,
    TRANS2_SET_FS_INFORMATION           = 0x0004,
    TRANS2_QUERY_PATH_INFORMATION       = 0x0005,
    TRANS2_SET_PATH_INFORMATION         = 0x0006,
    TRANS2_QUERY_FILE_INFORMATION       = 0x0007,
    TRANS2_SET_FILE_INFORMATION         = 0x0008,
    TRANS2_FSCTL                        = 0x0009,
    TRANS2_IOCTL2                       = 0x000A,
    TRANS2_FIND_NOTIFY_FIRST            = 0x000B,
    TRANS2_FIND_NOTIFY_NEXT             = 0x000C,
    TRANS2_CREATE_DIRECTORY             = 0x000D,
    TRANS2_SESSION_SETUP                = 0x000E,
    TRANS2_UNKNOWN_000F                 = 0x000F,
    TRANS2_GET_DFS_REFERRAL             = 0x0010,
    TRANS2_REPORT_DFS_INCONSISTENCY     = 0x0011,
    TRANS2_SUBCOM_MAX                   = 0x0012

} SmbTransaction2Subcommand;

typedef enum _SmbNtTransactSubcommand
{
    NT_TRANSACT_UNKNOWN_0000            = 0x0000,
    NT_TRANSACT_CREATE                  = 0x0001,
    NT_TRANSACT_IOCTL                   = 0x0002,
    NT_TRANSACT_SET_SECURITY_DESC       = 0x0003,
    NT_TRANSACT_NOTIFY_CHANGE           = 0x0004,
    NT_TRANSACT_RENAME                  = 0x0005,
    NT_TRANSACT_QUERY_SECURITY_DESC     = 0x0006,
    NT_TRANSACT_SUBCOM_MAX              = 0x0007

} SmbNtTransactSubcommand;


/********************************************************************
 * Structures and inline accessor functions
 ********************************************************************/
/* Pack the structs since we'll be laying them on top of packet data */
#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#else
#pragma pack(1)
#endif

/********************************************************************
 * NetBIOS Session Service header
 ********************************************************************/
typedef struct _NbssHdr
{
    uint8_t  type;
    uint8_t  flags;  /* Treat flags as the upper byte to length */
    uint16_t length;

} NbssHdr;

static inline uint32_t NbssLen(const NbssHdr *nb)
{
    /* Treat first bit of flags as the upper byte to length */
    return ((nb->flags & 0x01) << 16) | ntohs(nb->length);
}

static inline uint8_t NbssType(const NbssHdr *nb)
{
    return nb->type;
}

/********************************************************************
 * SMB headers
 *
 * Length of header is always 32 but meaning of fields differs
 *  according to dialect
 ********************************************************************/
typedef struct _SmbCoreHdr
{
    uint8_t  smb_idf[4];  /* contains 0xFF, 'SMB' */
    uint8_t  smb_com;     /* command code */
    uint8_t  smb_rcls;    /* error code class */
    uint8_t  smb_reh;     /* reserved (contains AH if DOS INT-24 ERR) */
    uint16_t smb_err;     /* error code */
    uint8_t  smb_reb;     /* reserved */
    uint16_t smb_res[7];  /* reserved */
    uint16_t smb_tid;     /* tree id # */
    uint16_t smb_pid;     /* caller's process id # */
    uint16_t smb_uid;     /* user id # */
    uint16_t smb_mid;     /* multiplex id # */
#if 0
    uint8_t  smb_wct;     /* count of parameter words */
    uint16_t smb_vwv[];   /* variable # words of params */
    uint16_t smb_bcc;     /* # bytes of data following */
    uint8_t  smb_data[];  /* data bytes */
#endif
} SmbCoreHdr;

typedef struct _SmbLm10Hdr
{
    uint8_t  smb_idf[4];    /* contains 0xFF, 'SMB' */
    uint8_t  smb_com;       /* command code */
    uint8_t  smb_rcls;      /* error class */
    uint8_t  smb_reh;       /* reserved for future */
    uint16_t smb_err;       /* error code */
    uint8_t  smb_flg;       /* flags */
    uint16_t smb_res[7];    /* reserved for future */
    uint16_t smb_tid;       /* authenticated resource identifier */
    uint16_t smb_pid;       /* caller's process id */
    uint16_t smb_uid;       /* unauthenticated user id */
    uint16_t smb_mid;       /* multiplex id */
#if 0
    uint8_t  smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_vwv[];     /* variable number of 16-bit words */
    uint16_t smb_bcc;       /* count of bytes that follow */
    uint8_t  smb_buf[];     /* variable number of bytes */
#endif
} SmbLm10Hdr;

typedef struct _SmbLm20Hdr
{
    uint8_t  smb_idf[4];    /* contains 0xFF,’SMB’ */
    uint8_t  smb_com;       /* command code */
    uint8_t  smb_rcls;      /* error class */
    uint8_t  smb_reh;       /* reserved for future */
    uint16_t smb_err;       /* error code */
    uint8_t  smb_flg;       /* flags */
    uint16_t smb_flg2;      /* flags */
    uint16_t smb_res[6];    /* reserved for future */
    uint16_t smb_tid;       /* authenticated resource identifier */
    uint16_t smb_pid;       /* caller’s process id */
    uint16_t smb_uid;       /* authenticated user id */
    uint16_t smb_mid;       /* multiplex id */
#if 0
    uint8_t  smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_vwv[];     /* variable number of 16-bit words */
    uint16_t smb_bcc;       /* count of bytes that follow */
    uint8_t  smb_buf[];     /* variable number of bytes */
#endif
} SmbLm20Hdr;

typedef struct _SmbNtHdr
{
    uint8_t  smb_idf[4];            /* contains 0xFF, 'SMB' */
    uint8_t  smb_com;               /* command code */
    union {
        struct {
            uint8_t  smb_class;     /* dos error class */
            uint8_t  smb_res;       /* reserved for future */
            uint16_t smb_code;      /* dos error code */
        } smb_status;
        uint32_t nt_status;         /* nt status */
    } smb_status;
    uint8_t  smb_flg;               /* flags */
    uint16_t smb_flg2;              /* flags */
    uint16_t smb_res[6];            /* reserved for future */
    uint16_t smb_tid;               /* tree id */
    uint16_t smb_pid;               /* caller's process id */
    uint16_t smb_uid;               /* authenticated user id */
    uint16_t smb_mid;               /* multiplex id */
#if 0
    uint8_t  smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_vwv[];     /* variable number of 16-bit words */
    uint16_t smb_bcc;       /* count of bytes that follow */
    uint8_t  smb_buf[];     /* variable number of bytes */
#endif
} SmbNtHdr;

static inline uint16_t SmbNtohs(const uint16_t *ptr)
{
    uint16_t value;

    if (ptr == NULL)
        return 0;

#ifdef WORDS_MUSTALIGN
    value = *((uint8_t *)ptr) << 8 | *((uint8_t *)ptr + 1);
#else
    value = *ptr;
#endif  /* WORDS_MUSTALIGN */

#ifdef WORDS_BIGENDIAN
    return ((value & 0xff00) >> 8) | ((value & 0x00ff) << 8);
#else
    return value;
#endif  /* WORDS_BIGENDIAN */
}

static inline uint16_t SmbHtons(const uint16_t *ptr)
{
    return SmbNtohs(ptr);
}

static inline uint32_t SmbNtohl(const uint32_t *ptr)
{
    uint32_t value;

    if (ptr == NULL)
        return 0;

#ifdef WORDS_MUSTALIGN
    value = *((uint8_t *)ptr)     << 24 | *((uint8_t *)ptr + 1) << 16 |
            *((uint8_t *)ptr + 2) << 8  | *((uint8_t *)ptr + 3);
#else
    value = *ptr;
#endif  /* WORDS_MUSTALIGN */

#ifdef WORDS_BIGENDIAN
    return ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8)  |
           ((value & 0x0000ff00) << 8)  | ((value & 0x000000ff) << 24);
#else
    return value;
#endif  /* WORDS_BIGENDIAN */
}

static inline uint32_t SmbHtonl(const uint32_t *ptr)
{
    return SmbNtohl(ptr);
}

static inline uint32_t SmbId(const SmbNtHdr *hdr)
{
#ifdef WORDS_MUSTALIGN
    uint8_t *idf = (uint8_t *)hdr->smb_idf;
    return *idf << 24 | *(idf + 1) << 16 | *(idf + 2) << 8 | *(idf + 3);
#else
    return ntohl(*((uint32_t *)hdr->smb_idf));
#endif  /* WORDS_MUSTALIGN */
}

static inline uint8_t SmbCom(const SmbNtHdr *hdr)
{
    return hdr->smb_com;
}

#if 0   // So no compiler warning for being unused
// Refers to older pre-NT status codes
static bool SmbStatusSmbCodes(const SmbNtHdr *hdr)
{
    if (SmbNtohs(&hdr->smb_flg2) & SMB_FLG2__NT_CODES)
        return false;
    return true;
}
#endif

static bool SmbStatusNtCodes(const SmbNtHdr *hdr)
{
    if (SmbNtohs(&hdr->smb_flg2) & SMB_FLG2__NT_CODES)
        return true;
    return false;
}

static inline uint32_t SmbNtStatus(const SmbNtHdr *hdr)
{
    return SmbNtohl(&hdr->smb_status.nt_status);
}

static inline uint8_t SmbNtStatusSeverity(const SmbNtHdr *hdr)
{
    return (uint8_t)(SmbNtStatus(hdr) >> 30);
}

static inline uint8_t SmbStatusClass(const SmbNtHdr *hdr)
{
    return hdr->smb_status.smb_status.smb_class;
}

static inline uint16_t SmbStatusCode(const SmbNtHdr *hdr)
{
    return SmbNtohs(&hdr->smb_status.smb_status.smb_code);
}

// This function is obviously deficient.  Need to do a lot more
// testing, research and reading MS-CIFS, MS-SMB and MS-ERREF.
static inline bool SmbError(const SmbNtHdr *hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        /* Nt status codes are being used.  First 2 bits indicate
         * severity. */
        switch (SmbNtStatusSeverity(hdr))
        {
            case SMB_NT_STATUS_SEVERITY__SUCCESS:
            case SMB_NT_STATUS_SEVERITY__INFORMATIONAL:
            case SMB_NT_STATUS_SEVERITY__WARNING:
                return false;
            case SMB_NT_STATUS_SEVERITY__ERROR:
            default:
                break;
        }
    }
    else
    {
        switch (SmbStatusClass(hdr))
        {
            case SMB_ERROR_CLASS__SUCCESS:
                return false;
            case SMB_ERROR_CLASS__ERRDOS:
                if (SmbStatusCode(hdr) == SMB_ERRDOS__MORE_DATA)
                    return false;
                break;
            case SMB_ERROR_CLASS__ERRSRV:
            case SMB_ERROR_CLASS__ERRHRD:
            case SMB_ERROR_CLASS__ERRCMD:
            default:
                break;
        }
    }

    return true;
}

static inline bool SmbBrokenPipe(const SmbNtHdr *hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        uint32_t nt_status = SmbNtStatus(hdr);
        if ((nt_status == SMB_NT_STATUS__PIPE_BROKEN)
                || (nt_status == SMB_NT_STATUS__PIPE_DISCONNECTED))
            return true;
    }
    else
    {
        if (SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRDOS)
        {
            uint16_t smb_status = SmbStatusCode(hdr);
            if ((smb_status == SMB_ERRDOS__BAD_PIPE)
                    || (smb_status == SMB_ERRDOS__PIPE_NOT_CONNECTED))
                return true;
        }
    }

    return false;
}

static inline int SmbType(const SmbNtHdr *hdr)
{
    if (hdr->smb_flg & SMB_FLG__TYPE)
        return SMB_TYPE__RESPONSE;

    return SMB_TYPE__REQUEST;
}

static inline bool SmbUnicode(const SmbNtHdr *hdr)
{
    return (SmbNtohs(&hdr->smb_flg2) & SMB_FLG2__UNICODE) ? true : false;
}

static inline uint16_t SmbUid(const SmbNtHdr *hdr)
{
    return SmbNtohs(&hdr->smb_uid);
}

static inline uint16_t SmbTid(const SmbNtHdr *hdr)
{
    return SmbNtohs(&hdr->smb_tid);
}

// PidHigh doesn't seem to matter ever
static inline uint16_t SmbPid(const SmbNtHdr *hdr)
{
    return SmbNtohs(&hdr->smb_pid);
}

static inline uint16_t SmbMid(const SmbNtHdr *hdr)
{
    return SmbNtohs(&hdr->smb_mid);
}

/********************************************************************
 * Common fields to all commands
 ********************************************************************/
typedef struct _SmbCommon
{
    uint8_t smb_wct;

} SmbCommon;

static inline uint8_t SmbWct(const SmbCommon *hdr)
{
    return hdr->smb_wct;
}

/* Common fields to all AndX commands */
typedef struct _SmbAndXCommon
{
    uint8_t  smb_wct;
    uint8_t  smb_com2;     /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;     /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */

} SmbAndXCommon;

static inline uint8_t SmbAndXCom2(const SmbAndXCommon *andx)
{
    return andx->smb_com2;
}

static inline uint16_t SmbAndXOff2(const SmbAndXCommon *andx)
{
    return SmbNtohs(&andx->smb_off2);
}

/* For server empty respones indicating client error or interim response */
typedef struct _SmbEmptyCom
{
    uint8_t  smb_wct;    /* value = 0 */
    uint16_t smb_bcc;    /* value = 0 */

} SmbEmptyCom;

static inline uint8_t SmbEmptyComWct(const SmbEmptyCom *ec)
{
    return ec->smb_wct;
}

static inline uint16_t SmbEmptyComBcc(const SmbEmptyCom *ec)
{
    return SmbNtohs(&ec->smb_bcc);
}

static inline uint16_t SmbBcc(const uint8_t *ptr, uint16_t com_size)
{
    /* com_size must be at least the size of the command encasing */
    if (com_size < sizeof(SmbEmptyCom))
        return 0;

    return SmbNtohs((uint16_t *)(ptr + com_size - sizeof(uint16_t)));
}

/********************************************************************
 * SMB_COM_OPEN
 ********************************************************************/
typedef struct _SmbOpenReq   /* smb_wct = 2 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_mode;    /* r/w/share */
    uint16_t smb_attr;    /* attribute */
    uint16_t smb_bcc;     /* min = 2 */

#if 0
    uint8_t  smb_fmt;     /* ASCII -- 04 */
    uint8_t  smb_buf[];   /* file pathname */
#endif
} SmbOpenReq;

typedef struct _SmbOpenResp   /* smb_wct = 7 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_attr;    /* attribute */
    uint16_t smb_tlow;    /* time1 low */
    uint16_t smb_thigh;   /* time1 high */
    uint16_t smb_fslow;   /* file size low */
    uint16_t smb_fshigh;  /* file size high */
    uint16_t smb_access;  /* access allowed */
    uint16_t smb_bcc;     /* must be 0 */

} SmbOpenResp;

static inline uint16_t SmbOpenRespFid(const SmbOpenResp *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_CREATE
 ********************************************************************/
typedef struct _SmbCreateReq   /* smb_wct = 3 */
{
    uint8_t  smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
#if 0
    uint8_t  smb_fmt;     /* ASCII -- 04 */
    uint8_t  smb_buf[];   /* file pathname */
#endif
} SmbCreateReq;

typedef struct _SmbCreateResp   /* smb_wct = 1 */
{
    uint8_t  smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;

} SmbCreateResp;

static inline uint16_t SmbCreateRespFid(const SmbCreateResp *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_CLOSE
 ********************************************************************/
typedef struct _SmbCloseReq   /* smb_wct = 3 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_tlow;    /* time low */
    uint16_t smb_thigh;   /* time high */
    uint16_t smb_bcc;     /* must be 0 */

} SmbCloseReq;

typedef struct _SmbCloseResp   /* smb_wct = 0 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* must be 0 */

} SmbCloseResp;

static inline uint16_t SmbCloseReqFid(const SmbCloseReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

/********************************************************************
 * SMB_COM_RENAME
 ********************************************************************/
typedef struct _SmbRenameReq  /* smb_wct = 1 */
{
    uint8_t  smb_wct;
    uint16_t smb_attrs;
    uint16_t smb_bcc;
#if 0
    uint8_t  smb_fmt;       /* ASCII -- 04 */
    uint8_t  smb_buf[];     /* old filename */
    uint8_t  smb_fmt2;      /* ASCII -- 04 */
    uint8_t  smb_buf2[];    /* new filename */
#endif
} SmbRenameReq;

typedef struct _SmbRenameResp  /* smb_wct = 0 */
{
    uint8_t  smb_wct;
    uint16_t smb_bcc;

} SmbRenameResp;

/********************************************************************
 * SMB_COM_READ
 ********************************************************************/
typedef struct _SmbReadReq   /* smb_wct = 5 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint32_t smb_off;     /* offset */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* must be 0 */

} SmbReadReq;

typedef struct _SmbReadResp   /* smb_wct = 5 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_res[4];  /* reserved (MBZ) */
    uint16_t smb_bcc;     /* length of data + 3 */

#if 0
    uint8_t  smb_fmt;     /* Data Block -- 01 */
    uint16_t smb_dlen;    /* length of data */
    uint8_t  smb_buf[];   /* data */
#endif
} SmbReadResp;

static inline uint16_t SmbReadReqFid(const SmbReadReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbReadRespCount(const SmbReadResp *resp)
{
    return SmbNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_WRITE
 ********************************************************************/
typedef struct _SmbWriteReq   /* smb_wct = 5 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint16_t smb_olow;    /* offset low */
    uint16_t smb_ohigh;   /* offset high */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* length of data + 3 */

#if 0
    uint16_t smb_fmt;     /* Data Block -- 01 */
    uint16_t smb_dlen;    /* length of data */
    uint8_t smb_buf[];    /* data */
#endif
} SmbWriteReq;

static inline uint16_t SmbWriteReqFid(const SmbWriteReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbWriteReqCount(const SmbWriteReq *req)
{
    return SmbNtohs(&req->smb_cnt);
}

typedef struct _SmbWriteResp   /* smb_wct = 1 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */

} SmbWriteResp;

static inline uint16_t SmbWriteRespCount(const SmbWriteResp *resp)
{
    return SmbNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_CREATE_NEW
 ********************************************************************/
typedef struct _SmbCreateNewReq   /* smb_wct = 3 */
{
    uint8_t  smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
#if 0
    uint8_t  smb_fmt;     /* ASCII -- 04 */
    uint8_t  smb_buf[];   /* file pathname */
#endif
} SmbCreateNewReq;

typedef struct _SmbCreateNewResp   /* smb_wct = 1 */
{
    uint8_t  smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;

} SmbCreateNewResp;

static inline uint16_t SmbCreateNewRespFid(const SmbCreateNewResp *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_WRITE_AND_UNLOCK
 ********************************************************************/
typedef struct _SmbWriteAndUnlockReq
{
    uint8_t  smb_wct;
    uint16_t smb_fid;
    uint16_t smb_cnt;
    uint32_t smb_write_offset;
    uint16_t smb_estimate_of_remaining;
    uint16_t smb_bcc;
#if 0
    uint16_t smb_fmt;     /* Data Block -- 01 */
    uint16_t smb_dlen;    /* length of data */
    uint8_t smb_buf[];    /* data */
#endif
} SmbWriteAndUnlockReq;

typedef struct _SmbWriteAndUnlockResp   /* smb_wct = 1 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */

} SmbWriteAndUnlockResp;

static inline uint16_t SmbWriteAndUnlockReqFid(const SmbWriteAndUnlockReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbWriteAndUnlockReqCount(const SmbWriteAndUnlockReq *req)
{
    return SmbNtohs(&req->smb_cnt);
}

/********************************************************************
 * SMB_COM_READ_RAW
 ********************************************************************/
typedef struct _SmbReadRawReq   /* smb_wct = 8 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return (max 65,535) */
    uint16_t smb_mincnt;     /* min number of bytes to return (normally 0) */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */

} SmbReadRawReq;

typedef struct _SmbReadRawExtReq   /* smb_wct = 10 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return (max 65,535) */
    uint16_t smb_mincnt;     /* min number of bytes to return (normally 0) */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd;       /* reserved */
    uint32_t smb_off_high;   /* high offset in file to begin write */
    uint16_t smb_bcc;        /* value = 0 */

} SmbReadRawExtReq;

/* Read Raw response is raw data wrapped in NetBIOS header */

static inline uint16_t SmbReadRawReqFid(const SmbReadRawReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

/********************************************************************
 * SMB_COM_WRITE_RAW
 ********************************************************************/
typedef struct _SmbWriteRawReq
{
    uint8_t  smb_wct;      /* value = 12 */
    uint16_t smb_fid;      /* file handle */
    uint16_t smb_tcount;   /* total bytes (including this buf, 65,535 max ) */
    uint16_t smb_rsvd;     /* reserved */
    uint32_t smb_offset;   /* offset in file to begin write */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;    /* write mode:
                              bit0 - complete write to disk and send final result response
                              bit1 - return smb_remaining (pipes/devices only) */
    uint32_t smb_rsvd2;    /* reserved */
    uint16_t smb_dsize;    /* number of data bytes this buffer (min value = 0) */
    uint16_t smb_doff;     /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];    /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];  /* data bytes (* = value of smb_dsize) */
#endif
} SmbWriteRawReq;

typedef struct _SmbWriteRawExtReq
{
    uint8_t  smb_wct;      /* value = 14 */
    uint16_t smb_fid;      /* file handle */
    uint16_t smb_tcount;   /* total bytes (including this buf, 65,535 max ) */
    uint16_t smb_rsvd;     /* reserved */
    uint32_t smb_offset;   /* offset in file to begin write */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;    /* write mode:
                              bit0 - complete write to disk and send final result response
                              bit1 - return smb_remaining (pipes/devices only) */
    uint32_t smb_rsvd2;    /* reserved */
    uint16_t smb_dsize;    /* number of data bytes this buffer (min value = 0) */
    uint16_t smb_doff;     /* offset (from start of SMB hdr) to data bytes */
    uint32_t smb_off_high; /* high offset in file to begin write */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];    /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];  /* data bytes (* = value of smb_dsize) */
#endif
} SmbWriteRawExtReq;

typedef struct _SmbWriteRawInterimResp
{
    uint8_t  smb_wct;        /* value = 1 */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint16_t smb_bcc;        /* value = 0 */

} SmbWriteRawInterimResp;

static inline uint16_t SmbWriteRawReqTotalCount(const SmbWriteRawReq *req)
{
    return SmbNtohs(&req->smb_tcount);
}

static inline bool SmbWriteRawReqWriteThrough(const SmbWriteRawReq *req)
{
    return SmbNtohs(&req->smb_wmode) & 0x0001;
}

static inline uint16_t SmbWriteRawReqFid(const SmbWriteRawReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbWriteRawReqDataOff(const SmbWriteRawReq *req)
{
    return SmbNtohs(&req->smb_doff);
}

static inline uint16_t SmbWriteRawReqDataCnt(const SmbWriteRawReq *req)
{
    return SmbNtohs(&req->smb_dsize);
}

static inline uint16_t SmbWriteRawInterimRespRemaining(const SmbWriteRawInterimResp *resp)
{
    return SmbNtohs(&resp->smb_remaining);
}

/********************************************************************
 * SMB_COM_WRITE_COMPLETE - final response to an SMB_COM_WRITE_RAW
 ********************************************************************/
typedef struct _SmbWriteCompleteResp
{
    uint8_t  smb_wct;    /* value = 1 */
    uint16_t smb_count;  /* total number of bytes written */
    uint16_t smb_bcc;    /* value = 0 */

} SmbWriteCompleteResp;

static inline uint16_t SmbWriteCompleteRespCount(const SmbWriteCompleteResp *resp)
{
    return SmbNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_TRANSACTION
 ********************************************************************/
typedef struct _SmbTransactionReq   /* smb_wct = 14 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 2 */
    uint8_t  smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_mprcnt;   /* max number of parameter bytes to return */
    uint16_t smb_mdrcnt;   /* max number of data bytes to return */
    uint8_t  smb_msrcnt;   /* max number of setup words to return */
    uint8_t  smb_rsvd;     /* reserved (pad above to word) */
    uint16_t smb_flags;    /* additional information:
                              bit 0 - if set, also disconnect TID in smb_tid
                              bit 1 - if set, transaction is one way (no final response) */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd1;    /* reserved */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint8_t  smb_suwcnt;   /* set up word count */
    uint8_t  smb_rsvd2;    /* reserved (pad above to word) */
    uint16_t smb_setup1;   /* function (see below)
                                TRANS_SET_NM_PIPE_STATE   = 0x0001
                                TRANS_RAW_READ_NMPIPE     = 0x0011
                                TRANS_QUERY_NMPIPE_STATE  = 0x0021
                                TRANS_QUERY_NMPIPE_INFO   = 0x0022
                                TRANS_PEEK_NMPIPE         = 0x0023
                                TRANS_TRANSACT_NMPIPE     = 0x0026
                                TRANS_RAW_WRITE_NMPIPE    = 0x0031
                                TRANS_READ_NMPIPE         = 0x0036
                                TRANS_WRITE_NMPIPE        = 0x0037
                                TRANS_WAIT_NMPIPE         = 0x0053
                                TRANS_CALL_NMPIPE         = 0x0054  */
    uint16_t smb_setup2;   /* FID (handle) of pipe (if needed), or priority */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_name[];   /* name of transaction */
    uint8_t  smb_pad[];    /* (optional) to pad to word or dword boundary */
    uint8_t  smb_param[*]; /* param bytes (* = value of smb_pscnt) */
    uint8_t  smb_pad1[];   /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];  /* data bytes (* = value of smb_dscnt) */
#endif
} SmbTransactionReq;

typedef struct _SmbTransactionInterimResp    /* smb_wct = 0 */
{
    uint8_t   smb_wct;      /* count of 16-bit words that follow */
    uint16_t  smb_bcc;      /* must be 0 */

} SmbTransactionInterimResp;

typedef struct _SmbTransactionResp   /* smb_wct = 10 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 0 */
    uint8_t  smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_tprcnt;   /* total number of parameter bytes being returned */
    uint16_t smb_tdrcnt;   /* total number of data bytes being returned */
    uint16_t smb_rsvd;     /* reserved */
    uint16_t smb_prcnt;    /* number of parameter bytes being returned this buf */
    uint16_t smb_proff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_prdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_drcnt;    /* number of data bytes being returned this buffer */
    uint16_t smb_droff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_drdisp;   /* byte displacement for these data bytes */
    uint8_t  smb_suwcnt;   /* set up return word count */
    uint8_t  smb_rsvd1;    /* reserved (pad above to word) */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];    /* (optional) to pad to word or dword boundary */
    uint8_t  smb_param[*]; /* param bytes (* = value of smb_prcnt) */
    uint8_t  smb_pad1[];   /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];  /* data bytes (* = value of smb_drcnt) */
#endif
} SmbTransactionResp;

static inline uint16_t SmbTransactionReqSubCom(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_setup1);
}

static inline uint16_t SmbTransactionReqFid(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_setup2);
}

static inline bool SmbTransactionReqDisconnectTid(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_flags) & 0x0001 ? true : false;
}

static inline bool SmbTransactionReqOneWay(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_flags) & 0x0002 ? true : false;
}

static inline uint8_t SmbTransactionReqSetupCnt(const SmbTransactionReq *req)
{
    return req->smb_suwcnt;
}

static inline uint16_t SmbTransactionReqTotalDataCnt(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_tdscnt);
}

static inline uint16_t SmbTransactionReqDataCnt(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_dscnt);
}

static inline uint16_t SmbTransactionReqDataOff(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_dsoff);
}

static inline uint16_t SmbTransactionReqTotalParamCnt(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_tpscnt);
}

static inline uint16_t SmbTransactionReqParamCnt(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_pscnt);
}

static inline uint16_t SmbTransactionReqParamOff(const SmbTransactionReq *req)
{
    return SmbNtohs(&req->smb_psoff);
}

static inline uint16_t SmbTransactionRespTotalDataCnt(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_tdrcnt);
}

static inline uint16_t SmbTransactionRespDataCnt(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_drcnt);
}

static inline uint16_t SmbTransactionRespDataOff(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_droff);
}

static inline uint16_t SmbTransactionRespDataDisp(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_drdisp);
}

static inline uint16_t SmbTransactionRespTotalParamCnt(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_tprcnt);
}

static inline uint16_t SmbTransactionRespParamCnt(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_prcnt);
}

static inline uint16_t SmbTransactionRespParamOff(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_proff);
}

static inline uint16_t SmbTransactionRespParamDisp(const SmbTransactionResp *resp)
{
    return SmbNtohs(&resp->smb_prdisp);
}

// Flags for TRANS_SET_NMPIPE_STATE parameters
#define PIPE_STATE_NON_BLOCKING  0x8000
#define PIPE_STATE_MESSAGE_MODE  0x0100

/********************************************************************
 * SMB_COM_TRANSACTION_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION requests if all
 *  data wasn't sent.
 ********************************************************************/
typedef struct _SmbTransactionSecondaryReq   /* smb_wct = 8 */
{
    uint8_t  smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_psdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_dsdisp;   /* byte displacement for these data bytes */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];    /* (optional) to pad to word or dword boundary */
    uint8_t  smb_param[*]; /* param bytes (* = value of smb_pscnt) */
    uint8_t  smb_pad1[];   /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];  /* data bytes (* = value of smb_dscnt) */
#endif
} SmbTransactionSecondaryReq;

static inline uint16_t SmbTransactionSecondaryReqTotalDataCnt(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_tdscnt);
}

static inline uint16_t SmbTransactionSecondaryReqDataCnt(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_dscnt);
}

static inline uint16_t SmbTransactionSecondaryReqDataOff(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_dsoff);
}

static inline uint16_t SmbTransactionSecondaryReqDataDisp(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_dsdisp);
}

static inline uint16_t SmbTransactionSecondaryReqTotalParamCnt(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_tpscnt);
}

static inline uint16_t SmbTransactionSecondaryReqParamCnt(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_pscnt);
}

static inline uint16_t SmbTransactionSecondaryReqParamOff(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_psoff);
}

static inline uint16_t SmbTransactionSecondaryReqParamDisp(const SmbTransactionSecondaryReq *req)
{
    return SmbNtohs(&req->smb_psdisp);
}

/********************************************************************
 * SMB_COM_WRITE_AND_CLOSE
 ********************************************************************/
typedef struct _SmbWriteAndCloseReq   /* smb_wct = 6 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle (close after write) */
    uint16_t smb_count;   /* number of bytes to write */
    uint32_t smb_offset;  /* offset in file to begin write */
    uint32_t smb_mtime;   /* modification time */
    uint16_t smb_bcc;     /* 1 (for pad) + value of smb_count */
#if 0
    uint8_t  smb_pad;     /* force data to dword boundary */
    uint8_t  smb_data[];  /* data */
#endif
} SmbWriteAndCloseReq;

typedef struct _SmbWriteAndCloseExtReq   /* smb_wct = 12 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle (close after write) */
    uint16_t smb_count;   /* number of bytes to write */
    uint32_t smb_offset;  /* offset in file to begin write */
    uint32_t smb_mtime;   /* modification time */
    uint32_t smb_rsvd1;   /* Optional */
    uint32_t smb_rsvd2;   /* Optional */
    uint32_t smb_rsvd3;   /* Optional */
    uint16_t smb_bcc;     /* 1 (for pad) + value of smb_count */
#if 0
    uint8_t  smb_pad;     /* force data to dword boundary */
    uint8_t  smb_data[];  /* data */
#endif
} SmbWriteAndCloseExtReq;

typedef struct _SmbWriteAndCloseResp   /* smb_wct = 1 */
{
    uint8_t  smb_wct;    /* count of 16-bit words that follow */
    uint16_t smb_count;  /* number of bytes written */
    uint16_t smb_bcc;    /* must be 0 */

} SmbWriteAndCloseResp;

static inline uint16_t SmbWriteAndCloseReqFid(const SmbWriteAndCloseReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbWriteAndCloseReqCount(const SmbWriteAndCloseReq *req)
{
    return SmbNtohs(&req->smb_count);
}

static inline uint16_t SmbWriteAndCloseRespCount(const SmbWriteAndCloseResp *resp)
{
    return SmbNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_OPEN_ANDX
 ********************************************************************/
typedef struct _SmbOpenAndXReq   /* smb_wct = 15 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, return additional information
                                bit 1 - if set, set single user total file lock (if only access)
                                bit 2 - if set, the server should notify the consumer on any
                                        action which can modify the file (delete, setattrib,
                                        rename, etc.). if not set, the server need only notify
                                        the consumer on another open request. This bit only has
                                        meaning if bit 1 is set. */
    uint16_t smb_mode;       /* file open mode */
    uint16_t smb_sattr;      /* search attributes */
    uint16_t smb_attr;       /* file attributes (for create) */
    uint32_t smb_time;       /* create time */
    uint16_t smb_ofun;       /* open function */
    uint32_t smb_size;       /* bytes to reserve on "create" or "truncate" */
    uint32_t smb_timeout;    /* max milliseconds to wait for resource to open */
    uint32_t smb_rsvd;       /* reserved (must be zero) */
    uint16_t smb_bcc;        /* minimum value = 1 */
#if 0
    uint8_t  smb_pathname[]; /* file pathname */
#endif
} SmbOpenAndXReq;

typedef struct _SmbOpenAndXResp   /* smb_wct = 15 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint16_t smb_attribute;  /* attributes of file or device */
    uint32_t smb_time;       /* last modification time */
    uint32_t smb_size;       /* current file size */
    uint16_t smb_access;     /* access permissions actually allowed */
    uint16_t smb_type;       /* file type */
    uint16_t smb_state;      /* state of IPC device (e.g. pipe) */
    uint16_t smb_action;     /* action taken */
    uint32_t smb_fileid;     /* server unique file id */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */

} SmbOpenAndXResp;

static inline uint16_t SmbOpenAndXRespFid(const SmbOpenAndXResp *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_READ_ANDX
 ********************************************************************/
typedef struct _SmbReadAndXReq   /* smb_wct = 10 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint16_t smb_bcc;        /* value = 0 */

} SmbReadAndXReq;

typedef struct _SmbReadAndXExtReq   /* smb_wct = 12 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_off_low;    /* low offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint32_t smb_off_high;   /* high offset in file to begin read */
    uint16_t smb_bcc;        /* value = 0 */

} SmbReadAndXExtReq;

typedef struct _SmbReadAndXResp    /* smb_wct = 12 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint32_t smb_rsvd;       /* reserved */
    uint16_t smb_dsize;      /* number of data bytes (minimum value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_rsvd1;      /* reserved (These last 5 words are reserved in */
    uint32_t smb_rsvd2;      /* reserved order to make the ReadandX response */
    uint32_t smb_rsvd3;      /* reserved the same size as the WriteandX request) */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];      /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];    /* data bytes (* = value of smb_dsize) */
#endif
} SmbReadAndXResp;

static inline uint16_t SmbReadAndXReqFid(const SmbReadAndXReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbReadAndXRespDataOff(const SmbReadAndXResp *req)
{
    return SmbNtohs(&req->smb_doff);
}

static inline uint16_t SmbReadAndXRespDataCnt(const SmbReadAndXResp *resp)
{
    return SmbNtohs(&resp->smb_dsize);
}

/********************************************************************
 * SMB_COM_WRITE_ANDX
 ********************************************************************/
typedef struct _SmbWriteAndXReq   /* smb_wct = 12 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin write */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;      /* write mode:
                                bit0 - complete write before return (write through)
                                bit1 - return smb_remaining (pipes/devices only)
                                bit2 - use WriteRawNamedPipe (pipes only)
                                bit3 - this is the start of a message (pipes only) */
    uint16_t smb_countleft;  /* bytes remaining to write to satisfy user’s request */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_dsize;      /* number of data bytes in buffer (min value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];      /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];    /* data bytes (* = value of smb_dsize) */
#endif
} SmbWriteAndXReq;

typedef struct _SmbWriteAndXExtReq   /* smb_wct = 14 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_off_low;    /* low offset in file to begin write */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;      /* write mode:
                                bit0 - complete write before return (write through)
                                bit1 - return smb_remaining (pipes/devices only)
                                bit2 - use WriteRawNamedPipe (pipes only)
                                bit3 - this is the start of a message (pipes only) */
    uint16_t smb_countleft;  /* bytes remaining to write to satisfy user’s request */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_dsize;      /* number of data bytes in buffer (min value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint32_t smb_off_high;   /* high offset in file to begin write */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
#if 0
    uint8_t  smb_pad[];      /* (optional) to pad to word or dword boundary */
    uint8_t  smb_data[*];    /* data bytes (* = value of smb_dsize) */
#endif
} SmbWriteAndXExtReq;

typedef struct _SmbWriteAndXResp   /* smb_wct = 6 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_count;      /* number of bytes written */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint32_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */

} SmbWriteAndXResp;

static inline uint16_t SmbWriteAndXReqFid(const SmbWriteAndXReq *req)
{
    return SmbNtohs(&req->smb_fid);
}

static inline uint16_t SmbWriteAndXReqDataOff(const SmbWriteAndXReq *req)
{
    return SmbNtohs(&req->smb_doff);
}

static inline uint16_t SmbWriteAndXReqRemaining(const SmbWriteAndXReq *req)
{
    return SmbNtohs(&req->smb_countleft);
}

static inline uint32_t SmbWriteAndXReqOffset(const SmbWriteAndXReq *req)
{
    return SmbNtohl(&req->smb_offset);
}

static inline uint16_t SmbWriteAndXReqDataCnt(const SmbWriteAndXReq *req)
{
    return SmbNtohs(&req->smb_dsize);
}

static inline uint16_t SmbWriteAndXReqWriteMode(const SmbWriteAndXReq *req)
{
    return SmbNtohs(&req->smb_wmode);
}

static inline bool SmbWriteAndXReqStartRaw(const SmbWriteAndXReq *req)
{
    return ((SmbNtohs(&req->smb_wmode) & 0x000c) == 0x000c) ? true : false;
}

static inline bool SmbWriteAndXReqRaw(const SmbWriteAndXReq *req)
{
    return ((SmbNtohs(&req->smb_wmode) & 0x000c) == 0x0004) ? true : false;
}

static inline uint16_t SmbWriteAndXRespCnt(const SmbWriteAndXResp *resp)
{
    return SmbNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_TRANSACTION2
 ********************************************************************/
typedef struct _SmbTransaction2Req
{
    uint8_t  smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_max_param_count;
    uint16_t smb_max_data_count;
    uint8_t  smb_max_setup_count;
    uint8_t  smb_res;
    uint16_t smb_flags;
    uint32_t smb_timeout;
    uint16_t smb_res2;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint8_t  smb_setup_count;   /* Should be 1 for all subcommands */
    uint8_t  smb_res3;
    uint16_t smb_setup;  /* This is the subcommand */
    uint16_t smb_bcc;
#if 0
    uint8_t smb_name[];  /* ASCII or Unicode depending on smb header flags */
    uint8_t pad1[];
    uint8_t smb_trans2_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_trans2_data[smb_data_count];
#endif
} SmbTransaction2Req;

typedef struct _SmbTransaction2InterimResp
{
    uint8_t  smb_wct;
    uint16_t smb_bcc;

} SmbTransaction2InterimResp;

typedef struct _SmbTransaction2Resp
{
    uint8_t  smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 or 1 word */
    uint8_t  smb_res2;
#if 0
    uint16_t smb_setup[smb_setup_count];
    uint16_t smb_bcc;
    uint8_t pad1[];
    uint8_t smb_trans2_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_trans2_data[smb_data_count];
#endif
} SmbTransaction2Resp;

static inline uint16_t SmbTransaction2ReqSubCom(const SmbTransaction2Req *req)
{
    return SmbNtohs(&req->smb_setup);
}

static inline uint16_t SmbTransaction2ReqTotalParamCnt(const SmbTransaction2Req *req)
{
    return SmbNtohs(&req->smb_total_param_count);
}

static inline uint16_t SmbTransaction2ReqParamCnt(const SmbTransaction2Req *req)
{
    return SmbNtohs(&req->smb_param_count);
}

static inline uint16_t SmbTransaction2ReqParamOff(const SmbTransaction2Req *req)
{
    return SmbNtohs(&req->smb_param_offset);
}

static inline uint16_t SmbTransaction2RespTotalParamCnt(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_total_param_count);
}

static inline uint16_t SmbTransaction2RespParamCnt(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_param_count);
}

static inline uint16_t SmbTransaction2RespParamOff(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_param_offset);
}

static inline uint16_t SmbTransaction2RespParamDisp(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_param_disp);
}

static inline uint16_t SmbTransaction2RespTotalDataCnt(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_total_data_count);
}

static inline uint16_t SmbTransaction2RespDataCnt(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_data_count);
}

static inline uint16_t SmbTransaction2RespDataOff(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_data_offset);
}

static inline uint16_t SmbTransaction2RespDataDisp(const SmbTransaction2Resp *resp)
{
    return SmbNtohs(&resp->smb_data_disp);
}

typedef struct _SmbTrans2Open2RespParams
{
    uint16_t smb_fid;
    uint16_t file_attributes;
    uint32_t creation_time;
    uint32_t file_data_size;
    uint16_t access_mode;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint16_t action_taken;
    uint32_t reserved;
    uint16_t extended_attribute_error_offset;
    uint32_t extended_attribute_length;

} SmbTrans2Open2RespParams;

typedef struct _SmbTrans2Open2Resp
{
    uint8_t  smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 */
    uint8_t  smb_res2;
    uint16_t smb_bcc;
#if 0
    uint8_t pad1[];
    uint8_t smb_trans2_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_trans2_data[smb_data_count];
#endif
} SmbTrans2Open2Resp;

static inline uint16_t SmbTrans2Open2RespFid(const SmbTrans2Open2RespParams *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_TRANSACTION2_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION2 requests if all
 *  data wasn't sent.
 ********************************************************************/
typedef struct _SmbTransaction2SecondaryReq
{
    uint8_t  smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_fid;
    uint16_t smb_bcc;
#if 0
    uint8_t pad1[];
    uint8_t smb_trans2_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_trans2_data[smb_data_count];
#endif
} SmbTransaction2SecondaryReq;

static inline uint16_t SmbTransaction2SecondaryReqTotalParamCnt(const SmbTransaction2SecondaryReq *req)
{
    return SmbNtohs(&req->smb_total_param_count);
}

static inline uint16_t SmbTransaction2SecondaryReqParamCnt(const SmbTransaction2SecondaryReq *req)
{
    return SmbNtohs(&req->smb_param_count);
}

static inline uint16_t SmbTransaction2SecondaryReqParamOff(const SmbTransaction2SecondaryReq *req)
{
    return SmbNtohs(&req->smb_param_offset);
}

static inline uint16_t SmbTransaction2SecondaryReqParamDisp(const SmbTransaction2SecondaryReq *req)
{
    return SmbNtohs(&req->smb_param_disp);
}

/*********************************************************************
 * SMB_COM_TREE_CONNECT
 *********************************************************************/
typedef struct _SmbTreeConnectReq  /* smb_wct = 0 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* min = 4 */

#if 0
    uint8_t  smb_fmt;     /* ASCII -- 04 */
    uint8_t  smb_buf[];   /* path/username */
    uint8_t  smb_fmt2;    /* ASCII -- 04 */
    uint8_t  smb_buf2[];  /* password */
    uint8_t  smb_fmt3;    /* ASCII -- 04 */
    uint8_t  smb_buf3[];  /* dev name (<device> or LPT1) */
#endif
} SmbTreeConnectReq;

typedef struct _SmbTreeConnectResp  /* smb_wct = 2 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_xmit;    /* max xmit size */
    uint16_t smb_tid;     /* tree id */
    uint16_t smb_bcc;

} SmbTreeConnectResp;

/********************************************************************
 * SMB_COM_TREE_DISCONNECT
 ********************************************************************/
typedef struct _SmbTreeDisconnectReq   /* smb_wct = 0 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* must be 0 */

} SmbTreeDisconnectReq;

typedef struct _SmbTreeDisconnectResp   /* smb_wct = 0 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* must be 0 */

} SmbTreeDisconnectResp;

/********************************************************************
 * SMB_COM_NEGOTIATE
 ********************************************************************/
typedef struct _SmbNegotiateReq   /* smb_wct = 0 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* min = 2 */

#if 0
    uint8_t  smb_fmt;     /* Dialect -- 02 */
    uint8_t  smb_buf[];   /* dialect0 */
            .
            .
            .
    uint8_t  smb_fmt;     /* Dialect -- 02 */
    uint8_t  smb_bufn[];  /* dialectn*/
#endif
} SmbCore_NegotiateProtocolReq;

/* This is the Core Protocol response */
typedef struct _SmbCore_NegotiateProtocolResp    /* smb_wct = 1 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_index;   /* index */
    uint16_t smb_bcc;     /* must be 0 */

} SmbCore_NegotiateProtocolResp;

/* This is the Lanman response */
typedef struct _SmbLm10_NegotiateProtocolResp   /* smb_wct = 13 */
{
    uint8_t  smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_index;     /* index identifying dialect selected */
    uint16_t smb_secmode;   /* security mode:
                               bit 0, 1 = User level, 0 = Share level
                               bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxxmt;    /* max transmit buffer size server supports, 1K min */
    uint16_t smb_maxmux;    /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;    /* max VCs per server/consumer session supported */
    uint16_t smb_blkmode;   /* block read/write mode support:
                               bit 0, Read Block Raw supported (65535 bytes max)
                               bit 1, Write Block Raw supported (65535 bytes max) */
    uint32_t smb_sesskey;   /* Session Key (unique token identifying session) */
    uint16_t smb_srv_time;  /* server's current time (hhhhh mmmmmm xxxxx) */
    uint16_t smb_srv_tzone; /* server's current data (yyyyyyy mmmm ddddd) */
    uint32_t smb_rsvd;      /* reserved */
    uint16_t smb_bcc;       /* value = (size of smb_cryptkey) */
#if 0
    uint8_t  smb_cryptkey[];  /* Key used for password encryption */
#endif
} SmbLm10_NegotiateProtocolResp;

/* This is the Lanman 2.1 response */
typedef struct _SmbLm21_NegotiateProtocolResp     /* smb_wct = 13 */
{
    uint8_t  smb_wct;         /* count of 16-bit words that follow */
    uint16_t smb_index;       /* index identifying dialect selected */
    uint16_t smb_secmode;     /* security mode:
                                 bit 0, 1 = User level, 0 = Share level
                                 bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxxmt;      /* max transmit buffer size server supports, 1K min */
    uint16_t smb_maxmux;      /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;      /* max VCs per server/consumer session supported */
    uint16_t smb_blkmode;     /* block read/write mode support:
                                 bit 0, Read Block Raw supported (65535 bytes max)
                                 bit 1, Write Block Raw supported (65535 bytes max) */
    uint32_t smb_sesskey;     /* Session Key (unique token identifying session) */
    uint16_t smb_srv_time;    /* server's current time (hhhhh mmmmmm xxxxx) */
    uint16_t smb_srv_tzone;   /* server's current data (yyyyyyy mmmm ddddd) */
    uint16_t smb_cryptkeylen; /* length of smb_cryptkey */
    uint16_t smb_rsvd;        /* reserved */
    uint16_t smb_bcc;       /* value = (size of smb_cryptkey) */
#if 0
    uint8_t  smb_cryptkey[];  /* Key used for password encryption */
    uint8_t  smb_domain[]     /* Null terminated server domain */
#endif
} SmbLm21_NegotiateProtocolResp;

/* This is the NT response */
typedef struct _SmbNt_NegotiateProtocolResp     /* smb_wct = 17 */
{
    uint8_t  smb_wct;           /* count of 16-bit words that follow */
    uint16_t smb_index;         /* index identifying dialect selected */
    uint8_t  smb_secmode;       /* security mode:
                                   bit 0, 1 = User level, 0 = Share level
                                   bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxmux;        /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;        /* max VCs per server/consumer session supported */
    uint32_t smb_maxbuf;        /* maximum buffer size supported */
    uint32_t smb_maxraw;        /* maximum raw buffer size supported */
    uint32_t smb_sesskey;       /* Session Key (unique token identifying session) */
    uint32_t smb_cap;           /* capabilities */
    struct {
        uint32_t low_time;
        int32_t  high_time;
    } smb_srv_time;             /* server time */
    uint16_t smb_srv_tzone;     /* server's current data (yyyyyyy mmmm ddddd) */
    uint8_t  smb_challenge_len; /* Challenge length */
    uint16_t smb_bcc;           /* value = (size of smb_cryptkey) */
#if 0
    uint8_t  smb_challenge[];  /* challenge used for password encryption */
    uint8_t  smb_domain[];     /* domain name */
    uint8_t  smb_server[];     /* server name */
    // or
    uint8_t  smb_server_guid[16];
    uint8_t  smb_security_blob[];
#endif
} SmbNt_NegotiateProtocolResp;

static inline uint16_t SmbNegotiateRespDialectIndex(const SmbCore_NegotiateProtocolResp *resp)
{
    return SmbNtohs(&resp->smb_index);
}

static inline uint16_t SmbLm_NegotiateRespMaxMultiplex(const SmbLm10_NegotiateProtocolResp *resp)
{
    return SmbNtohs(&resp->smb_maxmux);
}

static inline uint16_t SmbNt_NegotiateRespMaxMultiplex(const SmbNt_NegotiateProtocolResp *resp)
{
    return SmbNtohs(&resp->smb_maxmux);
}

/********************************************************************
 * SMB_COM_SESSION_SETUP_ANDX
 ********************************************************************/
typedef struct _SmbLm10_SessionSetupAndXReq   /* smb_wct = 10 */
{
    uint8_t  smb_wct;      /* count of 16-bit words that follow */
    uint8_t  smb_com2;     /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;     /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;  /* the consumers max buffer size */
    uint16_t smb_mpxmax;   /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;   /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;  /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_apasslen; /* size of account password (smb_apasswd) */
    uint32_t smb_rsvd;     /* reserved */
    uint16_t smb_bcc;      /* minimum value = 0 */
#if 0
    uint8_t  smb_apasswd[*];  /* account password (* = smb_apasslen value) */
    uint8_t  smb_aname[];     /* account name string */
#endif
} SmbLm10_SessionSetupAndXReq;

typedef struct _SmbLm10_SessionSetupAndXResp   /* smb_wct = 3 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint8_t  smb_com2;    /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;    /* reserved (pad to word) */
    uint16_t smb_off2;    /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;  /* request mode:
                             bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_bcc;     /* value = 0 */

} SmbLm10_SessionSetupAndXResp;

/* Extended request as defined in LM 2.0 document */
typedef struct _SmbLm20_SessionSetupAndXReq   /* smb_wct = 10 */
{
    uint8_t  smb_wct;         /* count of 16-bit words that follow */
    uint8_t  smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;        /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;     /* the consumers max buffer size */
    uint16_t smb_mpxmax;      /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;      /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;     /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_apasslen;    /* size of account password (smb_apasswd) */
    uint16_t smb_encryptlen;  /* size of encryption key (smb_encrypt) */
    uint16_t smb_encryptoff;  /* offet (from SMB hdr start) to smb_encrypt */
    uint16_t smb_bcc;         /* minimum value = 0 */
#if 0
    uint8_t  smb_apasswd[*];  /* account password (* = smb_apasslen value) */
    uint8_t  smb_aname[];     /* account name string */
    uint8_t  smb_encrypt[*];  /* encryption key. (* = smb_encryptlen value) */
#endif
} SmbLm20_SessionSetupAndXReq;

/* Extended response as defined in LM 2.0 document */
typedef struct _SmbLm20_SessionSetupAndXResp   /* smb_wct = 3 */
{
    uint8_t  smb_wct;     /* count of 16-bit words that follow */
    uint8_t  smb_com2;    /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;    /* reserved (pad to word) */
    uint16_t smb_off2;    /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;  /* request mode:
                             bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_bcc;     /* min value = 0 */
#if 0
    smb_encresp[];        /* server response to request encryption key */
#endif
} SmbLm20_SessionSetupAndXResp;

/* Extended request as defined in LM 2.1 document */
typedef struct _SmbLm21_SessionSetupAndXReq   /* smb_wct = 10 */
{
    uint8_t  smb_wct;         /* count of 16-bit words that follow */
    uint8_t  smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;        /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;     /* the consumers max buffer size */
    uint16_t smb_mpxmax;      /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;      /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;     /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_apasslen;    /* size of account password (smb_apasswd) */
    uint32_t smb_rsvd;        /* reserved */
    uint16_t smb_bcc;         /* minimum value = 0 */
#if 0
    uint8_t  smb_apasswd[*];  /* account password (* = smb_apasslen value) */
    uint8_t  smb_aname[];     /* account name string */
    uint8_t  smb_domain[];    /* name of domain that client was authenticated on */
    uint8_t  smb_mativeos[];  /* native operation system of client */
    uint8_t  smb_nativelm[];  /* native LAN Manager type */
#endif
} SmbLm21_SessionSetupAndXReq;

/* Extended response as defined in LM 2.1 document */
typedef struct _SmbLm21_SessionSetupAndXResp   /* smb_wct = 3 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;     /* request mode:
                                bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_bcc;        /* min value = 0 */
#if 0
    uint8_t smb_nativeos[];  /* server's native operating system */
    uint8_t smb_nativelm[];  /* server's native LM type */
#endif
} SmbLm21_SessionSetupAndXResp;

/* Extended request as defined in NT LM 1.0 document */
typedef struct _SmbNt10_SessionSetupAndXReq   /* smb_wct = 13 */
{
    uint8_t  smb_wct;             /* count of 16-bit words that follow */
    uint8_t  smb_com2;            /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;            /* reserved (must be zero) */
    uint16_t smb_off2;            /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;         /* the consumers max buffer size */
    uint16_t smb_mpxmax;          /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;          /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;         /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_oem_passlen;     /* case insensitive password length */
    uint16_t smb_unicode_passlen; /* case sensitive password length */
    uint32_t smb_rsvd;            /* reserved */
    uint32_t smb_cap;             /* capabilities */
    uint16_t smb_bcc;             /* minimum value = 0 */
#if 0
    uint8_t  smb_oem_passwd[*];     /* case insensitive password (* = smb_ci_passlen) */
    uint8_t  smb_unicode_passwd[*]; /* case sensitive password (* = smb_cs_passlen) */
    uint8_t  pad[];                 /* if unicode to align */
    uint8_t  smb_aname[];           /* ascii or unicode account name string */
    uint8_t  smb_domain[];          /* ascii or unicode name of domain that client was authenticated on */
    uint8_t  smb_nativeos[];        /* ascii or unicode native operation system of client */
    uint8_t  smb_nativelm[];        /* ascii or unicode native LAN Manager type */
#endif
} SmbNt10_SessionSetupAndXReq;

static inline uint16_t SmbSessionSetupAndXReqMaxMultiplex(const SmbLm10_SessionSetupAndXReq *req)
{
    return SmbNtohs(&req->smb_mpxmax);
}

static inline uint16_t SmbNt10SessionSetupAndXReqOemPassLen(SmbNt10_SessionSetupAndXReq *req)
{
    return SmbNtohs(&req->smb_oem_passlen);
}

static inline uint16_t SmbNt10SessionSetupAndXReqUnicodePassLen(SmbNt10_SessionSetupAndXReq *req)
{
    return SmbNtohs(&req->smb_unicode_passlen);
}

/* Extended request for security blob */
typedef struct _SmbNt10_SessionSetupAndXExtReq   /* smb_wct = 12 */
{
    uint8_t  smb_wct;         /* count of 16-bit words that follow */
    uint8_t  smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;        /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;     /* the consumers max buffer size */
    uint16_t smb_mpxmax;      /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;      /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;     /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_blob_len;    /* length of security blob */
    uint32_t smb_rsvd;        /* reserved */
    uint32_t smb_cap;         /* capabilities */
    uint16_t smb_bcc;         /* minimum value = 0 */
#if 0
    uint8_t  smb_blob[];        /* security blob */
    uint8_t  smb_nativeos[];    /* ascii or unicode native operation system of client */
    uint8_t  smb_nativelm[];    /* ascii or unicode native LAN Manager type */
#endif
} SmbNt10_SessionSetupAndXExtReq;

static inline uint16_t SmbSessionSetupAndXReqBlobLen(SmbNt10_SessionSetupAndXExtReq *req)
{
    return SmbNtohs(&req->smb_blob_len);
}

/* Response as defined in NT LM 1.0 document */
typedef struct _SmbNt10_SessionSetupAndXResp   /* smb_wct = 3 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;     /* request mode:
                                bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_bcc;        /* min value = 0 */
#if 0
    uint8_t  pad[];           /* if unicode is used to align */
    uint8_t  smb_nativeos[];  /* ascii or unicode server's native operating system */
    uint8_t  smb_nativelm[];  /* ascii or unicode server's native LM type */
    uint8_t  smb_domain[];    /* ascii or unicode logon domain of the user */
#endif
} SmbNt10_SessionSetupAndXResp;

/* Extended response for security blob */
typedef struct _SmbNt10_SessionSetupAndXExtResp   /* smb_wct = 4 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;     /* request mode:
                                bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_blob_len;   /* length of security blob */
    uint16_t smb_bcc;        /* min value = 0 */
#if 0
    uint8_t  smb_blob[];      /* security blob */
    uint8_t  smb_nativeos[];  /* ascii or unicode server's native operating system */
    uint8_t  smb_nativelm[];  /* ascii or unicode server's native LM type */
#endif
} SmbNt10_SessionSetupAndXExtResp;

static inline uint16_t SmbSessionSetupAndXRespBlobLen(const SmbNt10_SessionSetupAndXExtResp *resp)
{
    return SmbNtohs(&resp->smb_blob_len);
}

/********************************************************************
 * SMB_COM_LOGOFF_ANDX
 ********************************************************************/
typedef struct _SmbLogoffAndXReq    /* smb_wct = 2 */
{
    uint8_t  smb_wct;    /* count of 16-bit words that follow */
    uint8_t  smb_com2;   /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;   /* reserved (must be zero) */
    uint16_t smb_off2;   /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bcc;    /* value = 0 */

} SmbLogoffAndXReq;

typedef struct _SmbLogoffAndXResp    /* smb_wct = 2 */
{
    uint8_t  smb_wct;    /* count of 16-bit words that follow */
    uint8_t  smb_com2;   /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;   /* reserved (pad to word) */
    uint16_t smb_off2;   /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bcc;    /* value = 0 */

} SmbLogoffAndXResp;

/*********************************************************************
 * SMB_COM_TREE_CONNECT_ANDX
 *********************************************************************/
typedef struct _SmbTreeConnectAndXReq   /* smb_wct = 4 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_reh2;       /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, disconnect TID in current smb_tid */
    uint16_t smb_spasslen;   /* length of smb_spasswd */
    uint16_t smb_bcc;        /* minimum value = 3 */
#if 0
    uint8_t  smb_spasswd[*]; /* net-name password (* = smb_spasslen value) */
    uint8_t  pad[];          /* if unicode to align */
    uint8_t  smb_path[];     /* server name and net-name */
    uint8_t  smb_service[];  /* service name string */
#endif
} SmbTreeConnectAndXReq;

typedef struct _SmbLm10_TreeConnectAndXResp    /* smb_wct = 2 */
{
    uint8_t  smb_wct;       /* count of 16-bit words that follow */
    uint8_t  smb_com2;      /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;      /* reserved (pad to word) */
    uint16_t smb_off2;      /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bcc;       /* min value = 3 */
#if 0
    uint8_t  smb_service[]; /* service type connected to (string) */
#endif
} SmbLm10_TreeConnectAndXResp;

typedef struct _SmbTreeConnectAndXResp    /* smb_wct = 3 */
{
    uint8_t  smb_wct;        /* count of 16-bit words that follow */
    uint8_t  smb_com2;       /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;       /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_optsupp;    /* bit mask indicating advanced OS features available
                                bit0 = 1, exclusive search bits supported */
    uint16_t smb_bcc;        /* min value = 3 */
#if 0
    uint8_t  smb_service[];  /* service type connected to - ASCII */
    uint8_t  pad[];          /* if unicode to align */
    uint8_t  smb_nativefs[]; /* native file system for this connection */
#endif
} SmbTreeConnectAndXResp;

typedef struct _SmbTreeConnectAndXExtResp    /* smb_wct = 7 */
{
    uint8_t  smb_wct;          /* count of 16-bit words that follow */
    uint8_t  smb_com2;         /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;         /* reserved (pad to word) */
    uint16_t smb_off2;         /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_optsupp;      /* bit mask indicating advanced OS features available */
    uint32_t smb_share_access; /* maximal share access rights */
    uint32_t smb_guest_access; /* guest maximal share access rights */
    uint16_t smb_bcc;          /* min value = 3 */
#if 0
    uint8_t  smb_service[];  /* service type connected to - ASCII */
    uint8_t  pad[];          /* if unicode to align */
    uint8_t  smb_nativefs[]; /* native file system for this connection */
#endif
} SmbTreeConnectAndXExtResp;

static inline uint16_t SmbTreeConnectAndXReqPassLen(const SmbTreeConnectAndXReq *req)
{
    return SmbNtohs(&req->smb_spasslen);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT
 ********************************************************************/
typedef struct _SmbNtTransactReq
{
    uint8_t  smb_wct;
    uint8_t  smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t  smb_setup_count;
    uint16_t smb_function;
#if 0
    uint16_t smb_setup[smb_setup_count];
    uint16_t smb_bcc;
    uint8_t pad1[];
    uint8_t smb_nt_trans_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_nt_trans_data[smb_data_count];
#endif
} SmbNtTransactReq;

typedef struct _SmbNtTransactInterimResp
{
    uint8_t  smb_wct;
    uint16_t smb_bcc;

} SmbNtTransactInterimResp;

typedef struct _SmbNtTransactResp
{
    uint8_t  smb_wct;
    uint8_t  smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t  smb_setup_count;
#if 0
    uint16_t smb_setup[smb_setup_count];
    uint16_t smb_bcc;
    uint8_t pad1[];
    uint8_t smb_nt_trans_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_nt_trans_data[smb_data_count];
#endif
} SmbNtTransactResp;

static inline uint16_t SmbNtTransactReqSubCom(const SmbNtTransactReq *req)
{
    return SmbNtohs(&req->smb_function);
}

static inline uint32_t SmbNtTransactReqTotalParamCnt(const SmbNtTransactReq *req)
{
    return SmbNtohl(&req->smb_total_param_count);
}

static inline uint32_t SmbNtTransactReqParamCnt(const SmbNtTransactReq *req)
{
    return SmbNtohl(&req->smb_param_count);
}

static inline uint32_t SmbNtTransactReqParamOff(const SmbNtTransactReq *req)
{
    return SmbNtohl(&req->smb_param_offset);
}

static inline uint32_t SmbNtTransactRespTotalParamCnt(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_total_param_count);
}

static inline uint32_t SmbNtTransactRespParamCnt(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_param_count);
}

static inline uint32_t SmbNtTransactRespParamOff(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_param_offset);
}

static inline uint32_t SmbNtTransactRespParamDisp(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_param_disp);
}

static inline uint32_t SmbNtTransactRespTotalDataCnt(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_total_data_count);
}

static inline uint32_t SmbNtTransactRespDataCnt(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_data_count);
}

static inline uint32_t SmbNtTransactRespDataOff(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_data_offset);
}

static inline uint32_t SmbNtTransactRespDataDisp(const SmbNtTransactResp *resp)
{
    return SmbNtohl(&resp->smb_data_disp);
}

typedef struct _SmbNtTransactCreateReqParams
{
    uint32_t flags;
    uint32_t root_dir_fid;
    uint32_t desired_access;
    uint64_t allocation_size;
    uint32_t ext_file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint32_t security_descriptor_length;
    uint32_t ea_length;
    uint32_t name_length;
    uint32_t impersonation_level;
    uint8_t  security_flags;
#if 0
    uint8_t  name[name_length];
#endif
} SmbNtTransactCreateReqParams;

#if 0
// Not used now
typedef struct _SmbNtTransactCreateReqData
{
    uint8_t security_descriptor[security_descriptor_length];
    uint8_t extended_attributes[ea_length];

} SmbNtTransactCreateReqData;
#endif

typedef struct _SmbNtTransactCreateReq
{
    uint8_t  smb_wct;
    uint8_t  smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t  smb_setup_count;   /* Must be 0x00 */
    uint16_t smb_function;      /* NT_TRANSACT_CREATE */
    uint16_t smb_bcc;
#if 0
    uint8_t pad1[];
    uint8_t smb_nt_trans_params[smb_param_count];  /* SmbNtTransCreateParams */
    uint8_t pad2[];
    uint8_t smb_nt_trans_data[smb_data_count];
#endif
} SmbNtTransactCreateReq;

typedef struct _SmbNtTransactCreateRespParams
{
    uint8_t  op_lock_level;
    uint8_t  reserved;
    uint16_t smb_fid;
    uint32_t create_action;
    uint32_t ea_error_offset;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t last_change_time;
    uint32_t ext_file_attributes;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint8_t  directory;

} SmbNtTransactCreateRespParams;

typedef struct _SmbNtTransactCreateResp
{
    uint8_t  smb_wct;
    uint8_t  smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t  smb_setup_count;   /* 0x00 */
    uint16_t smb_bcc;
#if 0
    uint8_t pad1[];
    uint8_t smb_nt_trans_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_nt_trans_data[smb_data_count];
#endif
} SmbNtTransactCreateResp;

static inline uint16_t SmbNtTransactCreateRespFid(const SmbNtTransactCreateRespParams *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT_SECONDARY
 ********************************************************************/
typedef struct _SmbNtTransactSecondaryReq
{
    uint8_t  smb_wct;
    uint8_t  smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t  smb_res2;
#if 0
    uint8_t pad1[];
    uint8_t smb_nt_trans_params[smb_param_count];
    uint8_t pad2[];
    uint8_t smb_nt_trans_data[smb_data_count];
#endif

} SmbNtTransactSecondaryReq;

/********************************************************************
 * SMB_COM_NT_CREATE_ANDX
 ********************************************************************/
typedef struct _SmbNtCreateAndXReq   /* smb_wct = 24 */
{
    uint8_t  smb_wct;           /* count of 16-bit words that follow */
    uint8_t  smb_com2;          /* secondary (X) command, 0xFF = none */
    uint8_t  smb_res2;          /* reserved (pad to word) */
    uint16_t smb_off2;          /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint8_t  smb_res;           /* reserved */
    uint16_t smb_name_len;      /* length of name of file */
    uint32_t smb_flags;         /* flags */
    uint32_t smb_root_fid;      /* fid for previously opened directory */
    uint32_t smb_access;        /* specifies the type of file access */
    uint64_t smb_alloc_size;    /* initial allocation size of the file */
    uint32_t smb_file_attrs;    /* specifies the file attributes for the file */
    uint32_t smb_share_access;  /* the type of share access */
    uint32_t smb_create_disp;   /* actions to take if file does or does not exist */
    uint32_t smb_create_opts;   /* options used when creating or opening file */
    uint32_t smb_impersonation_level;  /* security impersonation level */
    uint8_t  smb_security_flags;  /* security flags */
    uint16_t smb_bcc;           /* byte count */
#if 0
    uint8_t * file_name[];    /* name of file to open - ascii or unicode */
#endif
} SmbNtCreateAndXReq;

typedef struct _SmbNtCreateAndXResp    /* smb_wct = 34 */
{
    uint8_t  smb_wct;
    uint8_t  smb_com2;
    uint8_t  smb_res2;
    uint16_t smb_off2;
    uint8_t  smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t  smb_directory;
    uint16_t smb_bcc;

} SmbNtCreateAndXResp;

// Word count is always set to 42 though there are actually 50 words
typedef struct _SmbNtCreateAndXExtResp    /* smb_wct = 42 */
{
    uint8_t  smb_wct;
    uint8_t  smb_com2;
    uint8_t  smb_res2;
    uint16_t smb_off2;
    uint8_t  smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t  smb_directory;
    uint8_t  smb_volume_guid[16];
    uint64_t smb_fileid;
    uint32_t smb_max_access_rights;
    uint32_t smb_guest_access_rights;
    uint16_t smb_bcc;

} SmbNtCreateAndXExtResp;

static inline uint16_t SmbNtCreateAndXRespFid(const SmbNtCreateAndXResp *resp)
{
    return SmbNtohs(&resp->smb_fid);
}

#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#else
#pragma pack()
#endif

#endif /* _SMB_H_ */

