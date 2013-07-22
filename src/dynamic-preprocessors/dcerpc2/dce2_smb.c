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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "spp_dce2.h"
#include "dce2_smb.h"
#include "dce2_tcp.h"
#include "dce2_co.h"
#include "snort_dce2.h"
#include "dce2_config.h"
#include "dce2_memory.h"
#include "dce2_utils.h"
#include "dce2_debug.h"
#include "dce2_stats.h"
#include "dce2_event.h"
#include "smb.h"
#include "sf_snort_packet.h"
#include "sf_types.h"
#include "profiler.h"
#include "snort_debug.h"
#include "sf_dynamic_preprocessor.h"

#ifndef WIN32
#include <arpa/inet.h>  /* for ntohl */
#endif  /* WIN32 */

/********************************************************************
 * Enums
 ********************************************************************/
typedef enum _DCE2_SmbComError
{
    // No errors associated with the command
    DCE2_SMB_COM_ERROR__COMMAND_OK          = 0x0000,

    // An error was reported in the SMB response header
    DCE2_SMB_COM_ERROR__STATUS_ERROR        = 0x0001,

    // An invalid word count makes it unlikely any data accessed will be correct
    // and if accessed the possibility of accessing out of bounds data
    DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT  = 0x0002,

    // An invalid byte count just means the byte count is not right for
    // the command processed.  The command can still be processed but
    // the byte count should not be used.  In general, the byte count
    // should not be used since Windows and Samba often times ignore it
    DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT  = 0x0004,

    // Not enough data to process command so don't try to access any
    // of the command's header or data.
    DCE2_SMB_COM_ERROR__BAD_LENGTH          = 0x0008

} DCE2_SmbComError;

/********************************************************************
 * Structures
 ********************************************************************/
typedef struct _DCE2_SmbComInfo
{
    int smb_type;   // SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
    int cmd_error;  // mask of DCE2_SmbComError
    uint8_t word_count;
    uint16_t byte_count;
    uint16_t cmd_size;

} DCE2_SmbComInfo;

// Inline accessor functions for DCE2_SmbComInfo

static inline bool DCE2_ComInfoIsResponse(const DCE2_SmbComInfo *com_info)
{
    return (com_info->smb_type == SMB_TYPE__RESPONSE) ? true : false;
}

static inline bool DCE2_ComInfoIsRequest(const DCE2_SmbComInfo *com_info)
{
    return (com_info->smb_type == SMB_TYPE__REQUEST) ? true : false;
}

static inline uint8_t DCE2_ComInfoWordCount(const DCE2_SmbComInfo *com_info)
{
    return com_info->word_count;
}

static inline uint16_t DCE2_ComInfoByteCount(const DCE2_SmbComInfo *com_info)
{
    return com_info->byte_count;
}

static inline uint16_t DCE2_ComInfoCommandSize(const DCE2_SmbComInfo *com_info)
{
    return com_info->cmd_size;
}

static inline bool DCE2_ComInfoIsCommandOK(const DCE2_SmbComInfo *com_info)
{
    return (com_info->cmd_error == DCE2_SMB_COM_ERROR__COMMAND_OK) ? true : false;
}

static inline bool DCE2_ComInfoIsStatusError(const DCE2_SmbComInfo *com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__STATUS_ERROR) ? true : false;
}

static inline bool DCE2_ComInfoIsInvalidWordCount(const DCE2_SmbComInfo *com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT) ? true : false;
}

static inline bool DCE2_ComInfoIsInvalidByteCount(const DCE2_SmbComInfo *com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT) ? true : false;
}

static inline bool DCE2_ComInfoIsBadLength(const DCE2_SmbComInfo *com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__BAD_LENGTH) ? true : false;
}

// If this returns false, the command should not be processed
static inline bool DCE2_ComInfoCanProcessCommand(const DCE2_SmbComInfo *com_info)
{
    if (DCE2_ComInfoIsBadLength(com_info)
            || DCE2_ComInfoIsStatusError(com_info)
            || DCE2_ComInfoIsInvalidWordCount(com_info))
        return false;
    return true;
}

/********************************************************************
 * Global variables
 ********************************************************************/
typedef DCE2_Ret (*DCE2_SmbComFunc)(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);

static DCE2_SmbComFunc smb_com_funcs[SMB_MAX_NUM_COMS];
static uint8_t smb_wcts[SMB_MAX_NUM_COMS][2][32];
static uint16_t smb_bccs[SMB_MAX_NUM_COMS][2][2];
static DCE2_SmbComFunc smb_chain_funcs[DCE2_POLICY__MAX][SMB_ANDX_COM__MAX][SMB_MAX_NUM_COMS];
static bool smb_deprecated_coms[SMB_MAX_NUM_COMS];
static bool smb_unusual_coms[SMB_MAX_NUM_COMS];

// Exported
SmbAndXCom smb_chain_map[SMB_MAX_NUM_COMS];

const char *smb_com_strings[SMB_MAX_NUM_COMS] = {
    "Create Directory",            // 0x00
    "Delete Directory",            // 0x01
    "Open",                        // 0x02
    "Create",                      // 0x03
    "Close",                       // 0x04
    "Flush",                       // 0x05
    "Delete",                      // 0x06
    "Rename",                      // 0x07
    "Query Information",           // 0x08
    "Set Information",             // 0x09
    "Read",                        // 0x0A
    "Write",                       // 0x0B
    "Lock Byte Range",             // 0x0C
    "Unlock Byte Range",           // 0x0D
    "Create Temporary",            // 0x0E
    "Create New",                  // 0x0F
    "Check Directory",             // 0x10
    "Process Exit",                // 0x11
    "Seek",                        // 0x12
    "Lock And Read",               // 0x13
    "Write And Unlock",            // 0x14
    "Unknown",                     // 0X15
    "Unknown",                     // 0X16
    "Unknown",                     // 0X17
    "Unknown",                     // 0X18
    "Unknown",                     // 0X19
    "Read Raw",                    // 0x1A
    "Read Mpx",                    // 0x1B
    "Read Mpx Secondary",          // 0x1C
    "Write Raw",                   // 0x1D
    "Write Mpx",                   // 0x1E
    "Write Mpx Secondary",         // 0x1F
    "Write Complete",              // 0x20
    "Query Server",                // 0x21
    "Set Information2",            // 0x22
    "Query Information2",          // 0x23
    "Locking AndX",                // 0x24
    "Transaction",                 // 0x25
    "Transaction Secondary",       // 0x26
    "Ioctl",                       // 0x27
    "Ioctl Secondary",             // 0x28
    "Copy",                        // 0x29
    "Move",                        // 0x2A
    "Echo",                        // 0x2B
    "Write And Close",             // 0x2C
    "Open AndX",                   // 0x2D
    "Read AndX",                   // 0x2E
    "Write AndX",                  // 0x2F
    "New File Size",               // 0x30
    "Close And Tree Disc",         // 0x31
    "Transaction2",                // 0x32
    "Transaction2 Secondary",      // 0x33
    "Find Close2",                 // 0x34
    "Find Notify Close",           // 0x35
    "Unknown",                     // 0X36
    "Unknown",                     // 0X37
    "Unknown",                     // 0X38
    "Unknown",                     // 0X39
    "Unknown",                     // 0X3A
    "Unknown",                     // 0X3B
    "Unknown",                     // 0X3C
    "Unknown",                     // 0X3D
    "Unknown",                     // 0X3E
    "Unknown",                     // 0X3F
    "Unknown",                     // 0X40
    "Unknown",                     // 0X41
    "Unknown",                     // 0X42
    "Unknown",                     // 0X43
    "Unknown",                     // 0X44
    "Unknown",                     // 0X45
    "Unknown",                     // 0X46
    "Unknown",                     // 0X47
    "Unknown",                     // 0X48
    "Unknown",                     // 0X49
    "Unknown",                     // 0X4A
    "Unknown",                     // 0X4B
    "Unknown",                     // 0X4C
    "Unknown",                     // 0X4D
    "Unknown",                     // 0X4E
    "Unknown",                     // 0X4F
    "Unknown",                     // 0X50
    "Unknown",                     // 0X51
    "Unknown",                     // 0X52
    "Unknown",                     // 0X53
    "Unknown",                     // 0X54
    "Unknown",                     // 0X55
    "Unknown",                     // 0X56
    "Unknown",                     // 0X57
    "Unknown",                     // 0X58
    "Unknown",                     // 0X59
    "Unknown",                     // 0X5A
    "Unknown",                     // 0X5B
    "Unknown",                     // 0X5C
    "Unknown",                     // 0X5D
    "Unknown",                     // 0X5E
    "Unknown",                     // 0X5F
    "Unknown",                     // 0X60
    "Unknown",                     // 0X61
    "Unknown",                     // 0X62
    "Unknown",                     // 0X63
    "Unknown",                     // 0X64
    "Unknown",                     // 0X65
    "Unknown",                     // 0X66
    "Unknown",                     // 0X67
    "Unknown",                     // 0X68
    "Unknown",                     // 0X69
    "Unknown",                     // 0X6A
    "Unknown",                     // 0X6B
    "Unknown",                     // 0X6C
    "Unknown",                     // 0X6D
    "Unknown",                     // 0X6E
    "Unknown",                     // 0X6F
    "Tree Connect",                // 0x70
    "Tree Disconnect",             // 0x71
    "Negotiate",                   // 0x72
    "Session Setup AndX",          // 0x73
    "Logoff AndX",                 // 0x74
    "Tree Connect AndX",           // 0x75
    "Unknown",                     // 0X76
    "Unknown",                     // 0X77
    "Unknown",                     // 0X78
    "Unknown",                     // 0X79
    "Unknown",                     // 0X7A
    "Unknown",                     // 0X7B
    "Unknown",                     // 0X7C
    "Unknown",                     // 0X7D
    "Security Package AndX",       // 0x7E
    "Unknown",                     // 0X7F
    "Query Information Disk",      // 0x80
    "Search",                      // 0x81
    "Find",                        // 0x82
    "Find Unique",                 // 0x83
    "Find Close",                  // 0x84
    "Unknown",                     // 0X85
    "Unknown",                     // 0X86
    "Unknown",                     // 0X87
    "Unknown",                     // 0X88
    "Unknown",                     // 0X89
    "Unknown",                     // 0X8A
    "Unknown",                     // 0X8B
    "Unknown",                     // 0X8C
    "Unknown",                     // 0X8D
    "Unknown",                     // 0X8E
    "Unknown",                     // 0X8F
    "Unknown",                     // 0X90
    "Unknown",                     // 0X91
    "Unknown",                     // 0X92
    "Unknown",                     // 0X93
    "Unknown",                     // 0X94
    "Unknown",                     // 0X95
    "Unknown",                     // 0X96
    "Unknown",                     // 0X97
    "Unknown",                     // 0X98
    "Unknown",                     // 0X99
    "Unknown",                     // 0X9A
    "Unknown",                     // 0X9B
    "Unknown",                     // 0X9C
    "Unknown",                     // 0X9D
    "Unknown",                     // 0X9E
    "Unknown",                     // 0X9F
    "Nt Transact",                 // 0xA0
    "Nt Transact Secondary",       // 0xA1
    "Nt Create AndX",              // 0xA2
    "Unknown",                     // 0XA3
    "Nt Cancel",                   // 0xA4
    "Nt Rename",                   // 0xA5
    "Unknown",                     // 0XA6
    "Unknown",                     // 0XA7
    "Unknown",                     // 0XA8
    "Unknown",                     // 0XA9
    "Unknown",                     // 0XAA
    "Unknown",                     // 0XAB
    "Unknown",                     // 0XAC
    "Unknown",                     // 0XAD
    "Unknown",                     // 0XAE
    "Unknown",                     // 0XAF
    "Unknown",                     // 0XB0
    "Unknown",                     // 0XB1
    "Unknown",                     // 0XB2
    "Unknown",                     // 0XB3
    "Unknown",                     // 0XB4
    "Unknown",                     // 0XB5
    "Unknown",                     // 0XB6
    "Unknown",                     // 0XB7
    "Unknown",                     // 0XB8
    "Unknown",                     // 0XB9
    "Unknown",                     // 0XBA
    "Unknown",                     // 0XBB
    "Unknown",                     // 0XBC
    "Unknown",                     // 0XBD
    "Unknown",                     // 0XBE
    "Unknown",                     // 0XBF
    "Open Print File",             // 0xC0
    "Write Print File",            // 0xC1
    "Close Print File",            // 0xC2
    "Get Print Queue",             // 0xC3
    "Unknown",                     // 0XC4
    "Unknown",                     // 0XC5
    "Unknown",                     // 0XC6
    "Unknown",                     // 0XC7
    "Unknown",                     // 0XC8
    "Unknown",                     // 0XC9
    "Unknown",                     // 0XCA
    "Unknown",                     // 0XCB
    "Unknown",                     // 0XCC
    "Unknown",                     // 0XCD
    "Unknown",                     // 0XCE
    "Unknown",                     // 0XCF
    "Unknown",                     // 0XD0
    "Unknown",                     // 0XD1
    "Unknown",                     // 0XD2
    "Unknown",                     // 0XD3
    "Unknown",                     // 0XD4
    "Unknown",                     // 0XD5
    "Unknown",                     // 0XD6
    "Unknown",                     // 0XD7
    "Read Bulk",                   // 0xD8
    "Write Bulk",                  // 0xD9
    "Write Bulk Data",             // 0xDA
    "Unknown",                     // 0XDB
    "Unknown",                     // 0XDC
    "Unknown",                     // 0XDD
    "Unknown",                     // 0XDE
    "Unknown",                     // 0XDF
    "Unknown",                     // 0XE0
    "Unknown",                     // 0XE1
    "Unknown",                     // 0XE2
    "Unknown",                     // 0XE3
    "Unknown",                     // 0XE4
    "Unknown",                     // 0XE5
    "Unknown",                     // 0XE6
    "Unknown",                     // 0XE7
    "Unknown",                     // 0XE8
    "Unknown",                     // 0XE9
    "Unknown",                     // 0XEA
    "Unknown",                     // 0XEB
    "Unknown",                     // 0XEC
    "Unknown",                     // 0XED
    "Unknown",                     // 0XEE
    "Unknown",                     // 0XEF
    "Unknown",                     // 0XF0
    "Unknown",                     // 0XF1
    "Unknown",                     // 0XF2
    "Unknown",                     // 0XF3
    "Unknown",                     // 0XF4
    "Unknown",                     // 0XF5
    "Unknown",                     // 0XF6
    "Unknown",                     // 0XF7
    "Unknown",                     // 0XF8
    "Unknown",                     // 0XF9
    "Unknown",                     // 0XFA
    "Unknown",                     // 0XFB
    "Unknown",                     // 0XFC
    "Unknown",                     // 0XFD
    "Invalid",                     // 0xFE
    "No AndX Command"              // 0xFF
};

const char *smb_transaction_sub_command_strings[TRANS_SUBCOM_MAX] = {
    "Unknown",                               // 0x0000
    "TRANS_SET_NMPIPE_STATE",                // 0x0001
    "Unknown",                               // 0x0002
    "Unknown",                               // 0x0003
    "Unknown",                               // 0x0004
    "Unknown",                               // 0x0005
    "Unknown",                               // 0x0006
    "Unknown",                               // 0x0007
    "Unknown",                               // 0x0008
    "Unknown",                               // 0x0009
    "Unknown",                               // 0x000A
    "Unknown",                               // 0x000B
    "Unknown",                               // 0x000C
    "Unknown",                               // 0x000D
    "Unknown",                               // 0x000E
    "Unknown",                               // 0x000F
    "Unknown",                               // 0x0010
    "TRANS_RAW_READ_NMPIPE",                 // 0x0011
    "Unknown",                               // 0x0012
    "Unknown",                               // 0x0013
    "Unknown",                               // 0x0014
    "Unknown",                               // 0x0015
    "Unknown",                               // 0x0016
    "Unknown",                               // 0x0017
    "Unknown",                               // 0x0018
    "Unknown",                               // 0x0019
    "Unknown",                               // 0x001A
    "Unknown",                               // 0x001B
    "Unknown",                               // 0x001C
    "Unknown",                               // 0x001D
    "Unknown",                               // 0x001E
    "Unknown",                               // 0x001F
    "Unknown",                               // 0x0020
    "TRANS_QUERY_NMPIPE_STATE",              // 0x0021
    "TRANS_QUERY_NMPIPE_INFO",               // 0x0022
    "TRANS_PEEK_NMPIPE",                     // 0x0023
    "Unknown",                               // 0x0024
    "Unknown",                               // 0x0025
    "TRANS_TRANSACT_NMPIPE",                 // 0x0026
    "Unknown",                               // 0x0027
    "Unknown",                               // 0x0028
    "Unknown",                               // 0x0029
    "Unknown",                               // 0x002A
    "Unknown",                               // 0x002B
    "Unknown",                               // 0x002C
    "Unknown",                               // 0x002D
    "Unknown",                               // 0x002E
    "Unknown",                               // 0x002F
    "Unknown",                               // 0x0030
    "TRANS_RAW_WRITE_NMPIPE",                // 0x0031
    "Unknown",                               // 0x0032
    "Unknown",                               // 0x0033
    "Unknown",                               // 0x0034
    "Unknown",                               // 0x0035
    "TRANS_READ_NMPIPE",                     // 0x0036
    "TRANS_WRITE_NMPIPE",                    // 0x0037
    "Unknown",                               // 0x0038
    "Unknown",                               // 0x0039
    "Unknown",                               // 0x003A
    "Unknown",                               // 0x003B
    "Unknown",                               // 0x003C
    "Unknown",                               // 0x003D
    "Unknown",                               // 0x003E
    "Unknown",                               // 0x003F
    "Unknown",                               // 0x0040
    "Unknown",                               // 0x0041
    "Unknown",                               // 0x0042
    "Unknown",                               // 0x0043
    "Unknown",                               // 0x0044
    "Unknown",                               // 0x0045
    "Unknown",                               // 0x0046
    "Unknown",                               // 0x0047
    "Unknown",                               // 0x0048
    "Unknown",                               // 0x0049
    "Unknown",                               // 0x004A
    "Unknown",                               // 0x004B
    "Unknown",                               // 0x004C
    "Unknown",                               // 0x004D
    "Unknown",                               // 0x004E
    "Unknown",                               // 0x004F
    "Unknown",                               // 0x0050
    "Unknown",                               // 0x0051
    "Unknown",                               // 0x0052
    "TRANS_WAIT_NMPIPE",                     // 0x0053
    "TRANS_CALL_NMPIPE"                      // 0x0054
};

const char *smb_transaction2_sub_command_strings[TRANS2_SUBCOM_MAX] = {
    "TRANS2_OPEN2",                          // 0x0000
    "TRANS2_FIND_FIRST2",                    // 0x0001
    "TRANS2_FIND_NEXT2",                     // 0x0002
    "TRANS2_QUERY_FS_INFORMATION",           // 0x0003
    "TRANS2_SET_FS_INFORMATION",             // 0x0004
    "TRANS2_QUERY_PATH_INFORMATION",         // 0x0005
    "TRANS2_SET_PATH_INFORMATION",           // 0x0006
    "TRANS2_QUERY_FILE_INFORMATION",         // 0x0007
    "TRANS2_SET_FILE_INFORMATION",           // 0x0008
    "TRANS2_FSCTL",                          // 0x0009
    "TRANS2_IOCTL2",                         // 0x000A
    "TRANS2_FIND_NOTIFY_FIRST",              // 0x000B
    "TRANS2_FIND_NOTIFY_NEXT",               // 0x000C
    "TRANS2_CREATE_DIRECTORY",               // 0x000D
    "TRANS2_SESSION_SETUP",                  // 0x000E
    "Unknown",                               // 0x000F
    "TRANS2_GET_DFS_REFERRAL",               // 0x0010
    "TRANS2_REPORT_DFS_INCONSISTENCY"        // 0x0011
};

const char *smb_nt_transact_sub_command_strings[NT_TRANSACT_SUBCOM_MAX] = {
    "Unknown",                               // 0x0000
    "NT_TRANSACT_CREATE",                    // 0x0001
    "NT_TRANSACT_IOCTL",                     // 0x0002
    "NT_TRANSACT_SET_SECURITY_DESC",         // 0x0003
    "NT_TRANSACT_NOTIFY_CHANGE",             // 0x0004
    "NT_TRANSACT_RENAME",                    // 0x0005
    "NT_TRANSACT_QUERY_SECURITY_DESC"        // 0x0006
};

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static inline int DCE2_SmbType(DCE2_SmbSsnData *);
static inline void DCE2_SmbSetValidWordCount(uint8_t, uint8_t, uint8_t);
static inline bool DCE2_SmbIsValidWordCount(uint8_t, uint8_t, uint8_t);
static inline void DCE2_SmbSetValidByteCount(uint8_t, uint8_t, uint16_t, uint16_t);
static inline bool DCE2_SmbIsValidByteCount(uint8_t, uint8_t, uint16_t);
static DCE2_Ret DCE2_NbssHdrChecks(DCE2_SmbSsnData *, const NbssHdr *);
static DCE2_SmbRequestTracker * DCE2_SmbInspect(DCE2_SmbSsnData *, const SmbNtHdr *);
static DCE2_Ret DCE2_SmbHdrChecks(DCE2_SmbSsnData *, const SmbNtHdr *);
static uint32_t DCE2_IgnoreJunkData(const uint8_t *, uint16_t, uint32_t);
static inline DCE2_Ret DCE2_SmbHandleSegmentation(DCE2_Buffer **,
        const uint8_t *, uint32_t, uint32_t);
static inline DCE2_Buffer ** DCE2_SmbGetSegBuffer(DCE2_SmbSsnData *);
static inline uint32_t * DCE2_SmbGetIgnorePtr(DCE2_SmbSsnData *);
static inline DCE2_SmbDataState * DCE2_SmbGetDataState(DCE2_SmbSsnData *);
static inline bool DCE2_SmbIsSegBuffer(DCE2_SmbSsnData *, const uint8_t *);
static inline void DCE2_SmbSegAlert(DCE2_SmbSsnData *, DCE2_Event);
static inline bool DCE2_SmbIsRawData(DCE2_SmbSsnData *);
static void DCE2_SmbProcessRawData(DCE2_SmbSsnData *, const uint8_t *, uint32_t);
static DCE2_SmbComInfo * DCE2_SmbCheckCommand(DCE2_SmbSsnData *,
        const SmbNtHdr *, const uint8_t, const uint8_t *, uint32_t);
static void DCE2_SmbProcessCommand(DCE2_SmbSsnData *, const SmbNtHdr *, const uint8_t *, uint32_t);
static inline DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData *, const uint8_t *,
        const uint8_t *, const uint32_t, const uint16_t, const uint16_t, uint16_t);
static inline DCE2_Ret DCE2_SmbCheckTransDataParams(DCE2_SmbSsnData *,
        const uint8_t *, const uint8_t *, const uint32_t, const uint16_t,
        const uint32_t, const uint32_t, const uint32_t, const uint32_t);
static inline DCE2_Ret DCE2_SmbCheckTotalCount(DCE2_SmbSsnData *,
        const uint32_t, const uint32_t, const uint32_t);
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData *, const uint32_t,
        const uint16_t, const uint8_t, const uint16_t, const uint16_t);
static inline DCE2_Ret DCE2_SmbCheckAndXOffset(DCE2_SmbSsnData *, const uint8_t *,
        const uint8_t *, const uint32_t);
static inline void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData *,
        const SmbNtHdr *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t *, uint32_t, uint16_t, bool);
static inline bool DCE2_SmbIsTransactionComplete(DCE2_SmbTransactionTracker *);
static DCE2_Ret DCE2_SmbOpen(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbCreate(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbClose(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbRename(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbRead(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWrite(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbCreateNew(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndUnlock(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbReadRaw(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteRaw(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteComplete(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTransaction(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTransactionSecondary(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndClose(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbOpenAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbReadAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTransaction2(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTransaction2Secondary(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTreeConnect(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTreeDisconnect(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbLogoffAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbTreeConnectAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbNtTransact(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbNtTransactSecondary(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static DCE2_Ret DCE2_SmbNtCreateAndX(DCE2_SmbSsnData *, const SmbNtHdr *,
        const DCE2_SmbComInfo *, const uint8_t *, uint32_t);
static inline DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData *, const uint16_t,
        const uint8_t *, uint32_t);
static inline DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData *,
        const uint8_t *, uint32_t);
static inline DCE2_SmbRequestTracker * DCE2_SmbNewRequestTracker(DCE2_SmbSsnData *, const SmbNtHdr *);
static inline DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker *,
        const uint8_t *, uint16_t, uint16_t);
static inline DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker *,
        const uint8_t *, uint16_t, uint16_t);
static inline DCE2_SmbRequestTracker * DCE2_SmbFindRequestTracker(DCE2_SmbSsnData *,
        const SmbNtHdr *);
static inline void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData *, DCE2_SmbRequestTracker *);
static void DCE2_SmbInsertUid(DCE2_SmbSsnData *, const uint16_t);
static DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData *, const uint16_t);
static void DCE2_SmbRemoveUid(DCE2_SmbSsnData *ssd, const uint16_t);
static void DCE2_SmbInsertTid(DCE2_SmbSsnData *, const uint16_t);
static DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData *, const uint16_t);
static void DCE2_SmbRemoveTid(DCE2_SmbSsnData *, const uint16_t);
static DCE2_SmbPipeTracker * DCE2_SmbNewPipeTracker(DCE2_SmbSsnData *,
        const uint16_t, const uint16_t, const uint16_t);
static void DCE2_SmbQueueTmpPipeTracker(DCE2_SmbRequestTracker *,
        const uint16_t, const uint16_t);
static inline DCE2_SmbPipeTracker * DCE2_SmbGetTmpPipeTracker(DCE2_SmbRequestTracker *);
static inline void DCE2_SmbEmptyTmpPipeTrackerQueue(DCE2_SmbRequestTracker *);
static DCE2_SmbPipeTracker * DCE2_SmbDequeueTmpPipeTracker(DCE2_SmbSsnData *,
        DCE2_SmbRequestTracker *, const uint16_t);
static inline DCE2_SmbPipeTracker * DCE2_SmbGetPipeTracker(DCE2_SmbSsnData *,
        const uint16_t);
static DCE2_SmbPipeTracker * DCE2_SmbFindPipeTracker(DCE2_SmbSsnData *, const uint16_t,
        const uint16_t, const uint16_t);
static void DCE2_SmbRemovePipeTracker(DCE2_SmbSsnData *, DCE2_SmbPipeTracker *);
static inline void DCE2_SmbCleanPipeTracker(DCE2_SmbPipeTracker *);
static inline void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker *);
static inline void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker *);
static int DCE2_SmbUidTidFidCompare(const void *, const void *);
static void DCE2_SmbPipeTrackerDataFree(void *);
static void DCE2_SmbRequestTrackerDataFree(void *);
static inline SFSnortPacket * DCE2_SmbGetRpkt(DCE2_SmbSsnData *, const uint8_t **,
        uint32_t *, DCE2_RpktType);
static inline void DCE2_SmbReturnRpkt(void);

/********************************************************************
 * Function: DCE2_SmbType()
 *
 * Purpose:
 *  Since Windows and Samba don't seem to care or even look at the
 *  actual flag in the SMB header, make the determination based on
 *  whether from client or server.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - session data structure that has the raw
 *     packet and packet flags to make determination
 *
 * Returns:
 *  SMB_TYPE__REQUEST if packet is from client
 *  SMB_TYPE__RESPONSE if packet is from server
 *
 ********************************************************************/
static inline int DCE2_SmbType(DCE2_SmbSsnData *ssd)
{
    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
        return SMB_TYPE__REQUEST;
    else
        return SMB_TYPE__RESPONSE;
}

/********************************************************************
 * Function: DCE2_SmbSetValidWordCount()
 *
 * Purpose:
 *  Initializes global data for valid word counts for supported
 *  SMB command requests and responses.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the valid word count
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidWordCount(uint8_t com,
        uint8_t resp, uint8_t wct)
{
    smb_wcts[com][resp][wct/8] |= (1 << (wct % 8));
}

/********************************************************************
 * Function: DCE2_SmbIsValidWordCount()
 *
 * Purpose:
 *  Checks if a word count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the word count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidWordCount(uint8_t com,
        uint8_t resp, uint8_t wct)
{
    return (smb_wcts[com][resp][wct/8] & (1 << (wct % 8))) ? true : false;
}

/********************************************************************
 * Function: DCE2_SmbSetValidByteCount()
 *
 * Purpose:
 *  Initializes global data for valid byte counts as a range for
 *  supported SMB command requests and responses.
 *  Since a byte count is 2 bytes, a 4 byte type is used to store
 *  the range.  The maximum is in the most significant 2 bytes and
 *  the minimum in the least significant 2 bytes.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the minimum word count that is valid
 *  uint8_t - the maximum word count that is valid
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidByteCount(uint8_t com,
        uint8_t resp, uint16_t min, uint16_t max)
{
    smb_bccs[com][resp][0] = min;
    smb_bccs[com][resp][1] = max;
}

/********************************************************************
 * Function: DCE2_SmbIsValidByteCount()
 *
 * Purpose:
 *  Checks if a byte count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the byte count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidByteCount(uint8_t com,
        uint8_t resp, uint16_t bcc)
{
    return ((bcc < smb_bccs[com][resp][0])
            || (bcc > smb_bccs[com][resp][1])) ? false : true;
}

/********************************************************************
 * Function: DCE2_SmbGetMinByteCount()
 *
 * Purpose:
 *  Returns the minimum byte count for the given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *
 * Returns:
 *  uint16_t - the minimum byte count
 *
 ********************************************************************/
static inline uint16_t DCE2_SmbGetMinByteCount(uint8_t com, uint8_t resp)
{
    return smb_bccs[com][resp][0];
}

/********************************************************************
 * Function: DCE2_SmbInitGlobals()
 *
 * Purpose:
 *  Initializes global variables for SMB processing.
 *  Sets up the functions and valid word and byte counts for SMB
 *  commands.
 *  Sets up AndX chain mappings and valid command chaining for
 *  supported policies.
 *
 * Arguments: None
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbInitGlobals(void)
{
    int com;
    DCE2_Policy policy;
    SmbAndXCom andx;
    int i;

    memset(&smb_wcts, 0, sizeof(smb_wcts));
    memset(&smb_bccs, 0, sizeof(smb_bccs));

    // Sets up the function to call for the command and valid word and byte
    // counts for the command.  Ensuring valid word and byte counts is very
    // important to processing the command as it will assume the command is
    // legitimate and can access data that is acutally there.  Note that
    // commands with multiple word counts indicate a different command
    // structure, however most, if not all just have an extended version
    // of the structure for which the extended part isn't used.  If the
    // extended part of a command structure needs to be used, be sure to
    // check the word count in the command function before accessing data
    // in the extended version of the command structure.
    for (com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
            case SMB_COM_OPEN:
                smb_com_funcs[com] = DCE2_SmbOpen;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_CREATE:
                smb_com_funcs[com] = DCE2_SmbCreate;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_CLOSE:
                smb_com_funcs[com] = DCE2_SmbClose;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_RENAME:
                smb_com_funcs[com] = DCE2_SmbRename;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 1);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 4, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_READ:
                smb_com_funcs[com] = DCE2_SmbRead;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 5);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 3, UINT16_MAX);
                break;
            case SMB_COM_WRITE:
                smb_com_funcs[com] = DCE2_SmbWrite;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_CREATE_NEW:
                smb_com_funcs[com] = DCE2_SmbCreateNew;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_WRITE_AND_UNLOCK:
                smb_com_funcs[com] = DCE2_SmbWriteAndUnlock;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_READ_RAW:
                smb_com_funcs[com] = DCE2_SmbReadRaw;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
                // With optional OffsetHigh
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                // Response is raw data, i.e. without SMB
                break;
            case SMB_COM_WRITE_RAW:
                smb_com_funcs[com] = DCE2_SmbWriteRaw;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
                // With optional OffsetHigh
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
                // Interim server response
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_WRITE_COMPLETE:
                // Final server response to SMB_COM_WRITE_RAW
                smb_com_funcs[com] = DCE2_SmbWriteComplete;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_TRANSACTION:
                smb_com_funcs[com] = DCE2_SmbTransaction;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                // Word count depends on setup count
                //for (i = 14; i < 256; i++)
                //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
                // In reality, all subcommands of SMB_COM_TRANSACTION requests
                // have a setup count of 2 words.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 16);

                // \PIPE\LANMAN
                // Not something the preprocessor is looking at as it
                // doesn't carry DCE/RPC but don't want to false positive
                // on the preprocessor event.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);

                // Word count depends on setup count
                //for (i = 10; i < 256; i++)
                //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
                // In reality, all subcommands of SMB_COM_TRANSACTION responses
                // have a setup count of 0 words.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);

                // Interim server response
                // When client sends an incomplete transaction and needs to
                // send TransactionSecondary requests to complete request.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                // Exception will be made for Interim responses when
                // byte count is checked.
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_TRANSACTION_SECONDARY:
                smb_com_funcs[com] = DCE2_SmbTransactionSecondary;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
                // Response is an SMB_COM_TRANSACTION

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                break;
            case SMB_COM_WRITE_AND_CLOSE:
                smb_com_funcs[com] = DCE2_SmbWriteAndClose;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 6);
                // For some reason MS-CIFS specifies a version of this command
                // with 6 extra words (12 bytes) of reserved, i.e. useless data.
                // Maybe had intentions of extending and defining the data at
                // some point, but there is no documentation that I could find
                // that does.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_OPEN_ANDX:
                smb_com_funcs[com] = DCE2_SmbOpenAndX;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 15);
                // Extended response
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                // MS-SMB says that Windows 2000, XP and Vista set this to
                // some arbitrary value that is ignored on receipt.
                //DCE2_SmbSetValidByteCount(com, SMB_TYPE__RESPONSE, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_READ_ANDX:
                smb_com_funcs[com] = DCE2_SmbReadAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
                // With optional OffsetHigh
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 12);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_WRITE_ANDX:
                smb_com_funcs[com] = DCE2_SmbWriteAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
                // With optional OffsetHigh
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 6);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_TRANSACTION2:
                smb_com_funcs[com] = DCE2_SmbTransaction2;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                // Word count depends on setup count
                //for (i = 14; i < 256; i++)
                //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
                // In reality, all subcommands of SMB_COM_TRANSACTION2
                // requests have a setup count of 1 word.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);

                // Word count depends on setup count
                //for (i = 10; i < 256; i++)
                //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
                // In reality, all subcommands of SMB_COM_TRANSACTION2
                // responses have a setup count of 0 or 1 word.
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 11);

                // Interim server response
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                // Exception will be made for Interim responses when
                // byte count is checked.
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_TRANSACTION2_SECONDARY:
                smb_com_funcs[com] = DCE2_SmbTransaction2Secondary;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 9);
                // Response is an SMB_COM_TRANSACTION2

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                break;
            case SMB_COM_TREE_CONNECT:
                smb_com_funcs[com] = DCE2_SmbTreeConnect;

                smb_deprecated_coms[com] = true;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 6, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_TREE_DISCONNECT:
                smb_com_funcs[com] = DCE2_SmbTreeDisconnect;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_NEGOTIATE:
                // Not doing anything with this command right now.
                smb_com_funcs[com] = DCE2_SmbNegotiate;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 13);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 17);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                // This can vary depending on dialect so just set wide.
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_SESSION_SETUP_ANDX:
                smb_com_funcs[com] = DCE2_SmbSessionSetupAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 13);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 4);

                // These can vary so just set wide.
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_LOGOFF_ANDX:
                smb_com_funcs[com] = DCE2_SmbLogoffAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
                // Windows responds to a LogoffAndX => SessionSetupAndX with just a
                // LogoffAndX and with the word count field containing 3, but only
                // has 2 words
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                break;
            case SMB_COM_TREE_CONNECT_ANDX:
                smb_com_funcs[com] = DCE2_SmbTreeConnectAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 4);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
                // Extended response
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 2, UINT16_MAX);
                break;
            case SMB_COM_NT_TRANSACT:
                smb_com_funcs[com] = DCE2_SmbNtTransact;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                // Word count depends on setup count
                // In reality, all subcommands of SMB_COM_NT_TRANSACT
                // requests have a setup count of 0 or 4 words.
                //for (i = 19; i < 256; i++)
                //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, i);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 19);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 23);

                // Word count depends on setup count
                // In reality, all subcommands of SMB_COM_NT_TRANSACT
                // responses have a setup count of 0 or 1 word.
                //for (i = 18; i < 256; i++)
                //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, i);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 18);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

                // Interim server response
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

                // Exception will be made for Interim responses when
                // byte count is checked.
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            case SMB_COM_NT_TRANSACT_SECONDARY:
                smb_com_funcs[com] = DCE2_SmbNtTransactSecondary;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 18);
                // Response is an SMB_COM_NT_TRANSACT

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                break;
            case SMB_COM_NT_CREATE_ANDX:
                smb_com_funcs[com] = DCE2_SmbNtCreateAndX;

                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;

                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 24);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 34);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 26);
                // Extended response - though there are actually 50 words
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 42);

                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
                // MS-SMB indicates that this field should be 0 but may be
                // sent uninitialized so basically ignore it.
                //DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
            default:
                smb_com_funcs[com] = NULL;
                smb_deprecated_coms[com] = false;
                smb_unusual_coms[com] = false;
                // Just set to all valid since the specific command won't
                // be processed.  Don't want to false positive on these.
                for (i = 0; i < 256; i++)
                {
                    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, (uint8_t)i);
                    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, (uint8_t)i);
                }
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
                DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
                break;
        }
    }

    // Maps commands for use in quickly determining if a command
    // is chainable and what command it is.
    for (com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
            case SMB_COM_SESSION_SETUP_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__SESSION_SETUP_ANDX;
                break;
            case SMB_COM_LOGOFF_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__LOGOFF_ANDX;
                break;
            case SMB_COM_TREE_CONNECT_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__TREE_CONNECT_ANDX;
                break;
            case SMB_COM_OPEN_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__OPEN_ANDX;
                break;
            case SMB_COM_NT_CREATE_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__NT_CREATE_ANDX;
                break;
            case SMB_COM_WRITE_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__WRITE_ANDX;
                break;
            case SMB_COM_READ_ANDX:
                smb_chain_map[com] = SMB_ANDX_COM__READ_ANDX;
                break;
            default:
                smb_chain_map[com] = SMB_ANDX_COM__NONE;
                break;
        }
    }

    // Sets up the valid command chaining combinations per policy
    for (policy = DCE2_POLICY__NONE; policy < DCE2_POLICY__MAX; policy++)
    {
        for (andx = SMB_ANDX_COM__NONE; andx < SMB_ANDX_COM__MAX; andx++)
        {
            /* com is the chained command or com2 */
            for (com = 0; com < SMB_MAX_NUM_COMS; com++)
            {
                DCE2_SmbComFunc com_func = NULL;

                switch (policy)
                {
                    case DCE2_POLICY__WIN2000:
                    case DCE2_POLICY__WINXP:
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2003:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                        switch (andx)
                        {
                            case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_OPEN:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_CREATE:
                                    case SMB_COM_CREATE_NEW:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    case SMB_COM_TRANSACTION:
                                        if (policy == DCE2_POLICY__WIN2000)
                                            com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__LOGOFF_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_TREE_CONNECT_ANDX:   // Only for responses
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_OPEN:
                                    case SMB_COM_CREATE:
                                    case SMB_COM_CREATE_NEW:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    case SMB_COM_TRANSACTION:
                                        if (policy == DCE2_POLICY__WIN2000)
                                            com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__OPEN_ANDX:
                            case SMB_ANDX_COM__NT_CREATE_ANDX:
                                break;
                            case SMB_ANDX_COM__WRITE_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_WRITE_ANDX:
                                    case SMB_COM_READ:
                                    case SMB_COM_READ_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__READ_ANDX:
                                break;
                            default:
                                break;
                        }
                        break;
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        switch (andx)
                        {
                            case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_CONNECT:
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_READ_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    case SMB_COM_WRITE:
                                        if ((policy == DCE2_POLICY__SAMBA_3_0_22)
                                                || (policy == DCE2_POLICY__SAMBA_3_0_20))
                                            com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__LOGOFF_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_WRITE:
                                    case SMB_COM_READ_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__OPEN_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_CONNECT:
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_WRITE:
                                    case SMB_COM_READ_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__NT_CREATE_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_TREE_CONNECT:
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_WRITE:
                                    case SMB_COM_READ_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                    case SMB_COM_CLOSE:
                                        if ((policy == DCE2_POLICY__SAMBA)
                                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                            com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__WRITE_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_CONNECT:
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_WRITE:
                                    case SMB_COM_READ_ANDX:
                                    case SMB_COM_WRITE_ANDX:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case SMB_ANDX_COM__READ_ANDX:
                                switch (com)
                                {
                                    case SMB_COM_SESSION_SETUP_ANDX:
                                    case SMB_COM_WRITE:
                                        com_func = smb_com_funcs[com];
                                        break;
                                    case SMB_COM_LOGOFF_ANDX:
                                    case SMB_COM_TREE_CONNECT:
                                    case SMB_COM_TREE_CONNECT_ANDX:
                                    case SMB_COM_TREE_DISCONNECT:
                                    case SMB_COM_OPEN_ANDX:
                                    case SMB_COM_NT_CREATE_ANDX:
                                    case SMB_COM_CLOSE:
                                    case SMB_COM_READ_ANDX:
                                        if ((policy == DCE2_POLICY__SAMBA)
                                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                            com_func = smb_com_funcs[com];
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }

                smb_chain_funcs[policy][andx][com] = com_func;
            }
        }
    }
}

/********************************************************************
 * Function: DCE2_SmbInitRdata()
 *
 * Purpose:
 *  Initializes the reassembled packet structure for an SMB
 *  reassembled packet.  Uses WriteAndX and ReadAndX.
 *  TODO Use command that was used when reassembly occurred.
 *  One issue with this is that multiple different write/read
 *  commands can be used to write/read the full DCE/RPC
 *  request/response.
 *
 * Arguments:
 *  uint8_t * - pointer to the start of the NetBIOS header where
 *              data initialization should start.
 *  int dir   - FLAG_FROM_CLIENT or FLAG_FROM_SERVER
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbInitRdata(uint8_t *nb_ptr, int dir)
{
    NbssHdr *nb_hdr = (NbssHdr *)nb_ptr;
    SmbNtHdr *smb_hdr = (SmbNtHdr *)((uint8_t *)nb_hdr + sizeof(NbssHdr));

    nb_hdr->type = NBSS_SESSION_TYPE__MESSAGE;
    memcpy((void *)smb_hdr->smb_idf, (void *)"\xffSMB", sizeof(smb_hdr->smb_idf));

    if (dir == FLAG_FROM_CLIENT)
    {
        SmbWriteAndXReq *writex =
            (SmbWriteAndXReq *)((uint8_t *)smb_hdr + sizeof(SmbNtHdr));
        uint16_t offset = sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq);

        smb_hdr->smb_com = SMB_COM_WRITE_ANDX;
        smb_hdr->smb_flg = 0x00;

        writex->smb_wct = 12;
        writex->smb_com2 = SMB_COM_NO_ANDX_COMMAND;
        writex->smb_doff = SmbHtons(&offset);
    }
    else
    {
        SmbReadAndXResp *readx =
            (SmbReadAndXResp *)((uint8_t *)smb_hdr + sizeof(SmbNtHdr));
        uint16_t offset = sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp);

        smb_hdr->smb_com = SMB_COM_READ_ANDX;
        smb_hdr->smb_flg = 0x80;

        readx->smb_wct = 12;
        readx->smb_com2 = SMB_COM_NO_ANDX_COMMAND;
        readx->smb_doff = SmbHtons(&offset);
    }
}

/********************************************************************
 * Function: DCE2_SmbSetRdata()
 *
 * Purpose:
 *  When a reassembled packet is needed this function is called to
 *  fill in appropriate fields to make the reassembled packet look
 *  correct from an SMB standpoint.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  uint8_t * - pointer to the start of the NetBIOS header where
 *              data initialization should start.
 *  uint16_t  - the length of the connection-oriented DCE/RPC data.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbSetRdata(DCE2_SmbSsnData *ssd, uint8_t *nb_ptr, uint16_t co_len)
{
    NbssHdr *nb_hdr = (NbssHdr *)nb_ptr;
    SmbNtHdr *smb_hdr = (SmbNtHdr *)((uint8_t *)nb_hdr + sizeof(NbssHdr));
    uint16_t uid = (ssd->cur_rtracker == NULL) ? 0 : ssd->cur_rtracker->uid;
    uint16_t tid = (ssd->cur_rtracker == NULL) ? 0 : ssd->cur_rtracker->tid;
    DCE2_SmbPipeTracker *ptracker = (ssd->cur_rtracker == NULL) ? NULL : ssd->cur_rtracker->ptracker;

    smb_hdr->smb_uid = SmbHtons((const uint16_t *)&uid);
    smb_hdr->smb_tid = SmbHtons((const uint16_t *)&tid);

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
    {
        SmbWriteAndXReq *writex =
            (SmbWriteAndXReq *)((uint8_t *)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq) + co_len;

        /* The data will get truncated anyway since we can only fit
         * 64K in the reassembly buffer */
        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);

        if ((ptracker != NULL) && (ptracker->fid > 0))
        {
            uint16_t fid = (uint16_t)ptracker->fid;
            writex->smb_fid = SmbHtons(&fid);
        }
        else
        {
            writex->smb_fid = 0;
        }

        writex->smb_countleft = SmbHtons(&co_len);
        writex->smb_dsize = SmbHtons(&co_len);
        writex->smb_bcc = SmbHtons(&co_len);
    }
    else
    {
        SmbReadAndXResp *readx =
            (SmbReadAndXResp *)((uint8_t *)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp) + co_len;

        /* The data will get truncated anyway since we can only fit
         * 64K in the reassembly buffer */
        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);

        readx->smb_remaining = SmbHtons(&co_len);
        readx->smb_dsize = SmbHtons(&co_len);
        readx->smb_bcc = SmbHtons(&co_len);
    }
}

/********************************************************************
 * Function: DCE2_SmbSsnInit()
 *
 * Purpose:
 *  Allocates and initializes a new session data structure.
 *
 * Arguments: None
 *
 * Returns:
 *  DCE2_SmbSsnData * - a new initialized session data structure.
 *
 ********************************************************************/
DCE2_SmbSsnData * DCE2_SmbSsnInit(SFSnortPacket *p)
{
    DCE2_SmbSsnData *ssd =
        (DCE2_SmbSsnData *)DCE2_Alloc(sizeof(DCE2_SmbSsnData), DCE2_MEM_TYPE__SMB_SSN);

    if (ssd == NULL)
        return NULL;

    ssd->dialect_index = DCE2_SENTINEL;
    ssd->max_outstanding_requests = 10;  // Until Negotiate/SessionSetupAndX 
    ssd->cli_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
    ssd->srv_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
    ssd->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;

    ssd->uid = DCE2_SENTINEL;
    ssd->tid = DCE2_SENTINEL;
    ssd->ptracker.fid = DCE2_SENTINEL;
    ssd->rtracker.mid = DCE2_SENTINEL;

    DCE2_ResetRopts(&ssd->sd.ropts);

    dce2_stats.smb_sessions++;

    return ssd;
}

/********************************************************************
 * Function: DCE2_NbssHdrChecks()
 *
 * Purpose:
 *  Does validation of the NetBIOS header.  SMB will only run over
 *  the Session Message type.  On port 139, there is always an
 *  initial Session Request / Session Positive/Negative response
 *  followed by the normal SMB conversation, i.e. Negotiate,
 *  SessionSetupAndX, etc.
 *  Side effects are potential alerts for anomolous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const NbssHdr *   - pointer to the NetBIOS Session Service
 *                      header structure.  Size is already validated.
 *
 * Returns:
 *  DCE2_Ret  -  DCE2_RET__SUCCESS if all goes well and processing
 *               should continue.
 *               DCE2_RET__IGNORE if it's not something we need to
 *               look at.
 *               DCE2_RET__ERROR if an invalid NetBIOS Session
 *               Service type is found.
 *
 ********************************************************************/
static DCE2_Ret DCE2_NbssHdrChecks(DCE2_SmbSsnData *ssd, const NbssHdr *nb_hdr)
{
    const SFSnortPacket *p = ssd->sd.wire_pkt;
    bool is_seg_buf = DCE2_SmbIsSegBuffer(ssd, (uint8_t *)nb_hdr);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "NetBIOS Session Service type: "));

    switch (NbssType(nb_hdr))
    {
        case NBSS_SESSION_TYPE__MESSAGE:
            /* Only want to look at session messages */
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Session Message\n"));

            if (!DCE2_SmbIsRawData(ssd))
            {
                uint32_t nb_len = NbssLen(nb_hdr);

                if (nb_len == 0)
                    return DCE2_RET__IGNORE;

                if (nb_len < sizeof(SmbNtHdr))
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "NetBIOS SS len(%u) < SMB header len(%u).\n",
                                sizeof(SmbNtHdr), sizeof(NbssHdr) + nb_len));

                    if (is_seg_buf)
                        DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_NB_LT_SMBHDR);
                    else
                        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_SMBHDR, nb_len, sizeof(SmbNtHdr));

                    return DCE2_RET__IGNORE;
                }
            }

            return DCE2_RET__SUCCESS;

        case NBSS_SESSION_TYPE__REQUEST:
            dce2_stats.smb_nbss_not_message++;
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Session Request\n"));
            if (DCE2_SsnFromServer(p))
            {
                if (is_seg_buf)
                    DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
                else
                    DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
            }

            break;

        case NBSS_SESSION_TYPE__POS_RESPONSE:
        case NBSS_SESSION_TYPE__NEG_RESPONSE:
        case NBSS_SESSION_TYPE__RETARGET_RESPONSE:
            dce2_stats.smb_nbss_not_message++;
            DCE2_DEBUG_CODE(DCE2_DEBUG__SMB,
                    if (NbssType(nb_hdr) == NBSS_SESSION_TYPE__POS_RESPONSE)
                    printf("Positive Session Response\n");
                    else if (NbssType(nb_hdr) == NBSS_SESSION_TYPE__NEG_RESPONSE)
                    printf("Negative Session Response\n");
                    else printf("Session Retarget Response\n"););
            if (DCE2_SsnFromClient(p))
            {
                if (is_seg_buf)
                    DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
                else
                    DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
            }

            break;

        case NBSS_SESSION_TYPE__KEEP_ALIVE:
            dce2_stats.smb_nbss_not_message++;
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Session Keep Alive\n"));
            break;

        default:
            dce2_stats.smb_nbss_not_message++;
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                        "Invalid Session Service type: 0x%02X\n", NbssType(nb_hdr)));

            if (is_seg_buf)
                DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
            else
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);

            return DCE2_RET__ERROR;
    }

    return DCE2_RET__IGNORE;
}

/********************************************************************
 * Function: DCE2_SmbInspect()
 *
 * Purpose:
 *  Determines whether the SMB command is something the preprocessor
 *  needs to inspect.
 *  This function returns a DCE2_SmbRequestTracker which tracks command
 *  requests / responses.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const SmbNtHdr *  - pointer to the SMB header.
 *
 * Returns:
 *  DCE2_SmbRequestTracker * - NULL if it's not something we want to or can
 *                     inspect.
 *                     Otherwise an initialized structure if request
 *                     and the found structure if response.
 *
 ********************************************************************/
static DCE2_SmbRequestTracker * DCE2_SmbInspect(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbRequestTracker *rtracker = NULL;
    int smb_com = SmbCom(smb_hdr);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "SMB command: %s (0x%02X)\n",
                smb_com_strings[smb_com], smb_com));

    if (smb_com_funcs[smb_com] == NULL)
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Command isn't processed "
                    "by preprocessor.\n"));
        return NULL;
    }

    // See if this is something we need to inspect
    if (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
    {
        switch (smb_com)
        {
            case SMB_COM_NEGOTIATE:
                if (ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED)
                {
                    DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_MULTIPLE_NEGOTIATIONS);
                    return NULL;
                }
                break;
            case SMB_COM_SESSION_SETUP_ANDX:
                break;
            case SMB_COM_TREE_CONNECT:
            case SMB_COM_TREE_CONNECT_ANDX:
            case SMB_COM_RENAME:
            case SMB_COM_LOGOFF_ANDX:
                if (DCE2_SmbFindUid(ssd, SmbUid(smb_hdr)) != DCE2_RET__SUCCESS)
                    return NULL;
                break;
            //case SMB_COM_NT_TRANSACT:   // NT_TRANSACT_CREATE
            case SMB_COM_TRANSACTION2:  // TRANS2_OPEN2
                // The preprocessor is currently only looking at the
                // above noted subcommands and Samba doesn't support these
                // opens under an IPC tree.  If other subcommands need to
                // be implemented, these need to be retested for the new
                // supported subcommands.
                // Samba actually does support NT_TRANSACT_CREATE but it's
                // implementation is bad since it parses the pipe name
                // incorrectly, however one can get it to work by adding
                // an extra non-slash character before the actual pipe name.
                // For TRANS2_OPEN2, Samba initially allows it because it
                // has the CAN_IPC flag, but for some reason aborts if it's IPC
                // so doesn't process it.
                switch (policy)
                {
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Samba "
                                    "doesn't process Transaction2/Trans2Open2 "
                                    "under an IPC tree which is the only "
                                    "Transaction2 subcommand processed by "
                                    "the preprocessor.\n"));
                        return NULL;
                    default:
                        break;
                }
                break;
            case SMB_COM_OPEN:
            case SMB_COM_CREATE:
            case SMB_COM_CREATE_NEW:
            case SMB_COM_WRITE_AND_CLOSE:
            case SMB_COM_WRITE_AND_UNLOCK:
            case SMB_COM_READ:
                // Samba doesn't allow these commands under an IPC tree
                switch (policy)
                {
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Samba doesn't "
                                    "process this command under an IPC tree.\n"));
                        return NULL;
                    default:
                        break;
                }
                break;
            case SMB_COM_READ_RAW:
            case SMB_COM_WRITE_RAW:
                // Samba and Windows Vista on don't allow these commands
                // under an IPC tree, whether or not the raw read/write
                // flag is set in the Negotiate capabilities.
                // Windows RSTs the connection and Samba FINs it.
                switch (policy)
                {
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Samba and "
                                    "Windows Vista on don't process this "
                                    "command under an IPC tree.\n"));
                        return NULL;
                    default:
                        break;
                }
                break;
            default:
                if (DCE2_SmbFindTid(ssd, SmbTid(smb_hdr)) != DCE2_RET__SUCCESS)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Couldn't find IPC Tid (%u)\n", SmbTid(smb_hdr)));

                    dce2_stats.smb_non_ipc_packets++;
                    return NULL;
                }
                break;
        }

        switch (smb_com)
        {
            case SMB_COM_TRANSACTION_SECONDARY:
            case SMB_COM_TRANSACTION2_SECONDARY:
            case SMB_COM_NT_TRANSACT_SECONDARY:
                rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
                break;
            case SMB_COM_TRANSACTION:
            case SMB_COM_TRANSACTION2:
            case SMB_COM_NT_TRANSACT:
                // If there is already and existing request tracker
                // and the transaction is not complete, server will
                // return an error.
                rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
                if (rtracker != NULL)
                    break;
                // Fall through
            default:
                rtracker = DCE2_SmbNewRequestTracker(ssd, smb_hdr);
                break;
        }
    }
    else
    {
        rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
    }

    DCE2_DEBUG_CODE(DCE2_DEBUG__SMB,
            if (rtracker == NULL) printf("Failed to get request tracker.\n"););

    return rtracker;
}

/********************************************************************
 * Function: DCE2_SmbHdrChecks()
 *
 * Checks some relevant fields in the header to make sure they're
 * sane.
 * Side effects are potential alerts for anomolous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to the session data structure.
 *  SmbNtHdr *
 *      Pointer to the header struct layed over the packet data.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we should continue processing, but
 *          ignore data because of the error.
 *      DCE2_RET__SUCCESS if we should continue processing.
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbHdrChecks(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr)
{
    const SFSnortPacket *p = ssd->sd.wire_pkt;
    bool is_seg_buf = DCE2_SmbIsSegBuffer(ssd, (uint8_t *)smb_hdr);

    if ((DCE2_SsnFromServer(p) && (SmbType(smb_hdr) == SMB_TYPE__REQUEST)) ||
            (DCE2_SsnFromClient(p) && (SmbType(smb_hdr) == SMB_TYPE__RESPONSE)))
    {
        if (is_seg_buf)
            DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_BAD_TYPE);
        else
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_TYPE);

        // Continue looking at traffic.  Neither Windows nor Samba seem
        // to care, or even look at this flag
    }

    if ((SmbId(smb_hdr) != DCE2_SMB_ID)
            && (SmbId(smb_hdr) != DCE2_SMB2_ID))
    {
        if (is_seg_buf)
            DCE2_SmbSegAlert(ssd, DCE2_EVENT__SMB_BAD_ID);
        else
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_ID);

        return DCE2_RET__IGNORE;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_IgnoreJunkData()
 *
 * Purpose:
 *   An evasion technique can be to put a bunch of junk data before
 *   the actual SMB request and it seems the MS implementation has
 *   no problem with it and seems to just ignore the data.  This
 *   function attempts to move past all the junk to get to the
 *   actual NetBIOS message request.
 *
 * Arguments:
 *   const uint8_t *  - pointer to the current position in the data
 *      being inspected
 *   uint16_t  -  the amount of data left to look at
 *   uint32_t  -  the amount of data to ignore if there doesn't seem
 *      to be any junk data.  Just use the length as if the bad
 *      NetBIOS header was good.
 *
 * Returns:
 *    uint32_t - the amount of bytes to ignore as junk.
 *
 ********************************************************************/
static uint32_t DCE2_IgnoreJunkData(const uint8_t *data_ptr, uint16_t data_len,
        uint32_t assumed_nb_len)
{
    const uint8_t *tmp_ptr = data_ptr;
    uint32_t ignore_bytes = 0;

    /* Try to find \xffSMB and go back 8 bytes to beginning
     * of what should be a Netbios header with type Session
     * Message (\x00) - do appropriate buffer checks to make
     * sure the index is in bounds. Ignore all intervening
     * bytes */

    while ((tmp_ptr + sizeof(uint32_t)) <= (data_ptr + data_len))
    {
        if ((SmbId((SmbNtHdr *)tmp_ptr) == DCE2_SMB_ID)
                || (SmbId((SmbNtHdr *)tmp_ptr) == DCE2_SMB2_ID))
        {
            break;
        }

        tmp_ptr++;
    }

    if ((tmp_ptr + sizeof(uint32_t)) > (data_ptr + data_len))
    {
        ignore_bytes = data_len;
    }
    else
    {
        if ((tmp_ptr - sizeof(NbssHdr)) > data_ptr)
            ignore_bytes = (tmp_ptr - data_ptr) - sizeof(NbssHdr);
        else  /* Just ignore whatever the bad NB header had as a length */
            ignore_bytes = assumed_nb_len;
    }

    return ignore_bytes;
}

/********************************************************************
 * Function: DCE2_SmbProcess()
 *
 * Purpose:
 *  This is the main entry point for SMB processing.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbProcess(DCE2_SmbSsnData *ssd)
{
    const SFSnortPacket *p = ssd->sd.wire_pkt;
    const uint8_t *data_ptr = p->payload;
    uint16_t data_len = p->payload_size;
    uint32_t *ignore_bytes = DCE2_SmbGetIgnorePtr(ssd);
    DCE2_Buffer **seg_buf = DCE2_SmbGetSegBuffer(ssd);
    DCE2_SmbDataState *data_state = DCE2_SmbGetDataState(ssd);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Processing SMB packet.\n"));
    dce2_stats.smb_pkts++;

    /* Have to account for segmentation.  Even though stream will give
     * us larger chunks, we might end up in the middle of something */
    while (data_len > 0)
    {
        // The amount of data needed in a given state to continue processing
        uint32_t data_need;
        NbssHdr *nb_hdr = NULL;
        SmbNtHdr *smb_hdr = NULL;
        uint32_t nb_len;
        const uint8_t *nb_ptr;
        DCE2_SmbRequestTracker *rtracker = NULL;
        DCE2_Ret status;

        // We are ignoring an entire PDU or junk data so state should be NETBIOS_HEADER
        // Note that it could be TCP segmented so ignore_bytes could be greater than
        // the amount of data we have
        if (*ignore_bytes)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Ignoring %u bytes\n", *ignore_bytes));

            if (data_len <= *ignore_bytes)
            {
                *ignore_bytes -= data_len;
                return;
            }
            else
            {
                /* ignore bytes is less than UINT16_MAX */
                DCE2_MOVE(data_ptr, data_len, (uint16_t)*ignore_bytes);
                *ignore_bytes = 0;
            }
        }

        switch (*data_state)
        {
            // This state is to verify it's a NetBIOS Session Message packet
            // and to get the length of the SMB PDU.  Also does the SMB junk
            // data check.  If it's not a Session Message the data isn't
            // processed since it won't be carrying SMB.
            case DCE2_SMB_DATA_STATE__NETBIOS_HEADER:
                data_need = sizeof(NbssHdr) - DCE2_BufferLength(*seg_buf);

                // See if there is enough data to process the NetBIOS header
                if (data_len < data_need)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data len(%u) < NetBIOS SS header(%u). "
                                "Queueing data.\n", data_len, data_need));

                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr,
                                data_len, sizeof(NbssHdr)) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                    }

                    return;
                }

                // Set the NetBIOS header structure
                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    nb_hdr = (NbssHdr *)data_ptr;
                }
                else
                {
                    // If data already buffered add the remainder for the
                    // size of the NetBIOS header
                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr,
                                data_need, sizeof(NbssHdr)) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        return;
                    }

                    nb_hdr = (NbssHdr *)DCE2_BufferData(*seg_buf);
                }

                nb_len = NbssLen(nb_hdr);
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                            "NetBIOS PDU length: %u\n", nb_len));

                status = DCE2_NbssHdrChecks(ssd, nb_hdr);
                if (status != DCE2_RET__SUCCESS)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not a NetBIOS Session Message.\n"));

                    if (status == DCE2_RET__IGNORE)
                    {
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Valid NetBIOS header "
                                    "type so ignoring NetBIOS length bytes.\n"));
                        *ignore_bytes = data_need + nb_len;
                    }
                    else  // nb_ret == DCE2_RET__ERROR, i.e. invalid NetBIOS type
                    {
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not a valid NetBIOS "
                                    "header type so trying to find \\xffSMB to "
                                    "determine how many bytes to ignore.\n"));

                        *ignore_bytes = DCE2_IgnoreJunkData(data_ptr, data_len, data_need + nb_len);
                    }

                    DCE2_BufferEmpty(*seg_buf);
                    dce2_stats.smb_ignored_bytes += *ignore_bytes;
                    continue;
                }

                if (!DCE2_BufferIsEmpty(*seg_buf))
                    DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

                switch (ssd->pdu_state)
                {
                    case DCE2_SMB_PDU_STATE__COMMAND:
                        *data_state = DCE2_SMB_DATA_STATE__SMB_HEADER;
                        break;
                    case DCE2_SMB_PDU_STATE__RAW_DATA:
                        *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;
                        // Continue here because of fall through below
                        continue;
                    default:
                        DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid SMB PDU "
                                "state: %d\n", __FILE__, __LINE__, ssd->pdu_state);
                        return;
                }

                // Fall through for DCE2_SMB_DATA_STATE__SMB_HEADER
                // This is the normal progression without segmentation.

                // This state is to do validation checks on the SMB header and
                // more importantly verify it's data that needs to be inspected.
                // If the TID in the SMB header is not referring to the IPC share
                // there won't be any DCE/RPC traffic associated with it.
            case DCE2_SMB_DATA_STATE__SMB_HEADER:
                data_need = (sizeof(NbssHdr) + sizeof(SmbNtHdr)) - DCE2_BufferLength(*seg_buf);

                // See if there is enough data to process the SMB header
                if (data_len < data_need)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data len (%u) < "
                                "NetBIOS SS header + SMB header (%u). Queueing data.\n",
                                data_len, data_need));

                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_len,
                                sizeof(NbssHdr) + sizeof(SmbNtHdr)) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                    }

                    return;
                }

                // Set the SMB header structure
                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    smb_hdr = (SmbNtHdr *)(data_ptr + sizeof(NbssHdr));
                }
                else
                {
                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_need,
                                sizeof(NbssHdr) + sizeof(SmbNtHdr)) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                        return;
                    }

                    smb_hdr = (SmbNtHdr *)(DCE2_BufferData(*seg_buf) + sizeof(NbssHdr));
                }

                // XXX Don't support SMB2 yet
                if (SmbId(smb_hdr) == DCE2_SMB2_ID)
                {
                    ssd->sd.flags |= DCE2_SSN_FLAG__NO_INSPECT;
                    return;
                }

                // See if this is something we need to inspect
                rtracker = DCE2_SmbInspect(ssd, smb_hdr);
                if (rtracker == NULL)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not inspecting SMB packet.\n"));

                    if (DCE2_BufferIsEmpty(*seg_buf))
                    {
                        *ignore_bytes = sizeof(NbssHdr) + NbssLen((NbssHdr *)data_ptr);
                    }
                    else
                    {
                        *ignore_bytes = (NbssLen((NbssHdr *)DCE2_BufferData(*seg_buf))
                                - sizeof(SmbNtHdr)) + data_need;
                        DCE2_BufferEmpty(*seg_buf);
                    }

                    *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

                    dce2_stats.smb_ignored_bytes += *ignore_bytes;
                    continue;
                }

                // Check the SMB header for anomolies
                if (DCE2_SmbHdrChecks(ssd, smb_hdr) != DCE2_RET__SUCCESS)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Bad SMB header.\n"));

                    if (DCE2_BufferIsEmpty(*seg_buf))
                    {
                        *ignore_bytes = sizeof(NbssHdr) + NbssLen((NbssHdr *)data_ptr);
                    }
                    else
                    {
                        *ignore_bytes = (NbssLen((NbssHdr *)DCE2_BufferData(*seg_buf))
                                - sizeof(SmbNtHdr)) + data_need;
                        DCE2_BufferEmpty(*seg_buf);
                    }

                    *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

                    dce2_stats.smb_ignored_bytes += *ignore_bytes;
                    continue;
                }

                if (!DCE2_BufferIsEmpty(*seg_buf))
                    DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;

                // Fall through

                // This state ensures that we have the entire PDU before continuing
                // to process.
            case DCE2_SMB_DATA_STATE__NETBIOS_PDU:
                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    nb_len = NbssLen((NbssHdr *)data_ptr);
                    data_need = sizeof(NbssHdr) + nb_len;
                }
                else
                {
                    nb_len = NbssLen((NbssHdr *)DCE2_BufferData(*seg_buf));
                    data_need = (sizeof(NbssHdr) + nb_len) - DCE2_BufferLength(*seg_buf);
                }

                /* It's something we want to inspect so make sure we have the full NBSS packet */
                if (data_len < data_need)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data len(%u) < "
                                "NetBIOS SS header + NetBIOS len(%u). "
                                "Queueing data.\n", data_len, sizeof(NbssHdr) + nb_len));

                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_len,
                                sizeof(NbssHdr) + nb_len) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                    }

                    return;
                }

                // data_len >= data_need which means data_need <= UINT16_MAX
                // So casts below of data_need to uint16_t are okay.

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    nb_ptr = data_ptr;
                    nb_len = data_need;
                    DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);
                }
                else
                {
                    SFSnortPacket *rpkt;

                    if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_need,
                                sizeof(NbssHdr) + nb_len) != DCE2_RET__SUCCESS)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);
                        continue;
                    }

                    DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

                    nb_ptr = DCE2_BufferData(*seg_buf);
                    nb_len = DCE2_BufferLength(*seg_buf);

                    // Get reassembled packet
                    rpkt = DCE2_SmbGetRpkt(ssd, &nb_ptr, &nb_len,
                            DCE2_RPKT_TYPE__SMB_SEG);
                    if (rpkt == NULL)
                    {
                        DCE2_BufferEmpty(*seg_buf);
                        continue;
                    }

                    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
                        dce2_stats.smb_cli_seg_reassembled++;
                    else
                        dce2_stats.smb_srv_seg_reassembled++;
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "TCP reassembled SMB PDU\n"));
                    DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););
                }

                switch (ssd->pdu_state)
                {
                    case DCE2_SMB_PDU_STATE__COMMAND:
                        smb_hdr = (SmbNtHdr *)(nb_ptr + sizeof(NbssHdr));
                        DCE2_MOVE(nb_ptr, nb_len, (sizeof(NbssHdr) + sizeof(SmbNtHdr)));
                        ssd->cur_rtracker = (rtracker != NULL)
                            ? rtracker : DCE2_SmbFindRequestTracker(ssd, smb_hdr);
                        if (ssd->cur_rtracker != NULL)
                            DCE2_SmbProcessCommand(ssd, smb_hdr, nb_ptr, nb_len);
                        break;
                    case DCE2_SMB_PDU_STATE__RAW_DATA:
                        DCE2_MOVE(nb_ptr, nb_len, sizeof(NbssHdr));
                        if (ssd->cur_rtracker != NULL)
                            DCE2_SmbProcessRawData(ssd, nb_ptr, nb_len);
                        // Only one raw read or write
                        ssd->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
                        break;
                    default:
                        DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid SMB PDU "
                                "state: %d\n", __FILE__, __LINE__, ssd->pdu_state);
                        return;
                }

                if (!DCE2_BufferIsEmpty(*seg_buf))
                {
                    DCE2_SmbReturnRpkt();
                    DCE2_BufferEmpty(*seg_buf);
                }

                break;

            default:
                DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid SMB Data "
                        "state: %d\n", __FILE__, __LINE__, *data_state);
                return;
        }
    }
}

/********************************************************************
 * Function: DCE2_SmbHandleSegmentation()
 *
 * Wrapper around DCE2_HandleSegmentation() to allocate a new
 * buffer object if necessary.
 *
 * Arguments:
 *  DCE2_SmbBuffer **
 *      Pointer to pointer of buffer to add data to.  If NULL
 *      a new buffer will be allocated.
 *  uint8_t *
 *      Pointer to the current data cursor in packet.
 *  uint32_t
 *      Length of data to add to buffer.
 *  uint32_t
 *      The minimum allocation size so that small allocations
 *      aren't consistently done.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__ERROR if an error occured.  Nothing can
 *          be trusted.
 *      DCE2_RET__SUCCESS if data was successfully added.
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbHandleSegmentation(DCE2_Buffer **buf,
        const uint8_t *data_ptr, uint32_t add_len, uint32_t alloc_size)
{
    DCE2_Ret status;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_seg);

    if (buf == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_seg);
        return DCE2_RET__ERROR;
    }

    if (*buf == NULL)
    {
        /* No initial size or min alloc size */
        *buf = DCE2_BufferNew(alloc_size, alloc_size, DCE2_MEM_TYPE__SMB_SEG);
        if (*buf == NULL)
        {
            PREPROC_PROFILE_END(dce2_pstat_smb_seg);
            return DCE2_RET__ERROR;
        }
    }
    else if (DCE2_BufferMinAllocSize(*buf) != alloc_size)
    {
        DCE2_BufferSetMinAllocSize(*buf, alloc_size);
    }

    status = DCE2_BufferAddData(*buf, data_ptr, add_len,
            DCE2_BufferLength(*buf), DCE2_BUFFER_MIN_ADD_FLAG__USE);

    DCE2_DEBUG_CODE(DCE2_DEBUG__SMB,
            if (status != DCE2_RET__SUCCESS)
            printf("Failed to add data to SMB segmentation buffer.\n"););

    PREPROC_PROFILE_END(dce2_pstat_smb_seg);
    return status;
}

/********************************************************************
 * Function: DCE2_SmbGetSegBuffer()
 *
 * Returns the appropriate segmentation buffer.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to SMB session data.
 *
 * Returns:
 *  DCE2_SmbSeg *
 *      Pointer to client or server segmenation buffer.
 *
 ********************************************************************/
static inline DCE2_Buffer ** DCE2_SmbGetSegBuffer(DCE2_SmbSsnData *ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_seg;
    return &ssd->cli_seg;
}

/********************************************************************
 * Function: DCE2_SmbGetIgnorePtr()
 *
 * Returns a pointer to the bytes we are ignoring on client or
 * server side.  Bytes are ignored if they are associated with
 * data we are not interested in.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  uint32_t *
 *      Pointer to the client or server ignore bytes.
 *
 ********************************************************************/
static inline uint32_t * DCE2_SmbGetIgnorePtr(DCE2_SmbSsnData *ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_ignore_bytes;
    return &ssd->cli_ignore_bytes;
}

/********************************************************************
 * Function: DCE2_SmbGetDataState()
 *
 * Returns a pointer to the data state of client or server
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  DCE2_SmbDataState *
 *      Pointer to the client or server data state.
 *
 ********************************************************************/
static inline DCE2_SmbDataState * DCE2_SmbGetDataState(DCE2_SmbSsnData *ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_data_state;
    return &ssd->cli_data_state;
}

/********************************************************************
 * Function: DCE2_SmbIsSegBuffer()
 *
 * Purpose:
 *  Determines whether the pointer passed in lies within one of the
 *  segmentation buffers or not.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to SMB session data.
 *
 * Returns:
 *  bool  -  True is the pointer lies within one of the segmentation
 *           buffers.
 *           False if it doesn't.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsSegBuffer(DCE2_SmbSsnData *ssd, const uint8_t *ptr)
{
    DCE2_Buffer *seg_buf;

    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        seg_buf = ssd->srv_seg;
    else
        seg_buf = ssd->cli_seg;

    if (DCE2_BufferIsEmpty(seg_buf))
        return false;

    /* See if we're looking at a segmentation buffer */
    if ((ptr < DCE2_BufferData(seg_buf)) ||
            (ptr > (DCE2_BufferData(seg_buf) + DCE2_BufferLength(seg_buf))))
    {
        return false;
    }

    return true;
}

/********************************************************************
 * Function: DCE2_SmbSegAlert()
 *
 * Purpose:
 *  To create a reassembled packet using the data in one of the
 *  segmentation buffers in order to generate an alert with the
 *  correct, or more complete data.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *  DCE2_Event        - the event code to generate and event for.
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSegAlert(DCE2_SmbSsnData *ssd, DCE2_Event event)
{
    SFSnortPacket *rpkt;
    DCE2_Buffer *buf;
    uint32_t nb_len = 0;
    const uint8_t *data_ptr;
    uint32_t data_len;

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
        buf = ssd->cli_seg;
    else
        buf = ssd->srv_seg;

    /* This should be called from the desegmentation code. */
    if (DCE2_BufferIsEmpty(buf))
        return;

    data_ptr = DCE2_BufferData(buf);
    data_len = DCE2_BufferLength(buf);

    rpkt = DCE2_SmbGetRpkt(ssd, &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_SEG);
    if (rpkt == NULL)
        return;

    if (DCE2_BufferLength(buf) >= sizeof(NbssHdr))
        nb_len = NbssLen((NbssHdr *)DCE2_BufferData(buf));

    switch (event)
    {
        case DCE2_EVENT__SMB_BAD_NBSS_TYPE:
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_NBSS_TYPE);
            break;

        case DCE2_EVENT__SMB_BAD_TYPE:
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_TYPE);
            break;

        case DCE2_EVENT__SMB_BAD_ID:
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_ID);
            break;

        case DCE2_EVENT__SMB_NB_LT_SMBHDR:
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_SMBHDR, nb_len, sizeof(SmbNtHdr));
            break;

        default:
            break;
    }

    DCE2_SmbReturnRpkt();
}

/********************************************************************
 * Function: DCE2_SmbIsRawData()
 *
 * Purpose:
 *  To determine if the current state is such that a raw read or
 *  write is expected.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  bool -  True if expecting raw data.
 *          False if not.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsRawData(DCE2_SmbSsnData *ssd)
{
    return (ssd->pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbProcessRawData(DCE2_SmbSsnData *ssd, const uint8_t *nb_ptr, uint32_t nb_len)
{
    DCE2_SmbPipeTracker *ptracker = ssd->cur_rtracker->ptracker;

    if (ptracker == NULL)
    {
        DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
        ssd->cur_rtracker = NULL;
        return;
    }

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Raw data: Write Raw\n"));
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Request Fid: 0x%04X\n", ptracker->fid));
        dce2_stats.smb_com_stats[SMB_TYPE__REQUEST][SMB_COM_WRITE_RAW]++;

        if (nb_len > ssd->cur_rtracker->writeraw_remaining)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_TDCNT_LT_DSIZE,
                    ssd->cur_rtracker->writeraw_remaining, nb_len);

            // If this happens, Windows never responds regardless of
            // WriteThrough flag, so get rid of request tracker
            DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
            ssd->cur_rtracker = NULL;
        }

        if (ssd->cur_rtracker != NULL)
        {
            if (!ssd->cur_rtracker->writeraw_writethrough)
            {
                // If WriteThrough flag was not set on initial request, a
                // SMB_COM_WRITE_COMPLETE will not be sent so need to get
                // rid of request tracker.
                DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
                ssd->cur_rtracker = NULL;
            }
            else
            {
                ssd->cur_rtracker->writeraw_writethrough = false;
                ssd->cur_rtracker->writeraw_remaining = 0;
            }
        }
    }
    else
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Raw data: Read Raw\n"));
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Response Fid: 0x%04X\n", ptracker->fid));
        dce2_stats.smb_com_stats[SMB_TYPE__RESPONSE][SMB_COM_READ_RAW]++;

        DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
        ssd->cur_rtracker = NULL;
    }

    // Only one raw read/write allowed
    ssd->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;

    // Maximum possible fragment length is 16 bit
    if (nb_len > UINT16_MAX)
        nb_len = UINT16_MAX;

    DCE2_CoProcess(&ssd->sd, &ptracker->co_tracker, nb_ptr, (uint16_t)nb_len);
}

/********************************************************************
 * Function: DCE2_SmbCheckCommand()
 *
 * Purpose:
 *  Checks basic validity of an SMB command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  int               - the SMB command code, i.e. SMB_COM_*
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *
 * Returns:
 *  DCE2_SmbComInfo *
 *      Populated structure for command processing
 *
 ********************************************************************/
static DCE2_SmbComInfo * DCE2_SmbCheckCommand(DCE2_SmbSsnData *ssd,
        const SmbNtHdr *smb_hdr, const uint8_t smb_com,
        const uint8_t *nb_ptr, uint32_t nb_len)
{
    SmbAndXCom andx_com = smb_chain_map[smb_com];
    const SmbCommon *sc = (SmbCommon *)nb_ptr;
    int chk_com_size;
    uint16_t smb_bcc;
    static DCE2_SmbComInfo com_info;

    com_info.smb_type = DCE2_SmbType(ssd);
    com_info.cmd_error = DCE2_SMB_COM_ERROR__COMMAND_OK;
    com_info.word_count = 0;
    com_info.cmd_size = 0;
    com_info.byte_count = 0;

    // Check for server error response
    if (com_info.smb_type == SMB_TYPE__RESPONSE)
    {
        const SmbEmptyCom *ec = (SmbEmptyCom *)nb_ptr;

        // Verify there is enough data to do checks
        if (nb_len < sizeof(SmbEmptyCom))
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_COM, nb_len, sizeof(SmbEmptyCom));
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
            return &com_info;
        }

        // If word and byte counts are zero and there is an error
        // the server didn't accept client request
        if ((SmbEmptyComWct(ec) == 0)
                && (SmbEmptyComBcc(ec) == 0) && SmbError(smb_hdr))
        {

            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                        "Response error: 0x%08X\n", SmbNtStatus(smb_hdr)));

            // If broken pipe, clean up data associated with open named pipe
            if (SmbBrokenPipe(smb_hdr))
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                            "  Broken or disconnected pipe.\n"));

                DCE2_SmbRemovePipeTracker(ssd, ssd->cur_rtracker->ptracker);
            }

            com_info.cmd_error |= DCE2_SMB_COM_ERROR__STATUS_ERROR;
            return &com_info;
        }
    }

    // Set the header size to the minimum size the command can be
    // without the byte count to make sure there is enough data to
    // get the word count.
    if (andx_com == SMB_ANDX_COM__NONE)
        chk_com_size = sizeof(SmbCommon);
    else
        chk_com_size = sizeof(SmbAndXCommon);

    // Verify there is enough data to do checks
    if (nb_len < (uint32_t)chk_com_size)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_COM, nb_len, chk_com_size);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return &com_info;
    }

    com_info.word_count = SmbWct(sc);

    // Make sure the word count is a valid one for the command.  If not
    // testing shows an error will be returned.  And command structures
    // won't lie on data correctly and out of bounds data accesses are possible.
    if (!DCE2_SmbIsValidWordCount(smb_com, (uint8_t)com_info.smb_type, com_info.word_count))
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_WCT, com_info.word_count);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT;
        return &com_info;
    }

    // This gets the size of the SMB command from word count through byte count
    // using the advertised value in the word count field.
    com_info.cmd_size = (uint16_t)SMB_COM_SIZE(com_info.word_count);
    if (nb_len < com_info.cmd_size)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_COM, nb_len, com_info.cmd_size);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return &com_info;
    }

    smb_bcc = SmbBcc(nb_ptr, com_info.cmd_size);

    // SMB_COM_NT_CREATE_ANDX is a special case.  Who know what's going
    // on with the word count (see MS-CIFS and MS-SMB).  A 42 word count
    // command seems to actually have 50 words, so who knows where the
    // byte count is.  Just set to zero since it's not needed.
    if ((smb_com == SMB_COM_NT_CREATE_ANDX)
            && (com_info.smb_type == SMB_TYPE__RESPONSE))
        smb_bcc = 0;

    // If byte count is deemed invalid, alert but continue processing
    switch (smb_com)
    {
        // Interim responses
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION2:
        case SMB_COM_NT_TRANSACT:
            // If word count is 0, byte count must be 0
            if ((com_info.word_count == 0) && (com_info.smb_type == SMB_TYPE__RESPONSE))
            {
                if (smb_bcc != 0)
                {
                    DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_BCC, smb_bcc);
                    com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
                }
                break;
            }
            // Fall through
        default:
            if (!DCE2_SmbIsValidByteCount(smb_com, (uint8_t)com_info.smb_type, smb_bcc))
            {
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_BCC, smb_bcc);
                com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
            }
            break;
    }

    // Move just past byte count field which is the end of the command
    DCE2_MOVE(nb_ptr, nb_len, com_info.cmd_size);

    // Validate that there is enough data to be able to process the command
    if (nb_len < DCE2_SmbGetMinByteCount(smb_com, (uint8_t)com_info.smb_type))
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_BCC, nb_len,
                DCE2_SmbGetMinByteCount(smb_com, (uint8_t)com_info.smb_type));
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    // The byte count seems to be ignored by Windows and current Samba (3.5.4)
    // as long as it is less than the amount of data left.  If more, an error
    // is returned.
    // !!!WARNING!!! the byte count should probably never be used.
    if (smb_bcc > nb_len)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_BCC, nb_len, smb_bcc);

        // Large byte count doesn't seem to matter for early Samba
        switch (DCE2_SsnGetPolicy(&ssd->sd))
        {
            case DCE2_POLICY__SAMBA_3_0_20:
            case DCE2_POLICY__SAMBA_3_0_22:
            case DCE2_POLICY__SAMBA_3_0_37:
                break;
            default:
                com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
                break;
        }
    }
    else if ((smb_bcc == 0) && (SmbCom(smb_hdr) == SMB_COM_TRANSACTION)
            && (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
            && (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA))
    {
        // Current Samba errors on a zero byte count Transaction because it
        // uses it to get the Name string and if zero Name will be NULL and
        // it won't process it.
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    com_info.byte_count = smb_bcc;

    return &com_info;
}

/********************************************************************
 * Function: DCE2_SmbProcessCommand()
 *
 * Purpose:
 *  This is the main function for handling SMB commands and command
 *  chaining.
 *  It does an initial check of the command to determine validity
 *  and gets basic information about the command.  Then it calls the
 *  specific command function (setup in DCE2_SmbInitGlobals).
 *  If there is command chaining, it will do the chaining foo to
 *  get to the next command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_SmbProcessCommand(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const uint8_t *nb_ptr, uint32_t nb_len)
{
    DCE2_Ret status = DCE2_RET__ERROR;
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    uint8_t smb_com = SmbCom(smb_hdr);
    int smb_type = DCE2_SmbType(ssd);
    int num_chained = 0;
    bool sess_chain = false;
    bool tree_chain = false;
    bool open_chain = false;

    dce2_stats.smb_com_stats[smb_type][smb_com]++;

    while (nb_len > 0)
    {
        SmbAndXCom andx_com = smb_chain_map[smb_com];
        const SmbAndXCommon *andx_ptr = (SmbAndXCommon *)nb_ptr;
        uint8_t smb_com2;
        const uint8_t *off2_ptr;
        DCE2_SmbComInfo *com_info;

        // Break out if command not supported
        if (smb_com_funcs[smb_com] == NULL)
            break;

        if (smb_deprecated_coms[smb_com])
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DEPR_COMMAND_USED,
                    smb_com_strings[smb_com]);
        }

        if (smb_unusual_coms[smb_com])
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_UNUSUAL_COMMAND_USED,
                    smb_com_strings[smb_com]);
        }

        com_info = DCE2_SmbCheckCommand(ssd, smb_hdr, smb_com, nb_ptr, nb_len);

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Processing command: %s (0x%02X)\n",
                    smb_com_strings[smb_com], smb_com));

        // Note that even if the command shouldn't be processed, some of
        // the command functions need to know and do cleanup or some other
        // processing.
        status = smb_com_funcs[smb_com](ssd, smb_hdr,
                (const DCE2_SmbComInfo *)com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__SUCCESS)
            break;

        // This command is not chainable
        if (andx_com == SMB_ANDX_COM__NONE)
            break;

        /**********************************************************
         * AndX Chaining
         **********************************************************/
        smb_com2 = SmbAndXCom2(andx_ptr);
        if (smb_com2 == SMB_COM_NO_ANDX_COMMAND)
            break;

        dce2_stats.smb_chained_stats[smb_type][andx_com][smb_com2]++;
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Chained SMB command: %s\n", smb_com_strings[smb_com2]));

        num_chained++;
        if (DCE2_ScSmbMaxChain(ssd->sd.sconfig) &&
                (num_chained >= DCE2_ScSmbMaxChain(ssd->sd.sconfig)))
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_EXCESSIVE_CHAINING, DCE2_ScSmbMaxChain(ssd->sd.sconfig));
        }

        // Multiple SessionSetupAndX, TreeConnectAndX, OpenAndX and NtCreateAndX
        // are only allowed by Samba.
        if (smb_com == SMB_COM_SESSION_SETUP_ANDX)
            sess_chain = true;

        // Check for multiple chained SessionSetupAndX
        if ((smb_com2 == SMB_COM_SESSION_SETUP_ANDX) && sess_chain)
        {
            // There is only one place to return a uid.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_MULT_CHAIN_SS);
            // XXX Should we continue processing?
            break;
        }

        // Check for chained SessionSetupAndX => .? => LogoffAndX
        if ((smb_com2 == SMB_COM_LOGOFF_ANDX) && sess_chain)
        {
            // This essentially deletes the uid created by the login
            // and doesn't make any sense.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_CHAIN_SS_LOGOFF);
        }

        if (smb_com == SMB_COM_TREE_CONNECT_ANDX)
            tree_chain = true;

        // Check for multiple chained TreeConnects
        if (((smb_com2 == SMB_COM_TREE_CONNECT_ANDX)
                    || (smb_com2 == SMB_COM_TREE_CONNECT)) && tree_chain)
        {
            // There is only one place to return a tid.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_MULT_CHAIN_TC);
            // XXX Should we continue processing?
            break;
        }

        // Check for chained TreeConnectAndX => .? => TreeDisconnect
        if ((smb_com2 == SMB_COM_TREE_DISCONNECT) && tree_chain)
        {
            // This essentially deletes the tid created by the tree connect
            // and doesn't make any sense.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_CHAIN_TC_TDIS);
        }

        if ((smb_com == SMB_COM_OPEN_ANDX) || (smb_com == SMB_COM_NT_CREATE_ANDX))
            open_chain = true;

        // Check for chained OpenAndX/NtCreateAndX => .? => Close
        if ((smb_com2 == SMB_COM_CLOSE) && open_chain)
        {
            // This essentially deletes the fid created by the open command
            // and doesn't make any sense.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_CHAIN_OPEN_CLOSE);
        }

        // Check that policy allows for such chaining
        if (smb_chain_funcs[policy][andx_com][smb_com2] == NULL)
            break;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        // XXX Need to test out of order chaining
        off2_ptr = (uint8_t *)smb_hdr + SmbAndXOff2(andx_ptr);
        if (DCE2_SmbCheckAndXOffset(ssd, off2_ptr, nb_ptr, nb_len) != DCE2_RET__SUCCESS)
            break;

        DCE2_MOVE(nb_ptr, nb_len, (off2_ptr - nb_ptr));

        // XXX Need to test more.
        switch (smb_com)
        {
            case SMB_COM_SESSION_SETUP_ANDX:
            case SMB_COM_TREE_CONNECT_ANDX:
            case SMB_COM_OPEN_ANDX:
            case SMB_COM_NT_CREATE_ANDX:
                switch (smb_com2)
                {
                    case SMB_COM_WRITE:
                    case SMB_COM_WRITE_ANDX:
                    case SMB_COM_TRANSACTION:
                        if (DCE2_SsnFromClient(ssd->sd.wire_pkt) && open_chain)
                        {
                            DCE2_SmbQueueTmpPipeTracker(ssd->cur_rtracker,
                                    SmbUid(smb_hdr), SmbTid(smb_hdr));
                        }
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }

        smb_com = smb_com2;
    }

    if (smb_type == SMB_TYPE__RESPONSE)
    {
        switch (smb_com)
        {
            case SMB_COM_TRANSACTION:
            case SMB_COM_TRANSACTION2:
            case SMB_COM_NT_TRANSACT:
            case SMB_COM_TRANSACTION_SECONDARY:
            case SMB_COM_TRANSACTION2_SECONDARY:
            case SMB_COM_NT_TRANSACT_SECONDARY:
                // This case means there was an error with the initial response
                // so the tracker isn't yet officially in response mode
                if (ssd->cur_rtracker->ttracker.smb_type == SMB_TYPE__REQUEST)
                {
                    // Samba throws out entire transaction and Windows just this request
                    if (DCE2_SsnIsServerSambaPolicy(&ssd->sd) && (status != DCE2_RET__SUCCESS))
                        break;

                    if (!DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                        return;
                }
                else
                {
                    if ((status == DCE2_RET__SUCCESS)
                            && !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                        return;
                }
                break;
            case SMB_COM_WRITE_RAW:
                if ((status == DCE2_RET__SUCCESS)
                        && (ssd->cur_rtracker->writeraw_remaining != 0))
                    return;
                break;
            default:
                break;
        }
    }
    else if (status != DCE2_RET__IGNORE)
    {
        switch (smb_com)
        {
            case SMB_COM_TRANSACTION:
            case SMB_COM_TRANSACTION_SECONDARY:
                if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
                {
                    if (!ssd->cur_rtracker->ttracker.one_way
                            || !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                        return;

                    // Remove the request tracker if transaction is one-way and
                    // all data and parameters have been sent
                    break;
                }
            default:
                // Anything else, keep the request tracker
                return;
        }
    }

    DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
    ssd->cur_rtracker = NULL;
}

/********************************************************************
 * Function: DCE2_SmbCheckData()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count from the SMB command
 *  const uint16_t    - reported data count in SMB command
 *  const uint16_t    - reported data offset in SMB command
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData *ssd,
        const uint8_t *smb_hdr_ptr, const uint8_t *nb_ptr,
        const uint32_t nb_len, const uint16_t bcc,
        const uint16_t dcnt, uint16_t doff)
{
    const uint8_t *offset = smb_hdr_ptr + doff;
    const uint8_t *nb_end = nb_ptr + nb_len;

    // Byte counts don't usually matter, so no error but still alert
    if (bcc < dcnt)
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BCC_LT_DSIZE, bcc, (uint64_t)dcnt);

    if (offset > nb_end)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, offset, nb_ptr, nb_end);

        // Error if offset is beyond data left
        return DCE2_RET__ERROR;
    }

    // Only check if the data count is non-zero
    if ((dcnt != 0) && (offset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, offset, nb_ptr, nb_end);
    }

    // Not necessarily an error if the addition of the data count goes
    // beyond the data left
    if ((offset + dcnt) > nb_end)
    {
        int pad = offset - nb_ptr;
        if (pad > 0)
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len - pad, dcnt);
        else
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len, dcnt);
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbCheckTransDataParams()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *  Note the 32 bit values are because of the NtTransact command
 *  though it's currently not checked.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count
 *  const uint32_t    - reported data count
 *  const uint32_t    - reported data offset
 *  const uint32_t    - reported parameter count
 *  const uint32_t    - reported parameter offset
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckTransDataParams(DCE2_SmbSsnData *ssd,
        const uint8_t *smb_hdr_ptr, const uint8_t *nb_ptr, const uint32_t nb_len,
        const uint16_t bcc, const uint32_t dcnt, const uint32_t doff,
        const uint32_t pcnt, const uint32_t poff)
{
    const uint8_t *doffset = smb_hdr_ptr + doff;
    const uint8_t *poffset = smb_hdr_ptr + poff;
    const uint8_t *nb_end = nb_ptr + nb_len;

    if (bcc < ((uint64_t)dcnt + pcnt))
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BCC_LT_DSIZE, bcc, ((uint64_t)dcnt + pcnt));

    // Check data offset out of bounds
    if ((doffset > nb_end) || (doffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, doffset, nb_ptr, nb_end);
        return DCE2_RET__ERROR;
    }

    // Check data offset in bounds but backwards
    // Only check if the data count is non-zero
    if ((dcnt != 0) && (doffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, doffset, nb_ptr, nb_end);
    }

    // Check the data offset + data count
    if (((doffset + dcnt) > nb_end)            // beyond data left
            || ((doffset + dcnt) < doffset))   // wrap
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len, dcnt);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset out of bounds
    if ((poffset > nb_end) || (poffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, poffset, nb_ptr, nb_end);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset in bounds but backwards
    // Only check if the parameter count is non-zero
    if ((pcnt != 0) && (poffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, poffset, nb_ptr, nb_end);
    }

    // Check the parameter offset + parameter count
    if (((poffset + pcnt) > nb_end)            // beyond data left
            || ((poffset + pcnt) < poffset))   // wrap
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len, pcnt);
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbCheckFmtData()
 *
 * Purpose:
 *  Checks the data count in commands with formats, e.g.
 *  SMB_COM_WRITE, SMB_COM_WRITE_AND_CLOSE, SMB_COM_WRITE_AND_UNLOCK.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint32_t    - remaining NetBIOS PDU length
 *  const uint16_t    - advertised byte count
 *  const uint8_t     - data format specifier
 *  const uint16_t    - data count reported in command
 *  const uint16_t    - data count reported in format field
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData *ssd,
        const uint32_t nb_len, const uint16_t bcc, const uint8_t fmt,
        const uint16_t com_dcnt, const uint16_t fmt_dcnt)
{
    if (fmt != SMB_FMT__DATA_BLOCK)
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_FORMAT, fmt);

    if (com_dcnt != fmt_dcnt)
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DCNT_MISMATCH, com_dcnt, fmt_dcnt);

    if (com_dcnt != (bcc - 3))
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_INVALID_DSIZE, com_dcnt, bcc);

    if (nb_len < com_dcnt)
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len, com_dcnt);
}

/********************************************************************
 * Function: DCE2_SmbCheckTotalCount()
 *
 * Purpose:
 *  Validates the advertised total data/param count.  Makes sure the
 *  current count isn't greater than total count, that the
 *  displacement + count isn't greater than the total data count and
 *  that the total data count isn't zero.  Mainly relevant to Write Raw,
 *  Transaction and Transaction Secondary commands.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint32_t    - total data count
 *  const uint32_t    - data count/size
 *  const uint32_t    - data displacement
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__SUCCESS if all is ok
 *             DCE2_RET__ERROR if any of the checks fail.
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckTotalCount(DCE2_SmbSsnData *ssd,
        const uint32_t tcnt, const uint32_t cnt, const uint32_t disp)
{
    DCE2_Ret ret = DCE2_RET__SUCCESS;

    if (cnt > tcnt)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_TDCNT_LT_DSIZE, tcnt, cnt);
        ret = DCE2_RET__ERROR;
    }

    if (((uint64_t)disp + cnt) > tcnt)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DSENT_GT_TDCNT, ((uint64_t)disp + cnt), tcnt);
        ret = DCE2_RET__ERROR;
    }

    return ret;
}

/********************************************************************
 * Function: DCE2_SmbCheckAndXOffset()
 *
 * Purpose:
 *  Validates that the AndXOffset is within bounds of the remaining
 *  data we have to work with.
 *
 * Arguments:
 *  uint8_t * - pointer to where the offset would take us.
 *  uint8_t * - pointer to bound offset
 *  uint8_t * - length of data where offset should be within
 *
 * Returns:
 *  DCE2_RET__SUCCESS - Offset is okay.
 *  DCE2_RET__ERROR   - Offset is bad.
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckAndXOffset(DCE2_SmbSsnData *ssd,
        const uint8_t *off_ptr, const uint8_t *start_bound, const uint32_t length)
{
    /* Offset should not point within data we just looked at or be equal to
     * or beyond the length of the NBSS length left */
    if ((off_ptr < start_bound) ||
            (off_ptr > (start_bound + length)))
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_OFF, off_ptr,
                start_bound, start_bound + length);

        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbInvalidShareCheck()
 *
 * Purpose:
 *  Checks the share reported in a TreeConnect or TreeConnectAndX
 *  against the invalid share list configured in the dcerpc2
 *  configuration in snort.conf.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to the share to check
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *  Alerts if there is an invalid share match.
 *
 ********************************************************************/
static inline void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData *ssd,
        const SmbNtHdr *smb_hdr, const uint8_t *nb_ptr, uint32_t nb_len)
{
    DCE2_List *share_list = DCE2_ScSmbInvalidShares(ssd->sd.sconfig);
    DCE2_SmbShare *smb_share;

    if (share_list == NULL)
        return;

    for (smb_share = (DCE2_SmbShare *)DCE2_ListFirst(share_list);
            smb_share != NULL;
            smb_share = (DCE2_SmbShare *)DCE2_ListNext(share_list))
    {
        unsigned int i;
        const char *share_str;
        unsigned int share_str_len;

        if (SmbUnicode(smb_hdr))
        {
            share_str = smb_share->unicode_str;
            share_str_len = smb_share->unicode_str_len;
        }
        else
        {
            share_str = smb_share->ascii_str;
            share_str_len = smb_share->ascii_str_len;
        }

        /* Make sure we have enough data */
        if (nb_len < share_str_len)
            continue;

        /* Test for share match */
        for (i = 0; i < share_str_len; i++)
        {
            /* All share strings should have been converted to upper case and
             * should include null terminating bytes */
            if ((nb_ptr[i] != share_str[i]) && (nb_ptr[i] != tolower((int)share_str[i])))
                break;
        }

        if (i == share_str_len)
        {
            /* Should only match one share since no duplicate shares in list */
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_INVALID_SHARE, smb_share->ascii_str);
            break;
        }
    }
}

/********************************************************************
 * Functions:
 *   DCE2_SmbOpen()
 *   DCE2_SmbCreate()
 *   DCE2_SmbClose()
 *   DCE2_SmbRename()
 *   DCE2_SmbRead()
 *   DCE2_SmbWrite()
 *   DCE2_SmbCreateNew()
 *   DCE2_SmbWriteAndUnlock()
 *   DCE2_SmbReadRaw()
 *   DCE2_SmbWriteRaw()
 *   DCE2_SmbWriteComplete()
 *   DCE2_SmbTransaction()
 *   DCE2_SmbTransactionSecondary()
 *   DCE2_SmbWriteAndClose()
 *   DCE2_SmbOpenAndX()
 *   DCE2_SmbReadAndX()
 *   DCE2_SmbWriteAndX()
 *   DCE2_SmbTransaction2()
 *   DCE2_SmbTransaction2Secondary()
 *   DCE2_SmbTreeConnect()
 *   DCE2_SmbTreeDisconnect()
 *   DCE2_SmbNegotiate()
 *   DCE2_SmbSessionSetupAndX()
 *   DCE2_SmbLogoffAndX()
 *   DCE2_SmbTreeConnectAndX()
 *   DCE2_SmbNtTransact()
 *   DCE2_SmbNtTransactSecondary()
 *   DCE2_SmbNtCreateAndX()
 *
 * Purpose: Process SMB command
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - SMB session data structure
 *  const SmbNtHdr *        - SMB header structure (packet pointer)
 *  const DCE2_SmbComInfo * - Basic command information structure
 *  uint8_t *               - pointer to start of command (packet pointer)
 *  uint32_t                - remaining NetBIOS length
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__ERROR if something went wrong and/or processing
 *               should stop
 *             DCE2_RET__SUCCESS if processing should continue
 *
 ********************************************************************/

// SMB_COM_OPEN
static DCE2_Ret DCE2_SmbOpen(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbNewPipeTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, SmbOpenRespFid((SmbOpenResp *)nb_ptr));
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE
static DCE2_Ret DCE2_SmbCreate(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbNewPipeTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, SmbCreateRespFid((SmbCreateResp *)nb_ptr));
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CLOSE
static DCE2_Ret DCE2_SmbClose(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbCloseReqFid((SmbCloseReq *)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ptracker = DCE2_SmbGetPipeTracker(ssd, fid);
    }
    else
    {
        DCE2_SmbRemovePipeTracker(ssd, ssd->cur_rtracker->ptracker);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_RENAME
static DCE2_Ret DCE2_SmbRename(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    // NOTE: This command is only processed for CVE-2006-4696 where the buffer
    // formats are invalid and has no bearing on DCE/RPC processing.

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 4 bytes of data based on byte count check done earlier

        uint32_t i;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_FORMAT, *nb_ptr);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        if (SmbUnicode(smb_hdr))
        {
            for (i = 0; i < (nb_len - 1); i += 2)
            {
                if (*((uint16_t *)(nb_ptr + i)) == 0)
                {
                    i += 2;  // move past null terminating bytes
                    break;
                }
            }
        }
        else
        {
            for (i = 0; i < nb_len; i++)
            {
                if (nb_ptr[i] == 0)
                {
                    i++;  // move past null terminating byte
                    break;
                }
            }
        }

        // i <= nb_len
        DCE2_MOVE(nb_ptr, nb_len, i);

        if ((nb_len > 0) && !SmbFmtAscii(*nb_ptr))
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_FORMAT, *nb_ptr);
            return DCE2_RET__ERROR;
        }
    }

    // Don't care about tracking response
    return DCE2_RET__ERROR;
}

// SMB_COM_READ
static DCE2_Ret DCE2_SmbRead(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbReadReqFid((SmbReadReq *)nb_ptr);

        // Set this for response since response doesn't have the Fid
        ssd->cur_rtracker->ptracker = DCE2_SmbGetPipeTracker(ssd, fid);
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t com_dcnt = SmbReadRespCount((SmbReadResp *)nb_ptr);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t fmt_dcnt = SmbNtohs((uint16_t *)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt > nb_len)
            return DCE2_RET__ERROR;

        if (DCE2_SmbProcessResponseData(ssd, nb_ptr, com_dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE
static DCE2_Ret DCE2_SmbWrite(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteReqCount((SmbWriteReq *)nb_ptr);
        uint16_t fmt_dcnt = SmbNtohs((uint16_t *)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteReqFid((SmbWriteReq *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DCNT_ZERO);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        if (DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE_NEW
static DCE2_Ret DCE2_SmbCreateNew(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbNewPipeTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, SmbCreateNewRespFid((SmbCreateNewResp *)nb_ptr));
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_AND_UNLOCK
static DCE2_Ret DCE2_SmbWriteAndUnlock(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        if (DCE2_ComInfoIsBadLength(com_info) || DCE2_ComInfoIsInvalidWordCount(com_info))
            return DCE2_RET__ERROR;

        // This is a special case.  The write succeeds but the unlock fails
        // on a named pipe so an error reponse is returned but the data was
        // actually written to the named pipe.
        if (DCE2_ComInfoIsResponse(com_info) && DCE2_ComInfoIsStatusError(com_info))
        {
            if (SmbStatusNtCodes(smb_hdr)
                    && (SmbNtStatus(smb_hdr) != SMB_NT_STATUS__INVALID_DEVICE_REQUEST))
                return DCE2_RET__ERROR;
        }
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteAndUnlockReqCount((SmbWriteAndUnlockReq *)nb_ptr);
        uint16_t fmt_dcnt = SmbNtohs((uint16_t *)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteAndUnlockReqFid((SmbWriteAndUnlockReq *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DCNT_ZERO);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        if (DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_READ_RAW
static DCE2_Ret DCE2_SmbReadRaw(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbReadRawReqFid((SmbReadRawReq *)nb_ptr);

        ssd->cur_rtracker->ptracker = DCE2_SmbFindPipeTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
    }
    else
    {
        // The server response is the raw data.  Supposedly if an error occurs,
        // the server will send a 0 byte read.  Just the NetBIOS header with
        // zero byte length.  Client upon getting the zero read is supposed to issue
        // another read using ReadAndX or Read to get the error.
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_RAW
static DCE2_Ret DCE2_SmbWriteRaw(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteRawReqFid((SmbWriteRawReq *)nb_ptr);
        uint16_t tdcnt = SmbWriteRawReqTotalCount((SmbWriteRawReq *)nb_ptr);
        bool writethrough = SmbWriteRawReqWriteThrough((SmbWriteRawReq *)nb_ptr);
        uint16_t doff = SmbWriteRawReqDataOff((SmbWriteRawReq *)nb_ptr);
        uint16_t dcnt = SmbWriteRawReqDataCnt((SmbWriteRawReq *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckData(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_NB_LT_DSIZE, nb_len, dcnt);
            return DCE2_RET__ERROR;
        }

        // If all of the data wasn't written in this request, the server will
        // send an interim SMB_COM_WRITE_RAW response and the client will send
        // the rest of the data raw.  In this case if the WriteThrough flag is
        // not set, the server will not send a final SMB_COM_WRITE_COMPLETE
        // response.  If all of the data is in this request the server will
        // send an SMB_COM_WRITE_COMPLETE response regardless of whether or
        // not the WriteThrough flag is set.
        if (dcnt != tdcnt)
        {
            ssd->cur_rtracker->writeraw_writethrough = writethrough;
            ssd->cur_rtracker->writeraw_remaining = tdcnt - dcnt;
        }

        if (DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }
    else
    {
        // If all the data wasn't written initially this interim response will
        // be sent by the server and the raw data will ensue from the client.
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_COMPLETE
static DCE2_Ret DCE2_SmbWriteComplete(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    return DCE2_RET__SUCCESS;
}

// Validates Name for Samba Transaction requests
// TODO Write a function that parses unicode and ascii strings, NULL
// or non-NULL terminated cause this thing is clunky.
static DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t *nb_ptr,
        uint32_t nb_len, uint16_t bcc, bool unicode)
{
    const uint8_t pipe_unicode[] = {'\\','\0','P','\0','I','\0','P','\0','E','\0'};
    const uint8_t pipe_ascii[] = {'\\','P','I','P','E'};
    const uint8_t *pipe_str;
    uint8_t pipe_len, i;
    uint8_t increment = unicode ? 2 : 1;

    if ((nb_len == 0) || (bcc == 0))
        return DCE2_RET__ERROR;

    if (bcc < nb_len)
        nb_len = bcc;

    if (unicode)
    {
        DCE2_MOVE(nb_ptr, nb_len, 1);  // One byte pad for unicode
        pipe_len = sizeof(pipe_unicode);
        pipe_str = pipe_unicode;
    }
    else
    {
        pipe_len = sizeof(pipe_ascii);
        pipe_str = pipe_ascii;
    }

    if (nb_len < pipe_len)
        return DCE2_RET__ERROR;

    for (i = 0; i < pipe_len; i++)
    {
        if (toupper((int)nb_ptr[i]) != pipe_str[i])
            return DCE2_RET__ERROR;
    }

    DCE2_MOVE(nb_ptr, nb_len, pipe_len);

    if (nb_len < increment)
        return DCE2_RET__ERROR;

    // Samba accepts with or without ending backslash
    if (*nb_ptr != '\\')
    {
        // No backslash so must be NULL terminated
        if (unicode)
        {
            if ((nb_ptr[0] == '\0') && (nb_ptr[1] == '\0'))
                return DCE2_RET__SUCCESS;
        }
        else if (*nb_ptr == '\0')
        {
            return DCE2_RET__SUCCESS;
        }

        return DCE2_RET__ERROR;
    }
    else
    {
        // Got backslash, so make sure for unicode the second byte is 0
        if (unicode)
        {
            DCE2_MOVE(nb_ptr, nb_len, 1);
            if (*nb_ptr != '\0')
                return DCE2_RET__ERROR;
        }

        // Past backslash or NULL byte in case of unicode
        DCE2_MOVE(nb_ptr, nb_len, 1);

        if (nb_len < increment)
            return DCE2_RET__ERROR;

        // If the string is NULL terminated here return success
        if (unicode)
        {
            if ((nb_ptr[0] == '\0') && (nb_ptr[1] == '\0'))
                return DCE2_RET__SUCCESS;
        }
        else if (*nb_ptr == '\0')
        {
            return DCE2_RET__SUCCESS;
        }

        // Samba accepts the following strings but doesn't check that
        // they refer to the correct pipe.  Some Windows 95 thing.

        // TODO The following code block should be updated for efficiency.
        // Primary targets include the repeated checks on the same bytes,
        // calling toupper() on '\0', etc.

        if (unicode)
        {
            const uint8_t samr_unicode[] = {'S','\0','A','\0','M','\0','R','\0','\0','\0'};
            const uint8_t wkssvc_unicode[] = {'W','\0','K','\0','S','\0','S','\0','V','\0','C','\0','\0','\0'};
            const uint8_t srvsvc_unicode[] = {'S','\0','R','\0','V','\0','S','\0','V','\0','C','\0','\0','\0'};
            const uint8_t winreg_unicode[] = {'W','\0','I','\0','N','\0','R','\0','E','\0','G','\0','\0','\0'};
            const uint8_t lsarpc_unicode[] = {'L','\0','S','\0','A','\0','R','\0','P','\0','C','\0','\0','\0'};

            // Check for SAMR
            if (nb_len >= sizeof(samr_unicode))
            {
                for (i = 0; i < sizeof(samr_unicode); i++)
                {
                    if (toupper((int)nb_ptr[i]) != samr_unicode[i])
                        break;
                }

                if (i == sizeof(samr_unicode))
                    return DCE2_RET__SUCCESS;
            }

            if (nb_len >= sizeof(wkssvc_unicode))
            {
                // Check for WKSSVC
                for (i = 0; i < sizeof(wkssvc_unicode); i++)
                {
                    if (toupper((int)nb_ptr[i]) != wkssvc_unicode[i])
                        break;
                }

                if (i == sizeof(wkssvc_unicode))
                    return DCE2_RET__SUCCESS;

                // Check for SRVSVC
                for (i = 0; i < sizeof(srvsvc_unicode); i++)
                {
                    if (toupper((int)nb_ptr[i]) != srvsvc_unicode[i])
                        break;
                }

                if (i == sizeof(srvsvc_unicode))
                    return DCE2_RET__SUCCESS;

                // Check for WINREG
                for (i = 0; i < sizeof(winreg_unicode); i++)
                {
                    if (toupper((int)nb_ptr[i]) != winreg_unicode[i])
                        break;
                }

                if (i == sizeof(winreg_unicode))
                    return DCE2_RET__SUCCESS;

                // Check for LSARPC
                for (i = 0; i < sizeof(lsarpc_unicode); i++)
                {
                    if (toupper((int)nb_ptr[i]) != lsarpc_unicode[i])
                        break;
                }

                if (i == sizeof(lsarpc_unicode))
                    return DCE2_RET__SUCCESS;
            }
        }
        else
        {
            const uint8_t wkssvc_ascii[] = {'W','K','S','S','V','C','\0'};
            const uint8_t srvsvc_ascii[] = {'S','R','V','S','V','C','\0'};
            const uint8_t winreg_ascii[] = {'W','I','N','R','E','G','\0'};
            const uint8_t samr_ascii[] = {'S','A','M','R','\0'};
            const uint8_t lsarpc_ascii[] = {'L','S','A','R','P','C','\0'};

            // Check for SAMR
            if (nb_len >= sizeof(samr_ascii))
            {
                for (i = 0; i < sizeof(samr_ascii); i++)
                {
                    if (toupper((int)nb_ptr[i]) != samr_ascii[i])
                        break;
                }

                if (i == sizeof(samr_ascii))
                    return DCE2_RET__SUCCESS;
            }

            if (nb_len >= sizeof(wkssvc_ascii))
            {
                // Check for WKSSVC
                for (i = 0; i < sizeof(wkssvc_ascii); i++)
                {
                    if (toupper((int)nb_ptr[i]) != wkssvc_ascii[i])
                        break;
                }

                if (i == sizeof(wkssvc_ascii))
                    return DCE2_RET__SUCCESS;

                // Check for SRVSVC
                for (i = 0; i < sizeof(srvsvc_ascii); i++)
                {
                    if (toupper((int)nb_ptr[i]) != srvsvc_ascii[i])
                        break;
                }

                if (i == sizeof(srvsvc_ascii))
                    return DCE2_RET__SUCCESS;

                // Check for WINREG
                for (i = 0; i < sizeof(winreg_ascii); i++)
                {
                    if (toupper((int)nb_ptr[i]) != winreg_ascii[i])
                        break;
                }

                if (i == sizeof(winreg_ascii))
                    return DCE2_RET__SUCCESS;

                // Check for LSARPC
                for (i = 0; i < sizeof(lsarpc_ascii); i++)
                {
                    if (toupper((int)nb_ptr[i]) != lsarpc_ascii[i])
                        break;
                }

                if (i == sizeof(lsarpc_ascii))
                    return DCE2_RET__SUCCESS;
            }
        }
    }

    return DCE2_RET__ERROR;
}

// Convenience function to determine whether or not the transaction is complete
// for one side, i.e. all data and parameters sent.
static inline bool DCE2_SmbIsTransactionComplete(DCE2_SmbTransactionTracker *ttracker)
{
    if ((ttracker->tdcnt == ttracker->dsent)
            && (ttracker->tpcnt == ttracker->psent))
        return true;
    return false;
}

// SMB_COM_TRANSACTION
static DCE2_Ret DCE2_SmbTransaction(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    DCE2_SmbTransactionTracker *ttracker = &ssd->cur_rtracker->ttracker;

    // Got a matching request for an in progress transaction - don't process it,
    // but don't want to remove tracker.
    if (DCE2_ComInfoIsRequest(com_info)
            && !DCE2_SmbIsTransactionComplete(ttracker))
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Got new transaction request "
                    "that matches an in progress transaction - not inspecting.\n"));
        return DCE2_RET__ERROR;
    }

    // Avoid decoding/tracking \PIPE\LANMAN requests
    if (DCE2_ComInfoIsRequest(com_info)
            && (DCE2_ComInfoWordCount(com_info) != 16))
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "\\PIPE\\LANMAN request - not inspecting\n"));
        return DCE2_RET__IGNORE;
    }

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial Transaction request and will have to complete the request
    // with TransactionSecondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
            && (com_size == sizeof(SmbTransactionInterimResp)))
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "  Server Transaction interim response.\n"));

        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t sub_com = SmbTransactionReqSubCom((SmbTransactionReq *)nb_ptr);
        uint16_t fid = SmbTransactionReqFid((SmbTransactionReq *)nb_ptr);
        uint8_t setup_count = SmbTransactionReqSetupCnt((SmbTransactionReq *)nb_ptr);
        uint16_t tdcnt = SmbTransactionReqTotalDataCnt((SmbTransactionReq *)nb_ptr);
        uint16_t doff = SmbTransactionReqDataOff((SmbTransactionReq *)nb_ptr);
        uint16_t dcnt = SmbTransactionReqDataCnt((SmbTransactionReq *)nb_ptr);
        uint16_t tpcnt = SmbTransactionReqTotalParamCnt((SmbTransactionReq *)nb_ptr);
        uint16_t pcnt = SmbTransactionReqParamCnt((SmbTransactionReq *)nb_ptr);
        uint16_t poff = SmbTransactionReqParamOff((SmbTransactionReq *)nb_ptr);
        bool disconnect_tid = SmbTransactionReqDisconnectTid((SmbTransactionReq *)nb_ptr);
        bool one_way = SmbTransactionReqOneWay((SmbTransactionReq *)nb_ptr);

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Transaction subcommand: %s (0x%04X)\n",
                    (sub_com < TRANS_SUBCOM_MAX)
                    ? smb_transaction_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < TRANS_SUBCOM_MAX)
            dce2_stats.smb_trans_subcom_stats[SMB_TYPE__REQUEST][sub_com]++;
        else
            dce2_stats.smb_trans_subcom_stats[SMB_TYPE__REQUEST][TRANS_SUBCOM_MAX]++;

        switch (sub_com)
        {
            case TRANS_TRANSACT_NMPIPE:
            case TRANS_SET_NMPIPE_STATE:
                break;
            case TRANS_READ_NMPIPE:
            case TRANS_WRITE_NMPIPE:
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_UNUSUAL_COMMAND_USED,
                        smb_transaction_sub_command_strings[sub_com]);
                break;

            // Not implemented according to MS-CIFS
            case TRANS_RAW_READ_NMPIPE:

            // Can only write 2 NULL bytes and subsequent writes return pipe disconnected
            case TRANS_RAW_WRITE_NMPIPE:

            // Can at most do a DCE/RPC bind
            case TRANS_CALL_NMPIPE:
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DEPR_COMMAND_USED,
                        smb_transaction_sub_command_strings[sub_com]);

            // Aren't looking at these or the three above
            case TRANS_QUERY_NMPIPE_STATE:
            case TRANS_QUERY_NMPIPE_INFO:
            case TRANS_PEEK_NMPIPE:
            case TRANS_WAIT_NMPIPE:
            default:
                // Don't want to track the response
                return DCE2_RET__IGNORE;
        }

        // Servers return error if incorrect setup count
        if (setup_count != 2)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_INVALID_SETUP_COUNT,
                    smb_com_strings[SMB_COM_TRANSACTION],
                    smb_transaction_sub_command_strings[sub_com],
                    setup_count);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // Samba validates the Name which should be \PIPE\ and errors
        // if not.  Windows doesn't care.
        // And Samba uses the ByteCount to validate
        if (DCE2_SsnIsSambaPolicy(&ssd->sd)
                && (DCE2_SmbTransactionGetName(nb_ptr, nb_len,
                        byte_count, SmbUnicode(smb_hdr)) != DCE2_RET__SUCCESS))
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Failed to validate "
                        "pipe name for Samba.\n"));
            return DCE2_RET__ERROR;
        }

        if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTotalCount(ssd, tpcnt, pcnt, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTransDataParams(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        ttracker->smb_type = SMB_TYPE__REQUEST;
        ttracker->subcom = (uint8_t)sub_com;
        ttracker->disconnect_tid = disconnect_tid;
        ttracker->one_way = one_way;
        ttracker->tdcnt = tdcnt;
        ttracker->dsent = dcnt;
        ttracker->tpcnt = tpcnt;
        ttracker->psent = pcnt;

        // Testing shows that Transacts aren't written to the pipe until
        // all of the data and parameters are received, so overlapping
        // writes to the same FID can occur as long as the pid/mid are
        // distinct (and that depends on policy).  So we need to buffer
        // data up for each incomplete Transact so data doesn't get mangled
        // together with multiple ones intermixing at the same time.

        ssd->cur_rtracker->ptracker = DCE2_SmbGetPipeTracker(ssd, fid);
        if (ssd->cur_rtracker->ptracker == NULL)
            return DCE2_RET__IGNORE;

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data count: %u, "
                    "Total data count: %u, Param count: %u, "
                    "Total param count: %u\n", dcnt, tdcnt, pcnt, tpcnt));

        if ((sub_com == TRANS_TRANSACT_NMPIPE) || (sub_com == TRANS_WRITE_NMPIPE))
        {
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd)
                    && ssd->cur_rtracker->ptracker->byte_mode
                    && (sub_com == TRANS_TRANSACT_NMPIPE))
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Pipe is in byte "
                            "mode - TRANS_TRANSACT_NMPIPE won't work\n"));
                return DCE2_RET__ERROR;
            }

            if (tdcnt == 0)
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_TDCNT_ZERO);

            // This may move backwards
            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

            // If all of the data and parameters weren't sent buffer what was sent
            if (((dcnt != tdcnt) && (dcnt != 0)) || (pcnt != tpcnt))
            {
                if (DCE2_SmbBufferTransactionData(ttracker,
                            nb_ptr, dcnt, 0) != DCE2_RET__SUCCESS)
                {
                    return DCE2_RET__ERROR;
                }
            }
            else if (pcnt == tpcnt)  // All data and parameters sent
            {
                if (DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
                    return DCE2_RET__ERROR;
            }
        }
        else if (sub_com == TRANS_SET_NMPIPE_STATE)
        {
            if (tpcnt == 0)
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_TDCNT_ZERO);

            // This may move backwards
            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + poff) - nb_ptr);

            // If all of the data and parameters weren't sent buffer what was sent
            if (((pcnt != tpcnt) && (pcnt != 0)) || (dcnt != tdcnt))
            {
                if (DCE2_SmbBufferTransactionParameters(ttracker,
                            nb_ptr, pcnt, 0) != DCE2_RET__SUCCESS)
                {
                    return DCE2_RET__ERROR;
                }
            }
            else if (dcnt == tdcnt)  // All data and parameters sent
            {
                // Only two parameters but more seems okay
                if ((pcnt >= 2) && (nb_len >= 2))
                {
                    if ((SmbNtohs((uint16_t *)nb_ptr) & PIPE_STATE_MESSAGE_MODE))
                        ttracker->pipe_byte_mode = false;
                    else
                        ttracker->pipe_byte_mode = true;

                    // Won't get a response
                    if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way)
                    {
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting pipe to %s mode\n",
                                    ttracker->pipe_byte_mode ? "byte" : "message"));

                        ssd->cur_rtracker->ptracker->byte_mode = ttracker->pipe_byte_mode;
                    }
                }
            }
        }

        if ((dcnt == tdcnt) && (pcnt == tpcnt)
                && DCE2_SsnIsWindowsPolicy(&ssd->sd)
                && ttracker->one_way
                && ttracker->disconnect_tid)
        {
            DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);
        }
    }
    else
    {
        uint16_t tdcnt = SmbTransactionRespTotalDataCnt((SmbTransactionResp *)nb_ptr);
        uint16_t doff = SmbTransactionRespDataOff((SmbTransactionResp *)nb_ptr);
        uint16_t dcnt = SmbTransactionRespDataCnt((SmbTransactionResp *)nb_ptr);
        uint16_t ddisp = SmbTransactionRespDataDisp((SmbTransactionResp *)nb_ptr);
        uint16_t tpcnt = SmbTransactionRespTotalParamCnt((SmbTransactionResp *)nb_ptr);
        uint16_t pcnt = SmbTransactionRespParamCnt((SmbTransactionResp *)nb_ptr);
        uint16_t poff = SmbTransactionRespParamOff((SmbTransactionResp *)nb_ptr);
        uint16_t pdisp = SmbTransactionRespParamDisp((SmbTransactionResp *)nb_ptr);
        DCE2_SmbTransactionTracker *ttracker = &ssd->cur_rtracker->ttracker;
        uint16_t sub_com = ttracker->subcom;

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Transaction subcommand: %s (0x%04X)\n",
                    (sub_com < TRANS_SUBCOM_MAX)
                    ? smb_transaction_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < TRANS_SUBCOM_MAX)
            dce2_stats.smb_trans_subcom_stats[SMB_TYPE__RESPONSE][sub_com]++;
        else
            dce2_stats.smb_trans_subcom_stats[SMB_TYPE__RESPONSE][TRANS_SUBCOM_MAX]++;

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // From client request
        if (ttracker->smb_type == SMB_TYPE__REQUEST)
        {
            ttracker->smb_type = SMB_TYPE__RESPONSE;
            ttracker->tdcnt = tdcnt;
            ttracker->tpcnt = tpcnt;
            ttracker->dsent = 0;
            ttracker->psent = 0;
            DCE2_BufferDestroy(ttracker->dbuf);
            ttracker->dbuf = NULL;
            DCE2_BufferDestroy(ttracker->pbuf);
            ttracker->pbuf = NULL;
        }
        else
        {
            // For responses, both Windows and Samba will reset the total
            // count if less than previous total count.
            if (tdcnt < ttracker->tdcnt)
                ttracker->tdcnt = tdcnt;
            if (tpcnt < ttracker->tpcnt)
                ttracker->tpcnt = pcnt;
        }

        if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTotalCount(ssd, tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTransDataParams(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (((ttracker->dsent + dcnt) > ttracker->tdcnt)
                || ((ttracker->psent + pcnt) > ttracker->tpcnt))
        {
            if ((ttracker->dsent + dcnt) > ttracker->tdcnt)
            {
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DSENT_GT_TDCNT,
                        ((uint64_t)ttracker->dsent + dcnt), ttracker->tdcnt);
            }

            if ((ttracker->psent + pcnt) > ttracker->tpcnt)
            {
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DSENT_GT_TDCNT,
                        ((uint64_t)ttracker->psent + pcnt), ttracker->tpcnt);
            }

            return DCE2_RET__ERROR;
        }

        if (ssd->cur_rtracker->ptracker == NULL)
            return DCE2_RET__ERROR;

        ttracker->dsent += dcnt;
        ttracker->psent += pcnt;

        if ((ttracker->subcom == TRANS_TRANSACT_NMPIPE)
                || (ttracker->subcom == TRANS_READ_NMPIPE))
        {

            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data displacement: %u, "
                        "Data size: %u, Total data count: %u\n",
                        ddisp, dcnt, tdcnt));

            // This may move backwards
            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

            if ((ttracker->dsent < ttracker->tdcnt)
                    || (ttracker->psent < ttracker->tpcnt)
                    || !DCE2_BufferIsEmpty(ttracker->dbuf))
            {
                DCE2_Ret status;

                if (dcnt != 0)
                {
                    status = DCE2_SmbBufferTransactionData(ttracker, nb_ptr, dcnt, ddisp);
                    if (status != DCE2_RET__SUCCESS)
                        return DCE2_RET__ERROR;
                }

                if ((ttracker->dsent == ttracker->tdcnt)
                        && (ttracker->psent == ttracker->tpcnt))
                {
                    const uint8_t *data_ptr = DCE2_BufferData(ttracker->dbuf);
                    uint32_t data_len = DCE2_BufferLength(ttracker->dbuf);
                    SFSnortPacket *rpkt = DCE2_SmbGetRpkt(ssd, &data_ptr,
                            &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                    if (rpkt == NULL)
                        return DCE2_RET__ERROR;

                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Reassembled Transaction response\n"));
                    DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                    if (DCE2_SmbProcessResponseData(ssd, data_ptr, data_len) != DCE2_RET__SUCCESS)
                        status = DCE2_RET__ERROR;

                    DCE2_SmbReturnRpkt();

                    if (status != DCE2_RET__SUCCESS)
                        return DCE2_RET__ERROR;
                }
            }
            else
            {
                if (DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
                    return DCE2_RET__ERROR;
            }
        }
        else if (sub_com == TRANS_SET_NMPIPE_STATE)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Setting pipe "
                        "to %s mode\n", ttracker->pipe_byte_mode ? "byte" : "message"));

            if ((ttracker->dsent == ttracker->tdcnt)
                    && (ttracker->psent == ttracker->tpcnt))
            {
                ssd->cur_rtracker->ptracker->byte_mode = ttracker->pipe_byte_mode;
            }
        }

        if ((ttracker->dsent == ttracker->tdcnt)
                && (ttracker->psent == ttracker->tpcnt)
                && ttracker->disconnect_tid)
        {
            DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION_SECONDARY
static DCE2_Ret DCE2_SmbTransactionSecondary(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t tdcnt, doff, dcnt, ddisp;
    uint16_t tpcnt, poff, pcnt, pdisp;
    DCE2_SmbTransactionTracker *ttracker = &ssd->cur_rtracker->ttracker;

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_SsnIsSambaPolicy(&ssd->sd))
    {
        // If the total count decreases, Samba will reset this to the new
        // total count.
        tdcnt = SmbTransactionSecondaryReqTotalDataCnt((SmbTransactionSecondaryReq *)nb_ptr);
        tpcnt = SmbTransactionSecondaryReqTotalParamCnt((SmbTransactionSecondaryReq *)nb_ptr);
        if (tdcnt < ttracker->tdcnt)
            ttracker->tdcnt = tdcnt;
        if (tpcnt < ttracker->tpcnt)
            ttracker->tpcnt = tpcnt;
    }
    else
    {
        // Windows always uses the total data count from the first transaction.
        tdcnt = (uint16_t)ttracker->tdcnt;
        tpcnt = (uint16_t)ttracker->tpcnt;
    }

    doff = SmbTransactionSecondaryReqDataOff((SmbTransactionSecondaryReq *)nb_ptr);
    dcnt = SmbTransactionSecondaryReqDataCnt((SmbTransactionSecondaryReq *)nb_ptr);
    ddisp = SmbTransactionSecondaryReqDataDisp((SmbTransactionSecondaryReq *)nb_ptr);
    poff = SmbTransactionSecondaryReqParamOff((SmbTransactionSecondaryReq *)nb_ptr);
    pcnt = SmbTransactionSecondaryReqParamCnt((SmbTransactionSecondaryReq *)nb_ptr);
    pdisp = SmbTransactionSecondaryReqParamDisp((SmbTransactionSecondaryReq *)nb_ptr);

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTotalCount(ssd, tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTransDataParams(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                byte_count, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (((ttracker->dsent + dcnt) > ttracker->tdcnt)
            || ((ttracker->psent + pcnt) > ttracker->tpcnt))
    {
        if ((ttracker->dsent + dcnt) > ttracker->tdcnt)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DSENT_GT_TDCNT,
                    ((uint64_t)ttracker->dsent + dcnt), ttracker->tdcnt);
        }

        if ((ttracker->psent + pcnt) > ttracker->tpcnt)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DSENT_GT_TDCNT,
                    ((uint64_t)ttracker->psent + pcnt), ttracker->tpcnt);
        }

        // Samba throws out entire transaction and Windows seems to hang in
        // limbo forever and never responds, so stop looking
        return DCE2_RET__IGNORE;
    }

    ttracker->dsent += dcnt;
    ttracker->psent += pcnt;

    // This may move backwards
    DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Data disp: %u, Data count: %u, "
                "Total data count: %u, Param count: %u, Param disp: %u, "
                "Total param count: %u\n", ddisp, dcnt, tdcnt, pdisp, pcnt, tpcnt));

    switch (ttracker->subcom)
    {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_WRITE_NMPIPE:
            if (dcnt != 0)
            {
                if (DCE2_SmbBufferTransactionData(ttracker, nb_ptr, dcnt, ddisp) != DCE2_RET__SUCCESS)
                    return DCE2_RET__ERROR;
            }

            if ((ttracker->dsent == ttracker->tdcnt)
                    && (ttracker->psent == ttracker->tpcnt))
            {
                DCE2_Ret status = DCE2_RET__SUCCESS;
                const uint8_t *data_ptr = DCE2_BufferData(ttracker->dbuf);
                uint32_t data_len = DCE2_BufferLength(ttracker->dbuf);
                SFSnortPacket *rpkt = DCE2_SmbGetRpkt(ssd, &data_ptr, &data_len,
                        DCE2_RPKT_TYPE__SMB_TRANS);

                if (rpkt == NULL)
                    return DCE2_RET__ERROR;

                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Reassembled Transaction request\n"));
                DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                if (DCE2_SmbProcessRequestData(ssd, 0, data_ptr, data_len) != DCE2_RET__SUCCESS)
                    status = DCE2_RET__ERROR;

                DCE2_SmbReturnRpkt();

                if (status != DCE2_RET__SUCCESS)
                    return DCE2_RET__ERROR;
            }
            break;
        case TRANS_SET_NMPIPE_STATE:
            if (pcnt != 0)
            {
                if (DCE2_SmbBufferTransactionParameters(ttracker, nb_ptr, pcnt, pdisp) != DCE2_RET__SUCCESS)
                    return DCE2_RET__ERROR;
            }

            if ((ttracker->dsent == ttracker->tdcnt)
                    && (ttracker->psent == ttracker->tpcnt))
            {
                if (DCE2_BufferLength(ttracker->pbuf) >= 2)
                {
                    if ((SmbNtohs((uint16_t *)DCE2_BufferData(ttracker->pbuf))
                                & PIPE_STATE_MESSAGE_MODE))
                        ttracker->pipe_byte_mode = false;
                    else
                        ttracker->pipe_byte_mode = true;

                    if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way)
                    {
                        // Server won't send response so set pipe state here
                        if (ssd->cur_rtracker->ptracker != NULL)
                            ssd->cur_rtracker->ptracker->byte_mode = ttracker->pipe_byte_mode;
                    }
                }
            }
            break;
        default:
            break;
    }

    if ((ttracker->dsent == ttracker->tdcnt)
            && (ttracker->psent == ttracker->tpcnt)
            && DCE2_SsnIsWindowsPolicy(&ssd->sd)
            && ttracker->one_way
            && ttracker->disconnect_tid)
    {
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_AND_CLOSE
static DCE2_Ret DCE2_SmbWriteAndClose(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least one byte based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t dcnt = SmbWriteAndCloseReqCount((SmbWriteAndCloseReq *)nb_ptr);
        uint16_t fid = SmbWriteAndCloseReqFid((SmbWriteAndCloseReq *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 1));

        if (DCE2_SmbCheckData(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt,
                    (uint16_t)(sizeof(SmbNtHdr) + com_size + 1)) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (dcnt == 0)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DCNT_ZERO);
            return DCE2_RET__ERROR;
        }

        // WriteAndClose has a 1 byte pad after the byte count
        if ((uint32_t)(dcnt + 1) != (uint32_t)byte_count)
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_INVALID_DSIZE, (dcnt + 1), byte_count);

        if (dcnt > nb_len)
            dcnt = (uint16_t)nb_len;

        DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt);
    }
    else
    {
        DCE2_SmbRemovePipeTracker(ssd, ssd->cur_rtracker->ptracker);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_OPEN_ANDX
static DCE2_Ret DCE2_SmbOpenAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        const uint16_t uid = ssd->cur_rtracker->uid;
        const uint16_t tid = ssd->cur_rtracker->tid;
        const uint16_t fid = SmbOpenAndXRespFid((SmbOpenAndXResp *)nb_ptr);

        // Set request tracker's current pipe tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon *)nb_ptr))
        {
            // This is in case in the request a write was chained to an open
            // in which case the write will be to the newly opened named pipe
            case SMB_COM_WRITE:
            case SMB_COM_WRITE_ANDX:
            case SMB_COM_TRANSACTION:
                ssd->cur_rtracker->ptracker =
                    DCE2_SmbDequeueTmpPipeTracker(ssd, ssd->cur_rtracker, fid);
                if (ssd->cur_rtracker->ptracker != NULL)
                    break;

                // Fall through

            default:
                ssd->cur_rtracker->ptracker = DCE2_SmbNewPipeTracker(ssd, uid, tid, fid);
                break;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_READ_ANDX
static DCE2_Ret DCE2_SmbReadAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbReadAndXReqFid((SmbReadAndXReq *)nb_ptr);
        DCE2_SmbPipeTracker *ptracker =
            DCE2_SmbFindPipeTracker(ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);

        // No sense in tracking response
        if (ptracker == NULL)
            return DCE2_RET__ERROR;

        // Set this for response
        ssd->cur_rtracker->ptracker = ptracker;
    }
    else
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t doff = SmbReadAndXRespDataOff((SmbReadAndXResp *)nb_ptr);
        uint16_t dcnt = SmbReadAndXRespDataCnt((SmbReadAndXResp *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
            dcnt = (uint16_t)nb_len;

        if (DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX
static DCE2_Ret DCE2_SmbWriteAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        DCE2_SmbPipeTracker *ptracker = ssd->cur_rtracker->ptracker;

        if ((ptracker != NULL) && (ptracker->writex_raw != NULL))
        {
            ptracker->writex_raw->remaining = 0;
            DCE2_BufferEmpty(ptracker->writex_raw->buf);
        }

        return DCE2_RET__ERROR;
    }

    if (DCE2_ComInfoIsRequest(com_info)
            && (SmbWriteAndXReqStartRaw((SmbWriteAndXReq *)nb_ptr)
                || SmbWriteAndXReqRaw((SmbWriteAndXReq *)nb_ptr)))
    {
        return DCE2_SmbWriteAndXRawRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq *)nb_ptr);
        uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq *)nb_ptr);
        uint16_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq *)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
        {
            // Current Samba erros if data count is greater than data left
            if (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA)
                return DCE2_RET__ERROR;

            // Windows and early Samba just use what's left
            dcnt = (uint16_t)nb_len;
        }

        if (DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX - raw mode
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq *)nb_ptr);
    uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq *)nb_ptr);
    uint16_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq *)nb_ptr);
    bool start_write_raw = SmbWriteAndXReqStartRaw((SmbWriteAndXReq *)nb_ptr);
    bool continue_write_raw = SmbWriteAndXReqRaw((SmbWriteAndXReq *)nb_ptr);
    uint16_t remaining = SmbWriteAndXReqRemaining((SmbWriteAndXReq *)nb_ptr);
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbPipeTracker *ptracker = DCE2_SmbGetPipeTracker(ssd, fid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Processing WriteAndX with raw mode flags\n"));

    // Set this now for possible reassembled packet
    ssd->cur_rtracker->ptracker = ptracker;

    if (ptracker == NULL)
        return DCE2_RET__ERROR;

    // Got request to write in raw mode without having gotten the initial
    // raw mode request or got initial raw mode request and then another
    // without having finished the first.
    if ((start_write_raw && (ptracker->writex_raw != NULL)
                && (ptracker->writex_raw->remaining != 0))
            || (continue_write_raw && ((ptracker->writex_raw == NULL)
                    || (ptracker->writex_raw->remaining == 0))))
    {
        switch (policy)
        {
            case DCE2_POLICY__WIN2000:
            case DCE2_POLICY__WINXP:
            case DCE2_POLICY__WINVISTA:
            case DCE2_POLICY__WIN2003:
            case DCE2_POLICY__WIN2008:
            case DCE2_POLICY__WIN7:
                if (ptracker->writex_raw != NULL)
                {
                    ptracker->writex_raw->remaining = 0;
                    DCE2_BufferEmpty(ptracker->writex_raw->buf);
                }
                return DCE2_RET__ERROR;
            case DCE2_POLICY__SAMBA:
            case DCE2_POLICY__SAMBA_3_0_37:
            case DCE2_POLICY__SAMBA_3_0_22:
            case DCE2_POLICY__SAMBA_3_0_20:
                // Samba doesn't do anything special here except if the two
                // flags are set it walks past the two "length" bytes.
                // See below.
                break;
            default:
                DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid policy: %d",
                        __FILE__, __LINE__, policy);
                break;
        }
    }

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbCheckData(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    // This may move backwards
    DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + doff) - nb_ptr);

    // If a "raw" write is requested there will be two bytes after the
    // header/pad and before the data which is supposed to represent a
    // length but everyone ignores it.  However we need to move past it.
    // This is the one situation where the remaining field matters and
    // should be equal to the total amount of data to be written.
    if (start_write_raw)
    {
        if (dcnt < 2)
            return DCE2_RET__ERROR;

        // From data size check above, nb_len >= dsize
        dcnt -= 2;
        DCE2_MOVE(nb_ptr, nb_len, 2);
    }

    if (dcnt > nb_len)
        dcnt = (uint16_t)nb_len;

    // Pipe tracker already validated
    switch (policy)
    {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (start_write_raw)
            {
                if (ptracker->writex_raw == NULL)
                {
                    ptracker->writex_raw = (DCE2_SmbWriteAndXRaw *)
                        DCE2_Alloc(sizeof(DCE2_SmbWriteAndXRaw), DCE2_MEM_TYPE__SMB_FID);
                    if (ptracker->writex_raw == NULL)
                        return DCE2_RET__ERROR;

                    ptracker->writex_raw->remaining = (int)remaining;
                }
            }

            ptracker->writex_raw->remaining -= (int)dcnt;
            if (ptracker->writex_raw->remaining < 0)
            {
                ptracker->writex_raw->remaining = 0;
                DCE2_BufferEmpty(ptracker->writex_raw->buf);
                return DCE2_RET__ERROR;
            }

            // If the "raw" write isn't finished in the first request
            // and haven't allocated a buffer yet.
            if (start_write_raw && (ptracker->writex_raw->remaining != 0)
                    && (ptracker->writex_raw->buf == NULL))
            {
                ptracker->writex_raw->buf =
                    DCE2_BufferNew(remaining, 0, DCE2_MEM_TYPE__SMB_FID);
                if (ptracker->writex_raw->buf == NULL)
                {
                    ptracker->writex_raw->remaining = 0;
                    return DCE2_RET__ERROR;
                }
            }

            // If data has to be added to buffer, i.e. not a start raw
            // or a start raw and more raw requests to come.
            if (!start_write_raw || (ptracker->writex_raw->remaining != 0))
            {
                if (DCE2_BufferAddData(ptracker->writex_raw->buf, nb_ptr,
                            dcnt, DCE2_BufferLength(ptracker->writex_raw->buf),
                            DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
                {
                    ptracker->writex_raw->remaining = 0;
                    DCE2_BufferEmpty(ptracker->writex_raw->buf);
                    return DCE2_RET__ERROR;
                }

                if (ptracker->writex_raw->remaining == 0)
                {
                    // Create reassembled packet
                    const uint8_t *data_ptr = DCE2_BufferData(ptracker->writex_raw->buf);
                    uint32_t data_len = DCE2_BufferLength(ptracker->writex_raw->buf);
                    SFSnortPacket *rpkt = DCE2_SmbGetRpkt(ssd,
                            &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                    if (rpkt == NULL)
                    {
                        DCE2_BufferEmpty(ptracker->writex_raw->buf);
                        return DCE2_RET__ERROR;
                    }

                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Reassembled WriteAndX raw mode request\n"));
                    DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                    DCE2_SmbProcessRequestData(ssd, fid, data_ptr, data_len);

                    DCE2_SmbReturnRpkt();
                    DCE2_BufferEmpty(ptracker->writex_raw->buf);
                }
            }
            else
            {
                DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt);
            }

            // Windows doesn't process chained commands to raw WriteAndXs
            return DCE2_RET__ERROR;

        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            // All Samba cares about is skipping the 2 byte "length"
            // if both flags are set.
            break;
        default:
            DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid policy: %d",
                    __FILE__, __LINE__, policy);
            break;
    }

    return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt);
}

// SMB_COM_TRANSACTION2
static DCE2_Ret DCE2_SmbTransaction2(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);

    // NOTE: Only looking at TRANS2_OPEN2 as another way to open a named pipe

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial Transaction2 request and will have to complete the request
    // with Transaction2Secondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
            && (com_size == sizeof(SmbTransaction2InterimResp)))
    {
        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t sub_com = SmbTransaction2ReqSubCom((SmbTransaction2Req *)nb_ptr);

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Transaction2 subcommand: %s (0x%04X)\n",
                    (sub_com < TRANS2_SUBCOM_MAX)
                    ? smb_transaction2_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < TRANS2_SUBCOM_MAX)
            dce2_stats.smb_trans2_subcom_stats[SMB_TYPE__REQUEST][sub_com]++;
        else
            dce2_stats.smb_trans2_subcom_stats[SMB_TYPE__REQUEST][TRANS2_SUBCOM_MAX]++;

        switch (sub_com)
        {
            case TRANS2_OPEN2:
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_UNUSUAL_COMMAND_USED,
                        smb_transaction2_sub_command_strings[sub_com]);
                ssd->cur_rtracker->ttracker.subcom = (uint8_t)sub_com;
                break;
            case TRANS2_FIND_FIRST2:
            case TRANS2_FIND_NEXT2:
            case TRANS2_QUERY_FS_INFORMATION:
            case TRANS2_SET_FS_INFORMATION:
            case TRANS2_QUERY_PATH_INFORMATION:
            case TRANS2_SET_PATH_INFORMATION:
            case TRANS2_QUERY_FILE_INFORMATION:
            case TRANS2_SET_FILE_INFORMATION:
            case TRANS2_FSCTL:
            case TRANS2_IOCTL2:
            case TRANS2_FIND_NOTIFY_FIRST:
            case TRANS2_FIND_NOTIFY_NEXT:
            case TRANS2_CREATE_DIRECTORY:
            case TRANS2_SESSION_SETUP:
            case TRANS2_GET_DFS_REFERRAL:
            case TRANS2_REPORT_DFS_INCONSISTENCY:
            default:
                // Don't want to process this transaction any more
                return DCE2_RET__IGNORE;
        }
    }
    else
    {
        // NOTE: If other subcommands besides TRANS2_OPEN2 need to be
        // implemented, the code above needs to save off subcommand and
        // code below needs to be subcommand specific.

        // Response shouldn't have to be segmented as originator would be from
        // a malicious client trying to evade.  Have yet to see a client use
        // anything other than NtCreateAndX or OpenAndX and possibly Open
        // to open a named pipe depending on dialect negotiated.
        uint16_t tpcnt = SmbTransaction2RespTotalParamCnt((SmbTransaction2Resp *)nb_ptr);
        uint16_t pcnt = SmbTransaction2RespParamCnt((SmbTransaction2Resp *)nb_ptr);
        uint16_t poff = SmbTransaction2RespParamOff((SmbTransaction2Resp *)nb_ptr);
        uint16_t pdisp = SmbTransaction2RespParamDisp((SmbTransaction2Resp *)nb_ptr);
        uint16_t tdcnt = SmbTransaction2RespTotalDataCnt((SmbTransaction2Resp *)nb_ptr);
        uint16_t dcnt = SmbTransaction2RespDataCnt((SmbTransaction2Resp *)nb_ptr);
        uint16_t doff = SmbTransaction2RespDataOff((SmbTransaction2Resp *)nb_ptr);
        uint16_t ddisp = SmbTransaction2RespDataDisp((SmbTransaction2Resp *)nb_ptr);
        uint16_t sub_com = ssd->cur_rtracker->ttracker.subcom;

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Transaction2 subcommand: %s (0x%04X)\n",
                    (sub_com < TRANS2_SUBCOM_MAX)
                    ? smb_transaction2_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < TRANS2_SUBCOM_MAX)
            dce2_stats.smb_trans2_subcom_stats[SMB_TYPE__RESPONSE][sub_com]++;
        else
            dce2_stats.smb_trans2_subcom_stats[SMB_TYPE__RESPONSE][TRANS2_SUBCOM_MAX]++;

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTotalCount(ssd, tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTransDataParams(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (pcnt < sizeof(SmbTrans2Open2RespParams))
            return DCE2_RET__ERROR;

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + poff) - nb_ptr);

        DCE2_SmbNewPipeTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, SmbTrans2Open2RespFid((SmbTrans2Open2RespParams *)nb_ptr));
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION2_SECONDARY
static DCE2_Ret DCE2_SmbTransaction2Secondary(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    // Right now only looking at TRANS2_OPEN2 and only need response so if the
    // client chooses to segment the transaction just return success so as to
    // continue processing until the response comes so as to get the FID.
    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT
static DCE2_Ret DCE2_SmbTreeConnect(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        const uint8_t *bs = NULL;
        const uint8_t ipc_unicode[] = {'I', '\0', 'P', '\0', 'C', '\0', '$', '\0', '\0', '\0'};
        const uint8_t ipc_ascii[] = {'I', 'P', 'C', '$', '\0'};
        const uint8_t *ipc_chars;
        unsigned int ipc_len;
        unsigned int i;

        // Have at least 4 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // If unicode flag is set, strings, except possibly the service string
        // are going to be unicode.  The NT spec specifies that unicode strings
        // must be word aligned with respect to the beginning of the SMB and that for
        // type-prefixed strings (this case), the padding byte is found after the
        // type format byte.

        // XXX MS-CIFS states that these must be ASCII (or OEM) strings
        // regardless of whether or not the Unicode flag is set in the SMB
        // header.  Need to test...

        // This byte will realign things.
        if (*nb_ptr != SMB_FMT__ASCII)
        {
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_FORMAT, *nb_ptr);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        // IPC$ does not need to be case sensitive.  And the case sensitivity flag in
        // the SMB header doesn't seem to have any effect on this.
        while ((bs = memchr(nb_ptr, '\\', nb_len)) != NULL)
            DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

        if (SmbUnicode(smb_hdr) && (nb_len > 0))
            DCE2_MOVE(nb_ptr, nb_len, 1);

        // Check for invalid shares first
        if ((DCE2_ScSmbInvalidShares(ssd->sd.sconfig) != NULL) && (nb_len > 0))
            DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);

        // Set appropriate array and length
        if (SmbUnicode(smb_hdr))
        {
            ipc_chars = ipc_unicode;
            ipc_len = sizeof(ipc_unicode);
        }
        else
        {
            ipc_chars = ipc_ascii;
            ipc_len = sizeof(ipc_ascii);
        }

        // Make sure we have enough data
        if (nb_len < ipc_len)
            return DCE2_RET__ERROR;

        // Test for IPC$
        for (i = 0; i < ipc_len; i++)
        {
            if ((nb_ptr[i] != ipc_chars[i])
                    && (nb_ptr[i] != tolower((int)ipc_chars[i])))
            {
                break;
            }
        }

        // Not IPC$
        if (i != ipc_len)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                        "TreeConnect not IPC$ so not tracking.\n"));

            // Don't want to continue processing the response
            return DCE2_RET__ERROR;
        }
    }
    else
    {
        // XXX What if the TID in the SMB header differs from that returned
        // in the TreeConnect command response?
        uint16_t tid = SmbTid(smb_hdr);
        DCE2_SmbInsertTid(ssd, tid);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_DISCONNECT
static DCE2_Ret DCE2_SmbTreeDisconnect(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NEGOTIATE
static DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    PROFILE_VARS;

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    PREPROC_PROFILE_START(dce2_pstat_smb_negotiate);

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 2 bytes based on byte count check done earlier

        uint8_t *term_ptr;
        int ntlm_index = 0;

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        while ((term_ptr = memchr(nb_ptr, '\0', nb_len)) != NULL)
        {
            if (!SmbFmtDialect(*nb_ptr))
            {
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_BAD_FORMAT, *nb_ptr);

                // Windows errors if bad format
                if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_negotiate);
                    return DCE2_RET__ERROR;
                }
            }

            // Move past format
            DCE2_MOVE(nb_ptr, nb_len, 1);

            if (nb_len == 0)
                break;

            // Just a NULL byte - acceptable by Samba and Windows
            if (term_ptr == nb_ptr)
                continue;

            if ((*nb_ptr == 'N')
                    && (strncmp((const char *)nb_ptr, SMB_DIALECT_NT_LM_012, term_ptr - nb_ptr) == 0))
                break;

            // Move past string and NULL byte
            DCE2_MOVE(nb_ptr, nb_len, (term_ptr - nb_ptr) + 1);

            ntlm_index++;
        }

        if (term_ptr != NULL)
        {
            ssd->dialect_index = ntlm_index;
        }
        else
        {
            ssd->dialect_index = DCE2_SENTINEL;
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DEPR_DIALECT_NEGOTIATED);
        }
    }
    else
    {
        uint16_t dialect_index =
            SmbNegotiateRespDialectIndex((SmbCore_NegotiateProtocolResp *)nb_ptr);

        if ((ssd->dialect_index != DCE2_SENTINEL) && (dialect_index != ssd->dialect_index))
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_DEPR_DIALECT_NEGOTIATED);

        ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (DCE2_ComInfoWordCount(com_info) == 17)
        {
            ssd->max_outstanding_requests =
                SmbNt_NegotiateRespMaxMultiplex((SmbNt_NegotiateProtocolResp *)nb_ptr);
        }
        else if (DCE2_ComInfoWordCount(com_info) == 13)
        {
            ssd->max_outstanding_requests =
                SmbLm_NegotiateRespMaxMultiplex((SmbLm10_NegotiateProtocolResp *)nb_ptr);
        }
        else
        {
            ssd->max_outstanding_requests = 1;
        }
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_negotiate);
    return DCE2_RET__SUCCESS;
}

#define OS_0          (0)   // "Windows" start
#define OS_1    (OS_0+ 8)   // Windows 2000 and XP server
#define OS_2    (OS_1+ 4)   // Windows 2000 and XP client
#define OS_3    (OS_2+ 5)   // "Server", 2003, 2008R2, 2008
#define OS_4    (OS_3+20)   // Windows Vista
#define OS_5    (OS_4 +5)   // Windows 7
#define OS_6    (OS_5 +1)   // Windows NT
#define OS_7    (OS_6 +2)   // Windows 98
#define OS_FS   (OS_7+ 3)   // Failure state
#define OS_WIN2000    (OS_FS+1)
#define OS_WINXP      (OS_FS+2)
#define OS_WIN2003    (OS_FS+3)
#define OS_WINVISTA   (OS_FS+4)
#define OS_WIN2008    (OS_FS+5)
#define OS_WIN7       (OS_FS+6)

typedef struct _DCE2SmbOsFsm
{
    char input;
    int next_state;
    int fail_state;

} DCE2_SmbOsFsm;

static DCE2_SmbOsFsm dce2_smb_os_fsm[] =
{
    // Windows start states
    { 'W', OS_0+1, OS_FS },
    { 'i', OS_0+2, OS_FS },
    { 'n', OS_0+3, OS_FS },
    { 'd', OS_0+4, OS_FS },
    { 'o', OS_0+5, OS_FS },
    { 'w', OS_0+6, OS_FS },
    { 's', OS_0+7, OS_FS },
    { ' ', OS_0+8, OS_FS },

    // Windows 2000 and XP server states
    { '5', OS_1+1, OS_2 },
    { '.', OS_1+2, OS_FS },
    { '1', OS_WINXP, OS_1+3 },    // Windows XP
    { '0', OS_WIN2000, OS_FS },   // Windows 2000

    // Windows 2000 or XP client states
    { '2', OS_2+1, OS_3 },
    { '0', OS_2+2, OS_FS },
    { '0', OS_2+3, OS_FS },
    { '2', OS_WINXP, OS_2+4 },    // Windows XP
    { '0', OS_WIN2000, OS_FS },   // Windows 2000

    // "Server" string states
    { 'S', OS_3+ 1, OS_4 },
    { 'e', OS_3+ 2, OS_FS },
    { 'r', OS_3+ 3, OS_FS },
    { 'v', OS_3+ 4, OS_FS },
    { 'e', OS_3+ 5, OS_FS },
    { 'r', OS_3+ 6, OS_FS },
    { ' ', OS_3+ 7, OS_FS },
    { '2', OS_3+ 8, OS_3+12 },
    { '0', OS_3+ 9, OS_FS },
    { '0', OS_3+10, OS_FS },
    { '3', OS_WIN2003, OS_3+11 },   // Windows Server 2003
    { '8', OS_WIN2008, OS_FS },     // Windows Server 2008R2

    // Windows 2008 has this, 2008 R2 does not
    { '(', OS_3+13, OS_FS },
    { 'R', OS_3+14, OS_FS },
    { ')', OS_3+15, OS_FS },
    { ' ', OS_3+16, OS_FS },
    { '2', OS_3+17, OS_FS },
    { '0', OS_3+18, OS_FS },
    { '0', OS_3+19, OS_FS },
    { '8', OS_WIN2008, OS_FS },

    // Windows Vista states
    { 'V', OS_4+1, OS_5 },
    { 'i', OS_4+2, OS_FS },
    { 's', OS_4+3, OS_FS },
    { 't', OS_4+4, OS_FS },
    { 'a', OS_WINVISTA, OS_FS },

    // Windows 7 state
    { '7', OS_WIN7, OS_6 },

    // Windows NT
    { 'N', OS_6+1, OS_7 },
    { 'T', OS_WIN2000, OS_FS },  // Windows NT, set policy to Windows 2000

    // Windows 98
    { '4', OS_7+1, OS_FS },
    { '.', OS_7+2, OS_FS },
    { '0', OS_WIN2000, OS_FS },  // Windows 98, set policy to Windows 2000

    // Failure state
    { 0, OS_FS, OS_FS }

    // Match states shouldn't be accessed
};

// SMB_COM_SESSION_SETUP_ANDX
static DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t max_multiplex =
            SmbSessionSetupAndXReqMaxMultiplex((SmbLm10_SessionSetupAndXReq *)nb_ptr);

        if (max_multiplex < ssd->max_outstanding_requests)
            ssd->max_outstanding_requests = max_multiplex;

        if (!DCE2_SmbFingerprintedClient(ssd) && DCE2_GcSmbFingerprintClient())
        {
            uint8_t increment = SmbUnicode(smb_hdr) ? 2 : 1;
            uint16_t word_count = DCE2_ComInfoWordCount(com_info);
            uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
            uint32_t i;
            PROFILE_VARS;

            DCE2_SmbSetFingerprintedClient(ssd);

            // OS and Lanman strings won't be in request
            if ((word_count != 13) && (word_count != 12))
                return DCE2_RET__SUCCESS;

            PREPROC_PROFILE_START(dce2_pstat_smb_fingerprint);

            if (word_count == 13)
            {
                uint16_t oem_pass_len =
                    SmbNt10SessionSetupAndXReqOemPassLen((SmbNt10_SessionSetupAndXReq *)nb_ptr);
                uint16_t uni_pass_len =
                    SmbNt10SessionSetupAndXReqUnicodePassLen((SmbNt10_SessionSetupAndXReq *)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, com_size);

                if (((uint32_t)oem_pass_len + uni_pass_len) > nb_len)
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, (oem_pass_len + uni_pass_len));

                // If unicode there should be a padding byte if the password
                // lengths are even since the command length is odd
                if ((increment == 2) && (nb_len != 0) && (!(oem_pass_len + uni_pass_len) % 2))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else  // Extended security blob version, word count of 12
            {
                uint16_t blob_len =
                    SmbSessionSetupAndXReqBlobLen((SmbNt10_SessionSetupAndXExtReq *)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, com_size);

                if (blob_len > nb_len)
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, blob_len);

                // If unicode there should be a padding byte if the blob
                // length is even since the command length is odd
                if ((increment == 2) && (nb_len != 0) && !(blob_len % 2))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }

            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Attempting to fingerprint "
                        "Client Windows/Samba version ... \n"));

            // Move past Account and Domain strings
            // Blob version doesn't have these as they're in the blob
            if (DCE2_ComInfoWordCount(com_info) == 13)
            {
                int j;

                for (j = 0; j < 2; j++)
                {
                    while ((nb_len >= increment) && (*nb_ptr != '\0'))
                        DCE2_MOVE(nb_ptr, nb_len, increment);

                    // Just return success if we run out of data
                    if (nb_len < increment)
                    {
                        PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                        return DCE2_RET__SUCCESS;
                    }

                    // Move past NULL string terminator
                    DCE2_MOVE(nb_ptr, nb_len, increment);
                }
            }

            if (nb_len < increment)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Note the below is quick and dirty.  We're assuming the client
            // is kosher.  It's policy will be used when the server is
            // sending data to it.

#ifdef DEBUG
            {
                uint32_t k, l = 0;
                char buf[65535];

                for (k = 0; (k < nb_len) && (nb_ptr[k] != 0); k += increment, l++)
                    buf[l] = nb_ptr[k];

                buf[l] = 0;
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "  Client OS: %s\n", buf));

                k += increment;

                l = 0;
                for (; k < nb_len && nb_ptr[k] != 0; k += increment, l++)
                    buf[l] = nb_ptr[k];

                buf[l] = 0;
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "  Client Lanman: %s\n", buf));
            }
#endif

            // Windows Vista and above don't put anything here
            if (*nb_ptr == '\0')
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                            "Setting client policy to Windows Vista\n"));
                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINVISTA);
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Windows
            if (*nb_ptr == 'W')
            {
                int state = OS_0;
                int64_t rlen = (int64_t)nb_len;

                while ((rlen > 0) && (state < OS_FS))
                {
                    if (dce2_smb_os_fsm[state].input == (char)*nb_ptr)
                    {
                        state = dce2_smb_os_fsm[state].next_state;
                        DCE2_MOVE(nb_ptr, rlen, increment);
                    }
                    else
                    {
                        state = dce2_smb_os_fsm[state].fail_state;
                    }
                }

                switch (state)
                {
                    case OS_WIN2000:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting client policy to Windows 2000\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2000);
                        break;
                    case OS_WINXP:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting client policy to Windows XP\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINXP);
                        break;
                    case OS_WIN2003:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting client policy to Windows 2003\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2003);
                        break;
                    default:
                        break;
                }

                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Samba puts "Unix" in the OS field
            if (*nb_ptr != 'U')
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Move past OS string
            for (i = 0; (i < nb_len) && (nb_ptr[i] != '\0'); i += increment);

            if ((i + increment) >= nb_len)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Move to LanMan string
            DCE2_MOVE(nb_ptr, nb_len, i + increment);

            // Samba
            if (*nb_ptr == 'S')
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                            "Setting client policy to Samba\n"));
                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
            }

            PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
        }
    }
    else
    {
        uint16_t uid = SmbUid(smb_hdr);

        DCE2_SmbInsertUid(ssd, uid);
        ssd->cur_rtracker->uid = uid;  // Set this in case there are chained commands

        if (!(ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED))
            ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (!DCE2_SmbFingerprintedServer(ssd) && DCE2_GcSmbFingerprintServer())
        {
            uint8_t increment = SmbUnicode(smb_hdr) ? 2 : 1;
            uint32_t i;
            PROFILE_VARS;

            DCE2_SmbSetFingerprintedServer(ssd);

            // Set the policy based on what the server reports in the OS field
            // for Windows and the LanManager field for Samba

            if (DCE2_ComInfoByteCount(com_info) == 0)
                return DCE2_RET__SUCCESS;

            PREPROC_PROFILE_START(dce2_pstat_smb_fingerprint);

            if (DCE2_ComInfoWordCount(com_info) == 3)
            {
                DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

                // Word count 3 and Unicode has a one byte pad
                if ((increment == 2) && (nb_len != 0))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else  // Only valid word counts are 3 and 4
            {
                uint16_t blob_len = SmbSessionSetupAndXRespBlobLen((SmbNt10_SessionSetupAndXExtResp *)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

                if (blob_len > nb_len)
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, blob_len);

                if ((increment == 2) && (nb_len != 0) && !(blob_len % 2))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }

            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Attempting to fingerprint "
                        "Server Windows/Samba version ... \n"));

            // Note the below is quick and dirty.  We're assuming the server
            // is kosher.  It's policy will be used when the client is
            // sending data to it.

#ifdef DEBUG
            {
                uint32_t k, l = 0;
                char buf[65535];

                for (k = 0; (k < nb_len) && (nb_ptr[k] != 0); k += increment, l++)
                    buf[l] = nb_ptr[k];

                buf[l] = 0;
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "  Server OS: %s\n", buf));

                k += increment;

                l = 0;
                for (; k < nb_len && nb_ptr[k] != 0; k += increment, l++)
                    buf[l] = nb_ptr[k];

                buf[l] = 0;
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "  Server Lanman: %s\n", buf));
            }
#endif

            if ((nb_len < increment) || (*nb_ptr == '\0'))
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Next field should be OS string
            for (i = 0; (i < nb_len) && (nb_ptr[i] != '\0'); i += increment);
            i -= increment;

            // Windows
            if (*nb_ptr == 'W')
            {
                int state = OS_0;
                int64_t rlen = (int64_t)nb_len;

                while ((rlen > 0) && (state < OS_FS))
                {
                    if (dce2_smb_os_fsm[state].input == (char)*nb_ptr)
                    {
                        state = dce2_smb_os_fsm[state].next_state;
                        DCE2_MOVE(nb_ptr, rlen, increment);
                    }
                    else
                    {
                        state = dce2_smb_os_fsm[state].fail_state;
                    }
                }

                switch (state)
                {
                    case OS_WIN2000:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows 2000\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2000);
                        break;
                    case OS_WINXP:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows XP\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINXP);
                        break;
                    case OS_WIN2003:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows 2003\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2003);
                        break;
                    case OS_WIN2008:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows 2008\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2008);
                        break;
                    case OS_WINVISTA:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows Vista\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINVISTA);
                        break;
                    case OS_WIN7:
                        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                    "Setting server policy to Windows 7\n"));
                        DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN7);
                        break;
                    default:
                        break;
                }

                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Samba puts "Unix" in the OS field
            if (*nb_ptr != 'U')
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Move past OS string
            for (i = 0; (i < nb_len) && (nb_ptr[i] != '\0'); i += increment);

            if ((i + increment) >= nb_len)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                return DCE2_RET__SUCCESS;
            }

            // Move to LanMan string
            DCE2_MOVE(nb_ptr, nb_len, i + increment);

            // Samba
            if (*nb_ptr == 'S')
            {
                uint8_t r1 = 0;  // Release version first digit
                uint8_t r2 = 0;  // Release version second digit

                // Get Major version
                for (i = 0; (i < nb_len) && (*nb_ptr != '\0'); i += increment)
                {
                    if (isdigit((int)nb_ptr[i]))
                        break;
                }

                if ((i == nb_len) || (*nb_ptr == '\0'))
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                // If less than 3 set policy to earliest Samba policy we use
                if ((nb_ptr[i] == '0') || (nb_ptr[i] == '1') || (nb_ptr[i] == '2'))
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Setting server policy to Samba 3.0.20\n"));
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_20);
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                // Need ".\d.\d\d" or ".\d.\d\x00"
                if (i + increment*5 > nb_len)
                {
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS; 
                }

                i += increment*2;

                // If it's not 0, then set to latest Samba policy we use
                if (nb_ptr[i] != '0')
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Setting server policy to current Samba\n"));
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                r1 = nb_ptr[i + increment*2];
                r2 = nb_ptr[i + increment*3];

                // First digit is 1 or no second digit or 20, Samba 3.0.20
                if ((r1 == '1') || (r2 == '\0') || ((r1 == '2') && (r2 == '0')))
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Setting server policy to Samba 3.0.20\n"));
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_20);
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                // 21 or 22, Samba 3.0.22
                if ((r1 == '2') && (r2 <= '2'))
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Setting server policy to Samba 3.0.22\n"));
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_22);
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                // 23, 24 ... 30 ... 37, Samba 3.0.37
                if ((r1 == '2') || ((r1 == '3') && (r2 <= '7')))
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                                "Setting server policy to Samba 3.0.37\n"));
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_37);
                    PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
                    return DCE2_RET__SUCCESS;
                }

                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                            "Setting server policy to current Samba\n"));
                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
            }

            PREPROC_PROFILE_END(dce2_pstat_smb_fingerprint);
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_LOGOFF_ANDX
static DCE2_Ret DCE2_SmbLogoffAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbRemoveUid(ssd, ssd->cur_rtracker->uid);

        switch (DCE2_SsnGetServerPolicy(&ssd->sd))
        {
            case DCE2_POLICY__WIN2000:
            case DCE2_POLICY__WINXP:
            case DCE2_POLICY__WINVISTA:
            case DCE2_POLICY__WIN2003:
            case DCE2_POLICY__WIN2008:
            case DCE2_POLICY__WIN7:
                /* Windows responds to a chained LogoffAndX => SessionSetupAndX with a
                 * word count 3 LogoffAndX without the chained SessionSetupAndX */
                if (DCE2_ComInfoWordCount(com_info) == 3)
                {
                    uint16_t uid = SmbUid(smb_hdr);
                    DCE2_SmbInsertUid(ssd, uid);
                    ssd->cur_rtracker->uid = uid;  // Set this in case there are chained commands
                }
                break;
            default:
                break;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT_ANDX
static DCE2_Ret DCE2_SmbTreeConnectAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        if (DCE2_ScSmbInvalidShares(ssd->sd.sconfig) != NULL)
        {
            uint16_t pass_len = SmbTreeConnectAndXReqPassLen((SmbTreeConnectAndXReq *)nb_ptr);
            const uint8_t *bs = NULL;

            DCE2_MOVE(nb_ptr, nb_len, com_size);

            if (pass_len >= nb_len)
                return DCE2_RET__ERROR;

            // Move past password length
            DCE2_MOVE(nb_ptr, nb_len, pass_len);

            // Move past path components
            while ((bs = memchr(nb_ptr, '\\', nb_len)) != NULL)
                DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

            // Move past NULL byte if unicode
            if (SmbUnicode(smb_hdr) && (nb_len != 0))
                DCE2_MOVE(nb_ptr, nb_len, 1);

            if (nb_len != 0)
                DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);
        }
    }
    else
    {
        const uint8_t ipc_chars[] = {'I', 'P', 'C', '\0'};
        unsigned int i;
        uint16_t tid = SmbTid(smb_hdr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (nb_len < sizeof(ipc_chars))
            return DCE2_RET__ERROR;

        // XXX Can this be case insensitive?
        // Look for IPC
        for (i = 0; i < sizeof(ipc_chars); i++)
        {
            if ((nb_ptr[i] != ipc_chars[i]))
                break;
        }

        if (i != sizeof(ipc_chars))
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                        "Tid (%u) not an IPC tree\n", SmbTid(smb_hdr)));
            return DCE2_RET__ERROR;
        }

        // Insert tid into list
        DCE2_SmbInsertTid(ssd, tid);
        ssd->cur_rtracker->tid = tid;  // Set this in case there are chained commands
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_TRANSACT
static DCE2_Ret DCE2_SmbNtTransact(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);

    // NOTE: Only looking at NT_TRANSACT_CREATE as another way to open a named pipe

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial NtTransact request and will have to complete the request
    // with NtTransactSecondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
            && (com_size == sizeof(SmbNtTransactInterimResp)))
    {
        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t sub_com = SmbNtTransactReqSubCom((SmbNtTransactReq *)nb_ptr);

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Nt Transact subcommand: %s (0x%04X)\n",
                    (sub_com < NT_TRANSACT_SUBCOM_MAX)
                    ? smb_nt_transact_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < NT_TRANSACT_SUBCOM_MAX)
            dce2_stats.smb_nt_transact_subcom_stats[SMB_TYPE__REQUEST][sub_com]++;
        else
            dce2_stats.smb_nt_transact_subcom_stats[SMB_TYPE__REQUEST][NT_TRANSACT_SUBCOM_MAX]++;

        switch (sub_com)
        {
            case NT_TRANSACT_CREATE:
                ssd->cur_rtracker->ttracker.subcom = (uint8_t)sub_com;
                DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_UNUSUAL_COMMAND_USED,
                        smb_nt_transact_sub_command_strings[sub_com]);
                break;
            case NT_TRANSACT_IOCTL:
            case NT_TRANSACT_SET_SECURITY_DESC:
            case NT_TRANSACT_NOTIFY_CHANGE:
            case NT_TRANSACT_RENAME:
            case NT_TRANSACT_QUERY_SECURITY_DESC:
            default:
                // Don't want to process this transaction any more
                return DCE2_RET__IGNORE;
        }
    }
    else
    {
        // NOTE: If other subcommands besides NT_TRANSACT_CREATE need to be
        // implemented, the code above needs to save off subcommand and
        // code below needs to be subcommand specific.

        // Response shouldn't have to be segmented as originator would be from
        // a malicious client trying to evade.  Have yet to see a client use
        // anything other than NtCreateAndX or OpenAndX and possibly Open
        // to open a named pipe depending on dialect negotiated.
        uint32_t tpcnt = SmbNtTransactRespTotalParamCnt((SmbNtTransactResp *)nb_ptr);
        uint32_t pcnt = SmbNtTransactRespParamCnt((SmbNtTransactResp *)nb_ptr);
        uint32_t poff = SmbNtTransactRespParamOff((SmbNtTransactResp *)nb_ptr);
        uint32_t pdisp = SmbNtTransactRespParamDisp((SmbNtTransactResp *)nb_ptr);
        uint32_t tdcnt = SmbNtTransactRespTotalDataCnt((SmbNtTransactResp *)nb_ptr);
        uint32_t dcnt = SmbNtTransactRespDataCnt((SmbNtTransactResp *)nb_ptr);
        uint32_t doff = SmbNtTransactRespDataOff((SmbNtTransactResp *)nb_ptr);
        uint32_t ddisp = SmbNtTransactRespDataDisp((SmbNtTransactResp *)nb_ptr);
        uint16_t sub_com = ssd->cur_rtracker->ttracker.subcom;

        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Nt Transact subcommand: %s (0x%04X)\n",
                    (sub_com < NT_TRANSACT_SUBCOM_MAX)
                    ? smb_nt_transact_sub_command_strings[sub_com]
                    : "Unknown", sub_com));

        if (sub_com < NT_TRANSACT_SUBCOM_MAX)
            dce2_stats.smb_nt_transact_subcom_stats[SMB_TYPE__RESPONSE][sub_com]++;
        else
            dce2_stats.smb_nt_transact_subcom_stats[SMB_TYPE__RESPONSE][NT_TRANSACT_SUBCOM_MAX]++;

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckTotalCount(ssd, tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTotalCount(ssd, tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckTransDataParams(ssd, (uint8_t *)smb_hdr, nb_ptr, nb_len,
                    byte_count, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (pcnt < sizeof(SmbNtTransactCreateRespParams))
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t *)smb_hdr + poff) - nb_ptr);

        DCE2_SmbNewPipeTracker(ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
                SmbNtTransactCreateRespFid((SmbNtTransactCreateRespParams *)nb_ptr));
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_TRANSACT_SECONDARY
static DCE2_Ret DCE2_SmbNtTransactSecondary(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    // Right now only looking at NT_TRANSACT_CREATE and only need response so if the
    // client chooses to segment the transaction just return success so as to
    // continue processing until the response comes so as to get the FID.
    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_CREATE_ANDX
static DCE2_Ret DCE2_SmbNtCreateAndX(DCE2_SmbSsnData *ssd, const SmbNtHdr *smb_hdr,
        const DCE2_SmbComInfo *com_info, const uint8_t *nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        uint16_t uid = ssd->cur_rtracker->uid;
        uint16_t tid = ssd->cur_rtracker->tid;
        const uint16_t fid = SmbNtCreateAndXRespFid((SmbNtCreateAndXResp *)nb_ptr);

        // Set request tracker's current pipe tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon *)nb_ptr))
        {
            // This is in case in the request a write was chained to an open
            // in which case the write will be to the newly opened named pipe
            case SMB_COM_WRITE:
            case SMB_COM_WRITE_ANDX:
            case SMB_COM_TRANSACTION:
                ssd->cur_rtracker->ptracker =
                    DCE2_SmbDequeueTmpPipeTracker(ssd, ssd->cur_rtracker, fid);
                if (ssd->cur_rtracker->ptracker != NULL)
                    break;

                // Fall through

            default:
                ssd->cur_rtracker->ptracker = DCE2_SmbNewPipeTracker(ssd, uid, tid, fid);
                break;
        }
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData *ssd,
        const uint16_t fid, const uint8_t *data_ptr, uint32_t data_len)
{
    DCE2_SmbPipeTracker *ptracker = DCE2_SmbGetPipeTracker(ssd, fid);

    if (ptracker == NULL)
        return DCE2_RET__ERROR;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Processing request data with Fid: 0x%04X ~~~~~~~~~~~~~~~~~\n", ptracker->fid));

    // Set this in case of chained commands or reassembled packet
    ssd->cur_rtracker->ptracker = ptracker;

    // Maximum possible fragment length is 16 bit
    if (data_len > UINT16_MAX)
        data_len = UINT16_MAX;

    DCE2_CoProcess(&ssd->sd, &ptracker->co_tracker, data_ptr, (uint16_t)data_len);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"));

    // For Windows 2000
    if (!ptracker->used)
        ptracker->used = true;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData *ssd,
        const uint8_t *data_ptr, uint32_t data_len)
{
    DCE2_SmbPipeTracker *ptracker = ssd->cur_rtracker->ptracker;

    if (ptracker == NULL)
        return DCE2_RET__ERROR;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Processing response data with Fid: 0x%04X ~~~~~~~~~~~~~~~~\n", ptracker->fid));

    // Maximum possible fragment length is 16 bit
    if (data_len > UINT16_MAX)
        data_len = UINT16_MAX;

    DCE2_CoProcess(&ssd->sd, &ptracker->co_tracker, data_ptr, (uint16_t)data_len);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"));

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *  DCE2_SmbRequestTracker *
 *      NULL if memcap is reached trying to allocate a new one.
 *
 ********************************************************************/
static inline DCE2_SmbRequestTracker * DCE2_SmbNewRequestTracker(DCE2_SmbSsnData *ssd,
        const SmbNtHdr *smb_hdr)
{
    DCE2_SmbRequestTracker *rtracker = NULL;
    DCE2_SmbRequestTracker *tmp_rtracker = NULL;
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    if (ssd == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return NULL;
    }

    if (ssd->outstanding_requests >= ssd->max_outstanding_requests)
    {
        DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_MAX_REQS_EXCEEDED,
                ssd->max_outstanding_requests);
    }

    // Check for outstanding requests with the same MID
    tmp_rtracker = &ssd->rtracker;
    while ((tmp_rtracker != NULL) && (tmp_rtracker->mid != DCE2_SENTINEL))
    {
        if (tmp_rtracker->mid == (int)mid)
        {
            // Have yet to see an MID repeatedly used so shouldn't
            // be any outstanding requests with the same MID.
            DCE2_Alert(&ssd->sd, DCE2_EVENT__SMB_REQS_SAME_MID);
            break;
        }

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = DCE2_QueueNext(ssd->rtrackers);
    }

    if (ssd->rtracker.mid == DCE2_SENTINEL)
    {
        rtracker = &ssd->rtracker;
    }
    else
    {
        if (ssd->rtrackers == NULL)
        {
            ssd->rtrackers = DCE2_QueueNew(DCE2_SmbRequestTrackerDataFree, DCE2_MEM_TYPE__SMB_REQ);
            if (ssd->rtrackers == NULL)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_req);
                return NULL;
            }
        }

        rtracker = (DCE2_SmbRequestTracker *)DCE2_Alloc(sizeof(DCE2_SmbRequestTracker), DCE2_MEM_TYPE__SMB_REQ);
        if (rtracker == NULL)
        {
            PREPROC_PROFILE_END(dce2_pstat_smb_req);
            return NULL;
        }

        if (DCE2_QueueEnqueue(ssd->rtrackers, (void *)rtracker) != DCE2_RET__SUCCESS)
        {
            DCE2_Free((void *)rtracker, sizeof(DCE2_SmbRequestTracker), DCE2_MEM_TYPE__SMB_REQ);
            PREPROC_PROFILE_END(dce2_pstat_smb_req);
            return NULL;
        }
    }

    rtracker->smb_com = SmbCom(smb_hdr);
    rtracker->uid = uid;
    rtracker->tid = tid;
    rtracker->pid = pid;
    rtracker->mid = (int)mid;
    memset(&rtracker->ttracker, 0, sizeof(rtracker->ttracker));
    rtracker->ptracker = NULL;

    ssd->outstanding_requests++;
    if (ssd->outstanding_requests > dce2_stats.smb_max_outstanding_requests)
        dce2_stats.smb_max_outstanding_requests = ssd->outstanding_requests;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Added new request tracker => "
                "Uid: %u, Tid: %u, Pid: %u, Mid: %u\n",
                rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid));
    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Current outstanding requests: %u\n", ssd->outstanding_requests));

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
    return rtracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker *ttracker,
        const uint8_t *data_ptr, uint16_t dcnt, uint16_t ddisp)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Buffering transaction data.\n"));

    if (ttracker->dbuf == NULL)
    {
        /* Buf size should be the total data count we need */
        ttracker->dbuf = DCE2_BufferNew(ttracker->tdcnt, 0, DCE2_MEM_TYPE__SMB_REQ);
        if (ttracker->dbuf == NULL)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Failed to allocate new "
                        "buffer to for transaction data.\n"));
            PREPROC_PROFILE_END(dce2_pstat_smb_req);
            return DCE2_RET__ERROR;
        }
    }

    if (DCE2_BufferAddData(ttracker->dbuf, data_ptr, dcnt, ddisp,
                DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Failed to buffer transaction data.\n"));
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return DCE2_RET__ERROR;
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Successfully buffered transaction data.\n"));

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker *ttracker,
        const uint8_t *param_ptr, uint16_t pcnt, uint16_t pdisp)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Buffering transaction parameters.\n"));

    if (ttracker->pbuf == NULL)
    {
        /* Buf size should be the total data count we need */
        ttracker->pbuf = DCE2_BufferNew(ttracker->tpcnt, 0, DCE2_MEM_TYPE__SMB_REQ);
        if (ttracker->pbuf == NULL)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Failed to allocate new "
                        "buffer to for transaction parameter.\n"));
            PREPROC_PROFILE_END(dce2_pstat_smb_req);
            return DCE2_RET__ERROR;
        }
    }

    if (DCE2_BufferAddData(ttracker->pbuf, param_ptr, pcnt, pdisp,
                DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                    "Failed to buffer transaction parameter data.\n"));
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return DCE2_RET__ERROR;
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Successfully buffered transaction parameter data.\n"));

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_SmbRequestTracker * DCE2_SmbFindRequestTracker(DCE2_SmbSsnData *ssd,
        const SmbNtHdr *smb_hdr)
{
    DCE2_Policy policy = DCE2_SsnGetPolicy(&ssd->sd);
    DCE2_SmbRequestTracker *first_rtracker = NULL;
    DCE2_SmbRequestTracker *win_rtracker = NULL;
    DCE2_SmbRequestTracker *first_mid_rtracker = NULL;
    DCE2_SmbRequestTracker *tmp_rtracker = NULL;
    DCE2_SmbRequestTracker *ret_rtracker = NULL;
    int smb_com = SmbCom(smb_hdr);
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Find request tracker => "
                "Uid: %u, Tid: %u, Pid: %u, Mid: %u ... ", uid, tid, pid, mid));

    tmp_rtracker = &ssd->rtracker;

    switch (smb_com)
    {
        case SMB_COM_TRANSACTION_SECONDARY:
            smb_com = SMB_COM_TRANSACTION;
            break;
        case SMB_COM_TRANSACTION2_SECONDARY:
            smb_com = SMB_COM_TRANSACTION2;
            break;
        case SMB_COM_NT_TRANSACT_SECONDARY:
            smb_com = SMB_COM_NT_TRANSACT;
            break;
        case SMB_COM_WRITE_COMPLETE:
            smb_com = SMB_COM_WRITE_RAW;
            break;
        default:
            break;
    }

    while (tmp_rtracker != NULL)
    {
        if ((tmp_rtracker->mid == (int)mid) && (tmp_rtracker->smb_com == smb_com))
        {
            // This is the normal case except for SessionSetupAndX and
            // TreeConnect/TreeConnectAndX which will fall into the
            // default case below.
            if ((tmp_rtracker->pid == pid) && (tmp_rtracker->uid == uid)
                    && (tmp_rtracker->tid == tid))
            {
                ret_rtracker = tmp_rtracker;
            }
            else
            {
                switch (smb_com)
                {
                    case SMB_COM_TRANSACTION:
                    case SMB_COM_TRANSACTION2:
                    case SMB_COM_NT_TRANSACT:
                    case SMB_COM_TRANSACTION_SECONDARY:
                    case SMB_COM_TRANSACTION2_SECONDARY:
                    case SMB_COM_NT_TRANSACT_SECONDARY:
                        // These should conform to above
                        break;
                    default:
                        if (tmp_rtracker->pid == pid)
                            ret_rtracker = tmp_rtracker;
                        break;
                }
            }

            if (ret_rtracker != NULL)
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Found.\n"));
                PREPROC_PROFILE_END(dce2_pstat_smb_req);
                return ret_rtracker;
            }

            // Take the first one where the PIDs also match
            // in the case of the Transacts above
            if ((tmp_rtracker->pid == pid) && (win_rtracker == NULL))
                win_rtracker = tmp_rtracker;

            // Set this to the first matching request in the queue
            // where the Mid matches.  Don't set for Windows if from
            // client since PID/MID are necessary
            if (((DCE2_SmbType(ssd) == SMB_TYPE__RESPONSE)
                        || !DCE2_SsnIsWindowsPolicy(&ssd->sd))
                    && first_mid_rtracker == NULL)
            {
                first_mid_rtracker = tmp_rtracker;
            }
        }

        // Set the first one we see for early Samba versions
        if ((first_rtracker == NULL) && (tmp_rtracker->mid != DCE2_SENTINEL)
                && (tmp_rtracker->smb_com == smb_com))
            first_rtracker = tmp_rtracker;

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = DCE2_QueueNext(ssd->rtrackers);
    }

    switch (policy)
    {
        case DCE2_POLICY__SAMBA_3_0_20:
        case DCE2_POLICY__SAMBA_3_0_22:
            ret_rtracker = first_rtracker;
            break;
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
            ret_rtracker = first_mid_rtracker;
            break;
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (win_rtracker != NULL)
                ret_rtracker = win_rtracker;
            else
                ret_rtracker = first_mid_rtracker;
            break;
        default:
            DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid policy: %d",
                    __FILE__, __LINE__, policy);
            break;
    }

    DCE2_DEBUG_CODE(DCE2_DEBUG__SMB,
            if (ret_rtracker != NULL) printf("Found.\n");
            else printf("Not found\n"););

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
    return ret_rtracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData *ssd,
        DCE2_SmbRequestTracker *rtracker)
{
    DCE2_SmbRequestTracker *tmp_node;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    if ((ssd == NULL) || (rtracker == NULL))
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return;
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removing request tracker => "
                "Uid: %u, Tid: %u, Pid: %u, Mid: %u ... ",
                rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid));

    if (rtracker == &ssd->rtracker)
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removed\n"));

        DCE2_SmbCleanRequestTracker(&ssd->rtracker);
        ssd->outstanding_requests--;

        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return;
    }

    for (tmp_node = DCE2_QueueFirst(ssd->rtrackers);
            tmp_node != NULL;
            tmp_node = DCE2_QueueNext(ssd->rtrackers))
    {
        if (tmp_node == (void *)rtracker)
        {
            DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removed.\n"));

            DCE2_QueueRemoveCurrent(ssd->rtrackers);
            ssd->outstanding_requests--;

            PREPROC_PROFILE_END(dce2_pstat_smb_req);
            return;
        }
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not removed.\n"));

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbInsertUid(DCE2_SmbSsnData *ssd, const uint16_t uid)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_uid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Inserting Uid: %u\n", uid););

    if (ssd->uid == DCE2_SENTINEL)
    {
        ssd->uid = (int)uid;
    }
    else
    {
        if (ssd->uids == NULL)
        {
            ssd->uids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                    NULL, NULL, DCE2_LIST_FLAG__NO_DUPS, DCE2_MEM_TYPE__SMB_UID);

            if (ssd->uids == NULL)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_uid);
                return;
            }
        }

        DCE2_ListInsert(ssd->uids, (void *)(uintptr_t)uid, (void *)(uintptr_t)uid);
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_uid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData *ssd, const uint16_t uid)
{
    DCE2_Ret status;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_uid);

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->uids, (void *)(uintptr_t)uid);

    PREPROC_PROFILE_END(dce2_pstat_smb_uid);

    return status;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbRemoveUid(DCE2_SmbSsnData *ssd, const uint16_t uid)
{
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbRequestTracker *rtracker;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_uid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removing Uid: %u\n", uid););

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        ssd->uid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->uids, (void *)(uintptr_t)uid);

    switch (policy)
    {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
            // Removing uid invalidates any fid that was created with it */
            if ((ssd->ptracker.fid != DCE2_SENTINEL) &&
                    (ssd->ptracker.uid == uid))
            {
                DCE2_SmbRemovePipeTracker(ssd, &ssd->ptracker);

                // NULL out pipe trackers of any outstanding requests
                // that reference this pipe tracker
                if (ssd->rtracker.ptracker == &ssd->ptracker)
                    ssd->rtracker.ptracker = NULL;

                for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                        rtracker != NULL;
                        rtracker = DCE2_QueueNext(ssd->rtrackers))
                {
                    if (rtracker->ptracker == &ssd->ptracker)
                        rtracker->ptracker = NULL;
                }
            }

            if (ssd->ptrackers != NULL)
            {
                DCE2_SmbPipeTracker *ptracker;

                for (ptracker = DCE2_ListFirst(ssd->ptrackers);
                        ptracker != NULL;
                        ptracker = DCE2_ListNext(ssd->ptrackers))
                {
                    if (ptracker->uid == uid)
                    {
                        DCE2_ListRemoveCurrent(ssd->ptrackers);

                        // NULL out pipe trackers of any outstanding requests
                        // that reference this pipe tracker
                        if (ssd->rtracker.ptracker == ptracker)
                            ssd->rtracker.ptracker = NULL;

                        for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                                rtracker != NULL;
                                rtracker = DCE2_QueueNext(ssd->rtrackers))
                        {
                            if (rtracker->ptracker == ptracker)
                                rtracker->ptracker = NULL;
                        }
                    }
                }
            }

            break;

        case DCE2_POLICY__SAMBA_3_0_20:
        case DCE2_POLICY__SAMBA_3_0_22:
            // Removing Uid used to create pipe doesn't invalidate it.
            break;

        default:
            DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid policy: %d",
                    __FILE__, __LINE__, policy);
            break;
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_uid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbInsertTid(DCE2_SmbSsnData *ssd, const uint16_t tid)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_tid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Inserting Tid: %u\n", tid));

    if (ssd->tid == DCE2_SENTINEL)
    {
        ssd->tid = (int)tid;
    }
    else
    {
        if (ssd->tids == NULL)
        {
            ssd->tids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                    NULL, NULL, DCE2_LIST_FLAG__NO_DUPS, DCE2_MEM_TYPE__SMB_TID);

            if (ssd->tids == NULL)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_tid);
                return;
            }
        }

        DCE2_ListInsert(ssd->tids, (void *)(uintptr_t)tid, (void *)(uintptr_t)tid);
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_tid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData *ssd, const uint16_t tid)
{
    DCE2_Ret status;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_tid);

    if ((ssd->tid != DCE2_SENTINEL) && (ssd->tid == (int)tid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->tids, (void *)(uintptr_t)tid);

    PREPROC_PROFILE_END(dce2_pstat_smb_tid);

    return status;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbRemoveTid(DCE2_SmbSsnData *ssd, const uint16_t tid)
{
    DCE2_SmbRequestTracker *rtracker;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_tid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removing Tid: %u\n", tid));

    if ((ssd->tid != DCE2_SENTINEL) && (ssd->tid == (int)tid))
        ssd->tid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->tids, (void *)(uintptr_t)tid);

    // Removing Tid invalidates named pipes created with it
    if ((ssd->ptracker.fid != DCE2_SENTINEL)
            && (ssd->ptracker.tid == tid))
    {
        DCE2_SmbRemovePipeTracker(ssd, &ssd->ptracker);

        // NULL out pipe trackers of any outstanding requests
        // that reference this pipe tracker
        if (ssd->rtracker.ptracker == &ssd->ptracker)
            ssd->rtracker.ptracker = NULL;

        for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                rtracker != NULL;
                rtracker = DCE2_QueueNext(ssd->rtrackers))
        {
            if (rtracker->ptracker == &ssd->ptracker)
                rtracker->ptracker = NULL;
        }
    }

    if (ssd->ptrackers != NULL)
    {
        DCE2_SmbPipeTracker *ptracker;

        for (ptracker = DCE2_ListFirst(ssd->ptrackers);
                ptracker != NULL;
                ptracker = DCE2_ListNext(ssd->ptrackers))
        {
            if (ptracker->tid == (int)tid)
            {
                DCE2_ListRemoveCurrent(ssd->ptrackers);

                // NULL out pipe trackers of any outstanding requests
                // that reference this pipe tracker
                if (ssd->rtracker.ptracker == ptracker)
                    ssd->rtracker.ptracker = NULL;

                for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                        rtracker != NULL;
                        rtracker = DCE2_QueueNext(ssd->rtrackers))
                {
                    if (rtracker->ptracker == ptracker)
                        rtracker->ptracker = NULL;
                }
            }
        }
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_tid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static DCE2_SmbPipeTracker * DCE2_SmbNewPipeTracker(DCE2_SmbSsnData *ssd,
        const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    DCE2_SmbPipeTracker *ptracker = NULL;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Creating new named pipe tracker "
                "with Uid: %u, Tid: %u, Fid: 0x%04x\n", uid, tid, fid));

    if (ssd->ptracker.fid == DCE2_SENTINEL)
    {
        ptracker = &ssd->ptracker;
    }
    else
    {
        if (ssd->ptrackers == NULL)
        {
            ssd->ptrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                    DCE2_SmbUidTidFidCompare, DCE2_SmbPipeTrackerDataFree, NULL,
                    DCE2_LIST_FLAG__NO_DUPS, DCE2_MEM_TYPE__SMB_FID);

            if (ssd->ptrackers == NULL)
            {
                PREPROC_PROFILE_END(dce2_pstat_smb_fid);
                return NULL;
            }
        }

        ptracker = (DCE2_SmbPipeTracker *)
            DCE2_Alloc(sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);

        if (ptracker == NULL)
        {
            PREPROC_PROFILE_END(dce2_pstat_smb_fid);
            return NULL;
        }

        if (DCE2_ListInsert(ssd->ptrackers, (void *)(uintptr_t)fid,
                    (void *)ptracker) != DCE2_RET__SUCCESS)
        {
            DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
            PREPROC_PROFILE_END(dce2_pstat_smb_fid);
            return NULL;
        }
    }

    ptracker->uid = uid;
    ptracker->tid = tid;
    ptracker->fid = (int)fid;
    ptracker->used = false;
    ptracker->writex_raw = NULL;
    DCE2_CoInitTracker(&ptracker->co_tracker);

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
    return ptracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbQueueTmpPipeTracker(DCE2_SmbRequestTracker *rtracker,
        const uint16_t uid, const uint16_t tid)
{
    DCE2_SmbPipeTracker *ptracker = NULL;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Queueing named pipe tracker "
                "with Uid: %u, Tid: %u\n", uid, tid));

    if (rtracker->pt_queue == NULL)
    {
        rtracker->pt_queue = DCE2_QueueNew(DCE2_SmbPipeTrackerDataFree, DCE2_MEM_TYPE__SMB_FID);
        if (rtracker->pt_queue == NULL)
        {
            PREPROC_PROFILE_END(dce2_pstat_smb_fid);
            return;
        }
    }

    ptracker = (DCE2_SmbPipeTracker *)
        DCE2_Alloc(sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);

    if (ptracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return;
    }

    if (DCE2_QueueEnqueue(rtracker->pt_queue, (void *)ptracker) != DCE2_RET__SUCCESS)
    {
        DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return;
    }

    ptracker->uid = uid;
    ptracker->tid = tid;
    ptracker->fid = DCE2_SENTINEL;
    ptracker->used = false;
    ptracker->writex_raw = NULL;
    DCE2_CoInitTracker(&ptracker->co_tracker);

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns: None
 *
 ********************************************************************/
static inline DCE2_SmbPipeTracker * DCE2_SmbGetTmpPipeTracker(DCE2_SmbRequestTracker *rtracker)
{
    if (!DCE2_QueueIsEmpty(rtracker->pt_queue))
        return (DCE2_SmbPipeTracker *)DCE2_QueueLast(rtracker->pt_queue);
    return NULL;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbEmptyTmpPipeTrackerQueue(DCE2_SmbRequestTracker *rtracker)
{
    if (!DCE2_QueueIsEmpty(rtracker->pt_queue))
        DCE2_QueueEmpty(rtracker->pt_queue);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns: None
 *
 ********************************************************************/
static DCE2_SmbPipeTracker * DCE2_SmbDequeueTmpPipeTracker(DCE2_SmbSsnData *ssd,
        DCE2_SmbRequestTracker *rtracker, const uint16_t fid)
{
    DCE2_SmbPipeTracker *ptracker;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Dequeueing named pipe tracker "
                "and binding to fid: 0x%04x\n", fid));

    ptracker = (DCE2_SmbPipeTracker *)DCE2_QueueDequeue(rtracker->pt_queue);
    if (ptracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return NULL;
    }

    if (ssd->ptracker.fid == DCE2_SENTINEL)
    {
        memcpy(&ssd->ptracker, ptracker, sizeof(DCE2_SmbPipeTracker));
        DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
        ptracker = &ssd->ptracker;
    }
    else
    {
        if (ssd->ptrackers == NULL)
        {
            ssd->ptrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                    DCE2_SmbUidTidFidCompare, DCE2_SmbPipeTrackerDataFree, NULL,
                    DCE2_LIST_FLAG__NO_DUPS, DCE2_MEM_TYPE__SMB_FID);

            if (ssd->ptrackers == NULL)
            {
                DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
                PREPROC_PROFILE_END(dce2_pstat_smb_fid);
                return NULL;
            }
        }

        if (DCE2_ListInsert(ssd->ptrackers, (void *)(uintptr_t)fid,
                    (void *)ptracker) != DCE2_RET__SUCCESS)
        {
            DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
            PREPROC_PROFILE_END(dce2_pstat_smb_fid);
            return NULL;
        }
    }

    // Other values were intialized when queueing.
    ptracker->fid = (int)fid;

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
    return ptracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline DCE2_SmbPipeTracker * DCE2_SmbGetPipeTracker(DCE2_SmbSsnData *ssd,
        const uint16_t fid)
{
    DCE2_SmbPipeTracker *ptracker = ssd->cur_rtracker->ptracker;

    if (ptracker == NULL)
    {
        // Write could've been chained to an OpenAndX or NtCreateAndX so a
        // temporary pipe tracker would've been created until we get the
        // response with the Fid returned from the OpenAndX / NtCreateAndX
        ptracker = DCE2_SmbGetTmpPipeTracker(ssd->cur_rtracker);
        if (ptracker == NULL)
        {
            // Otherwise find it with the passed in Fid
            ptracker = DCE2_SmbFindPipeTracker(ssd, ssd->cur_rtracker->uid,
                    ssd->cur_rtracker->tid, fid);
        }
    }

    return ptracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static DCE2_SmbPipeTracker * DCE2_SmbFindPipeTracker(DCE2_SmbSsnData *ssd,
        const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbPipeTracker *ptracker;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Finding pipe tracker with "
                "Uid: %u, Tid: %u, Fid: 0x%04X ... ", uid, tid, fid));

    if ((ssd->ptracker.fid != DCE2_SENTINEL) && (ssd->ptracker.fid == (int)fid))
    {
        ptracker = &ssd->ptracker;
    }
    else
    {
        ptracker = (DCE2_SmbPipeTracker *)
            DCE2_ListFind(ssd->ptrackers, (void *)(uintptr_t)fid);
    }

    if (ptracker == NULL)
    {
        DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not found.\n"));
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return NULL;
    }

    // Note IPC Tid has already been validated in initial processing
    switch (policy)
    {
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
            // Only Uid used to open pipe can be used to make a request
            if (ptracker->uid != uid)
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not found.\n"));
                PREPROC_PROFILE_END(dce2_pstat_smb_fid);
                return NULL;
            }

            break;

        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__SAMBA_3_0_20:
        case DCE2_POLICY__SAMBA_3_0_22:
            // Any valid Uid can be used to make a request to a named pipe ...
            // except for Windows 2000 on the first use.
            if ((policy != DCE2_POLICY__WIN2000) || ptracker->used)
            {
                // Check that the Uid exists
                if (DCE2_SmbFindUid(ssd, uid) != DCE2_RET__SUCCESS)
                {
                    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not found.\n"));
                    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
                    return NULL;
                }

                break;
            }

            // Fall through for Windows 2000 for first request to named pipe

        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            // Both Uid and Tid used to create named pipe must be used to make a request
            if ((ptracker->uid != uid) || (ptracker->tid != tid))
            {
                DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Not found.\n"));
                PREPROC_PROFILE_END(dce2_pstat_smb_fid);
                return NULL;
            }

            break;

        default:
            DCE2_Log(DCE2_LOG_TYPE__ERROR, "%s(%d) Invalid policy: %d",
                    __FILE__, __LINE__, policy);
            break;
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Found with "
                "Uid: %u, Tid: %u, Fid: 0x%04X\n",
                ptracker->uid, ptracker->tid, ptracker->fid));

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
    return ptracker;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbRemovePipeTracker(DCE2_SmbSsnData *ssd, DCE2_SmbPipeTracker *ptracker)
{
    DCE2_SmbRequestTracker *rtracker;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    if (ptracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return;
    }

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB,
                "Removing pipe tracker with Fid: 0x%04x\n", ptracker->fid));

    if (ptracker == &ssd->ptracker)
    {
        DCE2_SmbCleanPipeTracker(&ssd->ptracker);

        // NULL out pipe trackers of any outstanding requests
        // that reference this pipe tracker
        if (ssd->rtracker.ptracker == &ssd->ptracker)
            ssd->rtracker.ptracker = NULL;

        for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                rtracker != NULL;
                rtracker = DCE2_QueueNext(ssd->rtrackers))
        {
            if (rtracker->ptracker == &ssd->ptracker)
                rtracker->ptracker = NULL;
        }

    }
    else if (ssd->ptrackers != NULL)
    {
        DCE2_ListRemove(ssd->ptrackers, (void *)(uintptr_t)ptracker->fid);

        // NULL out pipe trackers of any outstanding requests
        // that reference this pipe tracker
        if (ssd->rtracker.ptracker == ptracker)
            ssd->rtracker.ptracker = NULL;

        for (rtracker = DCE2_QueueFirst(ssd->rtrackers);
                rtracker != NULL;
                rtracker = DCE2_QueueNext(ssd->rtrackers))
        {
            if (rtracker->ptracker == ptracker)
                rtracker->ptracker = NULL;
        }
    }

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline void DCE2_SmbCleanPipeTracker(DCE2_SmbPipeTracker *ptracker)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_fid);

    if (ptracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_fid);
        return;
    }

    ptracker->fid = DCE2_SENTINEL;
    ptracker->used = false;

    if (ptracker->writex_raw != NULL)
    {
        DCE2_BufferDestroy(ptracker->writex_raw->buf);
        DCE2_Free((void *)ptracker->writex_raw,
                sizeof(DCE2_SmbWriteAndXRaw), DCE2_MEM_TYPE__SMB_FID);
        ptracker->writex_raw = NULL;
    }

    DCE2_CoCleanTracker(&ptracker->co_tracker);

    PREPROC_PROFILE_END(dce2_pstat_smb_fid);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker *ttracker)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    if (ttracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return;
    }

    if (ttracker->dbuf != NULL)
        DCE2_BufferDestroy(ttracker->dbuf);

    if (ttracker->pbuf != NULL)
        DCE2_BufferDestroy(ttracker->pbuf);

    memset(ttracker, 0, sizeof(*ttracker));

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker *rtracker)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dce2_pstat_smb_req);

    if (rtracker == NULL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return;
    }

    if (rtracker->mid == DCE2_SENTINEL)
    {
        PREPROC_PROFILE_END(dce2_pstat_smb_req);
        return;
    }

    rtracker->mid = DCE2_SENTINEL;
    rtracker->ptracker = NULL;

    DCE2_SmbCleanTransactionTracker(&rtracker->ttracker);

    DCE2_QueueDestroy(rtracker->pt_queue);
    rtracker->pt_queue = NULL;

    PREPROC_PROFILE_END(dce2_pstat_smb_req);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static int DCE2_SmbUidTidFidCompare(const void *a, const void *b)
{
    int x = (int)(uintptr_t)a;
    int y = (int)(uintptr_t)b;

    if (x == y)
        return 0;

    /* Only care about equality for finding */
    return -1;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
void DCE2_SmbDataFree(DCE2_SmbSsnData *ssd)
{
    if (ssd == NULL)
        return;

    if (ssd->uids != NULL)
    {
        DCE2_ListDestroy(ssd->uids);
        ssd->uids = NULL;
    }

    if (ssd->tids != NULL)
    {
        DCE2_ListDestroy(ssd->tids);
        ssd->tids = NULL;
    }

    DCE2_SmbCleanPipeTracker(&ssd->ptracker);
    if (ssd->ptrackers != NULL)
    {
        DCE2_ListDestroy(ssd->ptrackers);
        ssd->ptrackers = NULL;
    }

    DCE2_SmbCleanRequestTracker(&ssd->rtracker);
    if (ssd->rtrackers != NULL)
    {
        DCE2_QueueDestroy(ssd->rtrackers);
        ssd->rtrackers = NULL;
    }

    if (ssd->cli_seg != NULL)
    {
        DCE2_BufferDestroy(ssd->cli_seg);
        ssd->cli_seg = NULL;
    }

    if (ssd->srv_seg != NULL)
    {
        DCE2_BufferDestroy(ssd->srv_seg);
        ssd->srv_seg = NULL;
    }
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
void DCE2_SmbSsnFree(void *ssn)
{
    DCE2_SmbSsnData *ssd = (DCE2_SmbSsnData *)ssn;

    if (ssd == NULL)
        return;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Removing Session: %p\n", ssd));

    DCE2_SmbDataFree(ssd);
    DCE2_Free((void *)ssn, sizeof(DCE2_SmbSsnData), DCE2_MEM_TYPE__SMB_SSN);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbPipeTrackerDataFree(void *data)
{
    DCE2_SmbPipeTracker *ptracker = (DCE2_SmbPipeTracker *)data;

    if (ptracker == NULL)
        return;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Freeing pipe tracker: "
                "Uid: %u, Tid: %u, Fid: 0x%04x\n",
                ptracker->uid, ptracker->tid, ptracker->fid));

    DCE2_SmbCleanPipeTracker(ptracker);
    DCE2_Free((void *)ptracker, sizeof(DCE2_SmbPipeTracker), DCE2_MEM_TYPE__SMB_FID);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static void DCE2_SmbRequestTrackerDataFree(void *data)
{
    DCE2_SmbRequestTracker *rtracker = (DCE2_SmbRequestTracker *)data;

    if (rtracker == NULL)
        return;

    DEBUG_WRAP(DCE2_DebugMsg(DCE2_DEBUG__SMB, "Freeing request tracker: "
                "Uid: %u, Tid: %u, Pid: %u, Mid: %u\n",
                rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid));

    DCE2_SmbCleanRequestTracker(rtracker);
    DCE2_Free((void *)rtracker, sizeof(DCE2_SmbRequestTracker), DCE2_MEM_TYPE__SMB_REQ);
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline SFSnortPacket * DCE2_SmbGetRpkt(DCE2_SmbSsnData *ssd,
        const uint8_t **data, uint32_t *data_len, DCE2_RpktType rtype)
{
    SFSnortPacket *rpkt;
    uint16_t header_len;

    if ((ssd == NULL) || (data == NULL) || (*data == NULL)
            || (data_len == NULL) || (*data_len == 0))
        return NULL;

    rpkt = DCE2_GetRpkt(ssd->sd.wire_pkt, rtype, *data, *data_len);

    if (rpkt == NULL)
    {
        DCE2_Log(DCE2_LOG_TYPE__ERROR,
                "%s(%d) Failed to create reassembly packet.",
                __FILE__, __LINE__);

        return NULL;
    }

    if (DCE2_PushPkt(rpkt) != DCE2_RET__SUCCESS)
    {
        DCE2_Log(DCE2_LOG_TYPE__ERROR,
                "%s(%d) Failed to push packet onto packet stack.",
                __FILE__, __LINE__);
        return NULL;
    }

    *data = rpkt->payload;
    *data_len = rpkt->payload_size;

    switch (rtype)
    {
        case DCE2_RPKT_TYPE__SMB_TRANS:
            if (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
                header_len = DCE2_MOCK_HDR_LEN__SMB_CLI;
            else
                header_len = DCE2_MOCK_HDR_LEN__SMB_SRV;
            DCE2_SmbSetRdata(ssd, (uint8_t *)rpkt->payload,
                    (uint16_t)(rpkt->payload_size - header_len));
            DCE2_MOVE(*data, *data_len, header_len);
            break;
        case DCE2_RPKT_TYPE__SMB_SEG:
        default:
            break;
    }

    return rpkt;
}

/********************************************************************
 * Function:
 *
 * Purpose:
 *
 * Arguments:
 *
 * Returns:
 *
 ********************************************************************/
static inline void DCE2_SmbReturnRpkt(void)
{
    DCE2_PopPkt();
}

