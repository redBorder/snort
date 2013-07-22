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

#ifndef _DCE2_SMB_H_
#define _DCE2_SMB_H_

#include "dce2_session.h"
#include "dce2_tcp.h"
#include "dce2_list.h"
#include "dce2_utils.h"
#include "smb.h"
#include "sf_snort_packet.h"
#include "sf_types.h"
#include "snort_debug.h"

/********************************************************************
 * Macros
 ********************************************************************/
// Used for reassembled packets
#define DCE2_MOCK_HDR_LEN__SMB_CLI \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq))
#define DCE2_MOCK_HDR_LEN__SMB_SRV \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp))

// This is for ease of comparison so a 32 bit numeric compare can be done
// instead of a string compare.
#define DCE2_SMB_ID   0xff534d42  /* \xffSMB */
#define DCE2_SMB2_ID  0xfe534d42  /* \xfeSMB */

/********************************************************************
 * Externs
 ********************************************************************/
extern SmbAndXCom smb_chain_map[SMB_MAX_NUM_COMS];
extern const char *smb_com_strings[SMB_MAX_NUM_COMS];
extern const char *smb_transaction_sub_command_strings[TRANS_SUBCOM_MAX];
extern const char *smb_transaction2_sub_command_strings[TRANS2_SUBCOM_MAX];
extern const char *smb_nt_transact_sub_command_strings[NT_TRANSACT_SUBCOM_MAX];

/********************************************************************
 * Enums
 ********************************************************************/
typedef enum _DCE2_SmbSsnState
{
    DCE2_SMB_SSN_STATE__START         = 0x00,
    DCE2_SMB_SSN_STATE__NEGOTIATED    = 0x01,
    DCE2_SMB_SSN_STATE__FP_CLIENT     = 0x02,
    DCE2_SMB_SSN_STATE__FP_SERVER     = 0x04 

} DCE2_SmbSsnState;

typedef enum _DCE2_SmbDataState
{
    DCE2_SMB_DATA_STATE__NETBIOS_HEADER,
    DCE2_SMB_DATA_STATE__SMB_HEADER,
    DCE2_SMB_DATA_STATE__NETBIOS_PDU

} DCE2_SmbDataState;

typedef enum _DCE2_SmbPduState
{
    DCE2_SMB_PDU_STATE__COMMAND,
    DCE2_SMB_PDU_STATE__RAW_DATA

} DCE2_SmbPduState;

/********************************************************************
 * Structures
 ********************************************************************/
typedef struct _DCE2_SmbWriteAndXRaw
{
    int remaining;  // An unsigned integer so it can be negative
    DCE2_Buffer *buf;

} DCE2_SmbWriteAndXRaw;

typedef struct _DCE2_SmbPipeTracker
{
    int fid;   // An unsigned integer so it can be set to sentinel
    uint16_t uid;
    uint16_t tid;

    // If pipe has been set to byte mode via TRANS_SET_NMPIPE_STATE
    bool byte_mode;

    bool used;   // For Windows 2000

    // For WriteAndX requests that use raw mode flag
    // Windows only
    DCE2_SmbWriteAndXRaw *writex_raw;

    // Connection-oriented DCE/RPC tracker
    DCE2_CoTracker co_tracker;

} DCE2_SmbPipeTracker;

typedef struct _DCE2_SmbTransactionTracker
{
    int smb_type;
    uint8_t subcom;
    bool one_way;
    bool disconnect_tid;
    bool pipe_byte_mode;
    uint32_t tdcnt;
    uint32_t dsent;
    DCE2_Buffer *dbuf;
    uint32_t tpcnt;
    uint32_t psent;
    DCE2_Buffer *pbuf;

} DCE2_SmbTransactionTracker;

typedef struct _DCE2_SmbRequestTracker
{
    int smb_com;

    int mid;   // An unsigned integer so it can be set to sentinel
    uint16_t uid;
    uint16_t tid;
    uint16_t pid;

    // For WriteRaw
    bool writeraw_writethrough;
    uint32_t writeraw_remaining;

    // For Transaction/Transaction2/NtTransact
    DCE2_SmbTransactionTracker ttracker;

    // Client can chain a write to an open.  Need to write data, but also
    // need to associate tracker with fid returned from server
    DCE2_Queue *pt_queue;

    // This is a reference to an existing pipe tracker
    DCE2_SmbPipeTracker *ptracker;

} DCE2_SmbRequestTracker;

typedef struct _DCE2_SmbSsnData
{
    DCE2_SsnData sd;  // This member must be first

    DCE2_Policy policy;

    int dialect_index;
    int ssn_state_flags;

    DCE2_SmbDataState cli_data_state;
    DCE2_SmbDataState srv_data_state;

    DCE2_SmbPduState pdu_state;

    // UIDs and IPC TIDs created on session
    // IPC tids created on session
    int uid;   // An unsigned integer so it can be set to sentinel
    int tid;   // An unsigned integer so it can be set to sentinel
    DCE2_List *uids;
    DCE2_List *tids;

    // Specific for Samba and Windows 2000
    DCE2_SmbPipeTracker ptracker;
    DCE2_List *ptrackers;  // List of DCE2_SmbPipeTracker

    // For tracking requests / responses
    DCE2_SmbRequestTracker rtracker;
    DCE2_Queue *rtrackers;
    uint16_t max_outstanding_requests;
    uint16_t outstanding_requests;

    // The current pid/mid node for this request/response
    DCE2_SmbRequestTracker *cur_rtracker;

    // Used for TCP segmentation to get full PDU
    DCE2_Buffer *cli_seg;
    DCE2_Buffer *srv_seg;

    // These are used when for commands we don't need to process
    uint32_t cli_ignore_bytes;
    uint32_t srv_ignore_bytes;

} DCE2_SmbSsnData;

/********************************************************************
 * Inline function prototypes
 ********************************************************************/
static inline DCE2_TransType DCE2_SmbAutodetect(const SFSnortPacket *);
static inline void DCE2_SmbSetFingerprintedClient(DCE2_SmbSsnData *);
static inline bool DCE2_SmbFingerprintedClient(DCE2_SmbSsnData *);
static inline void DCE2_SmbSetFingerprintedServer(DCE2_SmbSsnData *);
static inline bool DCE2_SmbFingerprintedServer(DCE2_SmbSsnData *);

/********************************************************************
 * Public function prototypes
 ********************************************************************/
void DCE2_SmbInitGlobals(void);
void DCE2_SmbInitRdata(uint8_t *, int);
void DCE2_SmbSetRdata(DCE2_SmbSsnData *, uint8_t *, uint16_t);
DCE2_SmbSsnData * DCE2_SmbSsnInit(SFSnortPacket *);
void DCE2_SmbProcess(DCE2_SmbSsnData *);
void DCE2_SmbDataFree(DCE2_SmbSsnData *);
void DCE2_SmbSsnFree(void *);

/*********************************************************************
 * Function: DCE2_SmbAutodetect()
 *
 * Purpose: Tries to determine if a packet is likely to be SMB.
 *
 * Arguments:
 *  const uint8_t * - pointer to packet data.
 *  uint16_t - packet data length.
 *
 * Returns:
 *  DCE2_TranType
 *
 *********************************************************************/
static inline DCE2_TransType DCE2_SmbAutodetect(const SFSnortPacket *p)
{
    if (p->payload_size > (sizeof(NbssHdr) + sizeof(SmbNtHdr)))
    {
        NbssHdr *nb_hdr = (NbssHdr *)p->payload;

        switch (NbssType(nb_hdr))
        {
            case NBSS_SESSION_TYPE__MESSAGE:
                {
                    SmbNtHdr *smb_hdr = (SmbNtHdr *)(p->payload + sizeof(NbssHdr));

                    if ((SmbId(smb_hdr) == DCE2_SMB_ID)
                            || (SmbId(smb_hdr) == DCE2_SMB2_ID))
                    {
                        return DCE2_TRANS_TYPE__SMB;
                    }
                }

                break;

            default:
                break;

        }
    }

    return DCE2_TRANS_TYPE__NONE;
}

static inline void DCE2_SmbSetFingerprintedClient(DCE2_SmbSsnData *ssd)
{
    ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__FP_CLIENT;
}

static inline bool DCE2_SmbFingerprintedClient(DCE2_SmbSsnData *ssd)
{
    return ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__FP_CLIENT;
}

static inline void DCE2_SmbSetFingerprintedServer(DCE2_SmbSsnData *ssd)
{
    ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__FP_SERVER;
}

static inline bool DCE2_SmbFingerprintedServer(DCE2_SmbSsnData *ssd)
{
    return ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__FP_SERVER;
}

#endif  /* _DCE2_SMB_H_ */

