/*
 * VRT RULES
 *
 * Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This file is autogenerated via rules2c, by Brian Caswell <bmc@sourcefire.com>
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"


/* declare detection functions */
int rule3052eval(void *p);

/* declare rule data structures */
/* precompile the stuff that needs pre-compiled */
// content:"|00|", depth 1;
static ContentInfo rule3052content0 =
{
    (u_int8_t *)("|00|"), /* pattern (now in snort content format) */
    1, /* depth */
    0, /* offset */
    CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule3052option0 =
{
    OPTION_TYPE_CONTENT,
    { &rule3052content0 }
};
// content:"|FF|SMB|A0|", offset 3, depth 5, relative;
static ContentInfo rule3052content1 =
{
    (u_int8_t *)("|FF|SMB|A0|"), /* pattern (now in snort content format) */
    5, /* depth */
    3, /* offset */
    CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule3052option1 =
{
    OPTION_TYPE_CONTENT,
    { &rule3052content1 }
};
/* byte_test:size 1, value 128, operator &, offset 6, relative; */
static ByteData rule3052byte_test2 =
{
    1, /* size */
    CHECK_AND, /* operator */
    128, /* value */
    6, /* offset */
    0, /*multiplier */
    BYTE_BIG_ENDIAN|CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED|EXTRACT_AS_BYTE, /* flags */
    0, /* post offset */
    NULL, // offset_refId
    NULL, // value_refId
    NULL, // offset_location
    NULL  // value_location
};

static RuleOption rule3052option2 =
{
    OPTION_TYPE_BYTE_TEST,
    { &rule3052byte_test2 }
};
// pcre:"^.{27}", relative;
static PCREInfo rule3052pcre3 =
{
    "^.{27}", /* pattern */
    NULL,                               /* holder for compiled pattern */
    NULL,                               /* holder for compiled pattern flags */
    0,     /* compile flags */
    CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED,     /* content flags */
    0 /* offset */
};

static RuleOption rule3052option3 =
{
    OPTION_TYPE_PCRE,
    { &rule3052pcre3 }
};
// content:"|01 00|", offset 37, depth 2, relative;
static ContentInfo rule3052content4 =
{
    (u_int8_t *)("|01 00|"), /* pattern (now in snort content format) */
    2, /* depth */
    37, /* offset */
    CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule3052option4 =
{
    OPTION_TYPE_CONTENT,
    { &rule3052content4 }
};
/* byte_jump:size 4, offset -7, relative, endian little; */
static ByteData rule3052byte_jump5 =
{
4, /* size */
    0, /* operator, byte_jump doesn't use operator! */
    0, /* value, byte_jump doesn't use value! */
    -7, /* offset */
    0, /* multiplier */
    BYTE_LITTLE_ENDIAN|CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED|EXTRACT_AS_BYTE|JUMP_FROM_BEGINNING, /* flags */
    0, /* post offset */
    NULL, // offset_refId
    NULL, // value_refId
    NULL, // offset_location
    NULL  // value_location
};

static RuleOption rule3052option5 =
{
    OPTION_TYPE_BYTE_JUMP,
    { &rule3052byte_jump5 }
};
// pcre:"^.{4}", relative;
static PCREInfo rule3052pcre6 =
{
    "^.{4}", /* pattern */
    NULL,                               /* holder for compiled pattern */
    NULL,                               /* holder for compiled pattern flags */
    0,     /* compile flags */
    CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED,     /* content flags */
    0 /* offset */
};

static RuleOption rule3052option6 =
{
    OPTION_TYPE_PCRE,
    { &rule3052pcre6 }
};
// content:"|00 00 00 00|", offset 16, depth 4, relative;
static ContentInfo rule3052content7 =
{
    (u_int8_t *)("|00 00 00 00|"), /* pattern (now in snort content format) */
    4, /* depth */
    16, /* offset */
    NOT_FLAG|CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule3052option7 =
{
    OPTION_TYPE_CONTENT,
    { &rule3052content7 }
};
/* byte_jump:size 4, offset 16, relative, endian little; */
static ByteData rule3052byte_jump8 =
{
4, /* size */
    0, /* operator, byte_jump doesn't use operator! */
    0, /* value, byte_jump doesn't use value! */
    16, /* offset */
    0, /* multiplier */
    BYTE_LITTLE_ENDIAN|CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED|EXTRACT_AS_BYTE, /* flags */
    0, /* post offset */
    NULL, // offset_refId
    NULL, // value_refId
    NULL, // offset_location
    NULL  // value_location
};

static RuleOption rule3052option8 =
{
    OPTION_TYPE_BYTE_JUMP,
    { &rule3052byte_jump8 }
};
// content:"|00 00|", offset -10, depth 2, relative;
static ContentInfo rule3052content9 =
{
    (u_int8_t *)("|00 00|"), /* pattern (now in snort content format) */
    2, /* depth */
    -10, /* offset */
    CONTENT_RELATIVE|CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule3052option9 =
{
    OPTION_TYPE_CONTENT,
    { &rule3052content9 }
};

/* references for sid 3052 */
static RuleReference *rule3052refs[] =
{
    NULL
};
RuleOption *rule3052options[] =
{
    &rule3052option0,
    &rule3052option1,
    &rule3052option2,
    &rule3052option3,
    &rule3052option4,
    &rule3052option5,
    &rule3052option6,
    &rule3052option7,
    &rule3052option8,
    &rule3052option9,
    NULL
};

Rule rule3052 = {

   /* rule header, akin to => tcp any any -> any any               */{
       IPPROTO_TCP, /* proto */
       "$EXTERNAL_NET", /* SRCIP     */
       "any", /* SRCPORT   */
       1, /* DIRECTION */
       "$HOME_NET", /* DSTIP     */
       "139", /* DSTPORT   */
   },
   /* metadata */
   {
       3,  /* genid (HARDCODED!!!) */
       3052, /* sigid */
       2, /* revision */

       "protocol-command-decode", /* classification */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "!! Dynamic !! NETBIOS SMB NT Trans NT CREATE unicode invalid SACL ace size dos attempt",     /* message */
       rule3052refs, /* ptr to references */
       NULL /* Meta data */
   },
   rule3052options, /* ptr to rule options */
   NULL,  //&rule3052eval, /* use the built in detection function */
   0, /* am I initialized yet? */
   0,                                  /* Rule option count, used internally */
   0,                                  /* Flag with no alert, used internally */
   NULL /* ptr to internal data... setup during rule registration */
};


/* detection functions */
int rule3052eval(void *p) {
    //const u_int8_t *cursor_uri = 0;
    //const u_int8_t *cursor_raw = 0;
    const u_int8_t *cursor_normal = 0;


    // content:"|00|", depth 1;
    if (contentMatch(p, rule3052options[0]->option_u.content, &cursor_normal) > 0) {
        // content:"|FF|SMB|A0|", offset 3, depth 5, relative;
        if (contentMatch(p, rule3052options[1]->option_u.content, &cursor_normal) > 0) {
            // byte_test:size 1, value 128, operator &, offset 6, relative;
            if (byteTest(p, rule3052options[2]->option_u.byte, cursor_normal) > 0) {
                // pcre:"^.{27}", relative;
                if (pcreMatch(p, rule3052options[3]->option_u.pcre, &cursor_normal)) {
                    // content:"|01 00|", offset 37, depth 2, relative;
                    if (contentMatch(p, rule3052options[4]->option_u.content, &cursor_normal) > 0) {
                        // byte_jump:size 4, offset -7, relative, endian little;
                        if (byteJump(p, rule3052options[5]->option_u.byte, &cursor_normal) > 0) {
                            // pcre:"^.{4}", relative;
                            if (pcreMatch(p, rule3052options[6]->option_u.pcre, &cursor_normal)) {
                                // content:"|00 00 00 00|", offset 16, depth 4, relative;
                                if (!(contentMatch(p, rule3052options[7]->option_u.content, &cursor_normal) > 0)) {
                                    // byte_jump:size 4, offset 16, relative, endian little;
                                    if (byteJump(p, rule3052options[8]->option_u.byte, &cursor_normal) > 0) {
                                        // content:"|00 00|", offset -10, depth 2, relative;
                                        if (contentMatch(p, rule3052options[9]->option_u.content, &cursor_normal) > 0) {
                                            return RULE_MATCH;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return RULE_NOMATCH;
}

