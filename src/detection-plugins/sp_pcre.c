/* $Id$ */
/*
** Copyright (C) 2003 Brian Caswell <bmc@snort.org>
** Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2003-2013 Sourcefire, Inc.
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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "snort_bounds.h"
#include "rules.h"
#include "treenodes.h"
#include "snort_debug.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"
#include "mstring.h"
#include "sfhashfcn.h"

#ifdef WIN32
#define PCRE_DEFINITION
#endif

#include "sp_pcre.h"

#include <pcre.h>

#ifdef INTEL_HYPERSCAN
#include <hs.h>
#endif

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats pcrePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "sfhashfcn.h"
#include "detection_options.h"
#include "detection_util.h"

/*
 * we need to specify the vector length for our pcre_exec call.  we only care
 * about the first vector, which if the match is successful will include the
 * offset to the end of the full pattern match.  If we decide to store other
 * matches, make *SURE* that this is a multiple of 3 as pcre requires it.
 */
static int s_pcre_init = 1;

#ifdef INTEL_HYPERSCAN
static hs_scratch_t *pcreScratch = NULL;
static size_t total_pcre_count = 0;
static size_t total_pcre_size = 0;
static size_t total_hyperscan_size = 0;

/* Switch on for correctness testing by always running pcre_exec. */
#define INTEL_HYPERSCAN_CORRECTNESS_TEST 0

#endif

void SnortPcreInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void SnortPcreParse(struct _SnortConfig *, char *, PcreData *, OptTreeNode *);
void SnortPcreDump(PcreData *);
int SnortPcre(void *option_data, Packet *p);

void PcreFree(void *d)
{
    PcreData *data = (PcreData *)d;

#ifdef INTEL_HYPERSCAN
    hs_free_database(data->hs_db);
#endif

    free(data->expression);
    free(data->re);
    free(data->pe);
    free(data);
}

#ifdef INTEL_HYPERSCAN
static void HyperscanCleanup(int unused, void *data) {
    hs_free_scratch(pcreScratch);
    pcreScratch = NULL;
}

static void HyperscanStats(struct _SnortConfig *sc, int unused, void *data)
{
    LogMessage("+--[HyperScan PCRE acceleration]------------------------------\n");
    LogMessage("| Hyperscan version    : %s\n", hs_version());
    LogMessage("| Number of PCREs      : %zu\n", total_pcre_count);
    LogMessage("| Total PCRE size      : %zu bytes\n", total_pcre_size);
    LogMessage("| Total Hyperscan size : %zu bytes\n", total_hyperscan_size);
    LogMessage("+-------------------------------------------------------------\n");
}
#endif // INTEL_HYPERSCAN

uint32_t PcreHash(void *d)
{
    int i,j,k,l,expression_len;
    uint32_t a,b,c,tmp;
    PcreData *data = (PcreData *)d;

    expression_len = strlen(data->expression);
    a = b = c = 0;

    for (i=0,j=0;i<expression_len;i+=4)
    {
        tmp = 0;
        k = expression_len - i;
        if (k > 4)
            k=4;

        for (l=0;l<k;l++)
        {
            tmp |= *(data->expression + i + l) << l*8;
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
            j=0;
        }
    }

    if (j != 0)
    {
        mix(a,b,c);
    }

    a += RULE_OPTION_TYPE_PCRE;
    b += data->options;

    final(a,b,c);

    return c;
}

int PcreCompare(void *l, void *r)
{
    PcreData *left = (PcreData *)l;
    PcreData *right = (PcreData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (( strcmp(left->expression, right->expression) == 0) &&
        ( left->options == right->options))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}

void PcreDuplicatePcreData(void *src, PcreData *pcre_dup)
{
    PcreData *pcre_src = (PcreData *)src;

    pcre_dup->expression = pcre_src->expression;
    pcre_dup->options = pcre_src->options;
    pcre_dup->search_offset = 0;
    pcre_dup->pe = pcre_src->pe;
    pcre_dup->re = pcre_src->re;

#ifdef INTEL_HYPERSCAN
    pcre_dup->hs_db = pcre_src->hs_db;
    pcre_dup->hs_flags = pcre_src->hs_flags;
    pcre_dup->hs_noconfirm = pcre_src->hs_noconfirm;
#endif
}

int PcreAdjustRelativeOffsets(PcreData *pcre, uint32_t search_offset)
{
    if ((pcre->options & (SNORT_PCRE_INVERT | SNORT_PCRE_ANCHORED)))
    {
        return 0; /* Don't search again */
    }

    if (pcre->options & ( SNORT_PCRE_HTTP_BUFS ))
    {
        return 0;
    }

    /* What's coming in has the absolute offset */
    pcre->search_offset += search_offset;

    return 1; /* Continue searcing */
}

void SetupPcre(void)
{
    RegisterRuleOption("pcre", SnortPcreInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("pcre", &pcrePerfStats, 3, &ruleOTNEvalPerfStats, NULL);
#endif
#ifdef INTEL_HYPERSCAN
    // Clean up Hyperscan resources at the end.
    AddFuncToCleanExitList(HyperscanCleanup, NULL);
#endif
}

static void Ovector_Init(struct _SnortConfig *sc, int unused, void *data)
{
    /* Since SO rules are loaded 1 time at startup, regardless of
     * configuraton, we won't pcre capture count again, so save the max.  */
    static int s_ovector_max = 0;

    /* The pcre_fullinfo() function can be used to find out how many
     * capturing subpatterns there are in a compiled pattern. The
     * smallest size for ovector that will allow for n captured
     * substrings, in addition to the offsets of the substring matched
     * by the whole pattern, is (n+1)*3.  */
    sc->pcre_ovector_size += 1;
    sc->pcre_ovector_size *= 3;

    if (sc->pcre_ovector_size > s_ovector_max)
        s_ovector_max = sc->pcre_ovector_size;

    sc->pcre_ovector = (int *) SnortAlloc(s_ovector_max*sizeof(int));
}

#if SNORT_RELOAD
static void Ovector_Reload(struct _SnortConfig *sc, int unused, void *data)
{
    Ovector_Init(sc, unused, data);
}
#endif

void PcreCapture(struct _SnortConfig *sc, const void *code, const void *extra)
{
    int tmp_ovector_size = 0;

    pcre_fullinfo((const pcre *)code, (const pcre_extra *)extra,
        PCRE_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > sc->pcre_ovector_size)
        sc->pcre_ovector_size = tmp_ovector_size;

    if (s_pcre_init)
    {
        AddFuncToPostConfigList(sc, Ovector_Init, NULL);
#if SNORT_RELOAD
        AddFuncToReloadList(Ovector_Reload, NULL);
#endif
#ifdef INTEL_HYPERSCAN
        AddFuncToPostConfigList(sc, HyperscanStats, NULL);
#endif
        s_pcre_init = 0;
    }

}

#ifdef INTEL_HYPERSCAN
static void CalcPcreSize(const PcreData *pcre_data) {
    int rc;
    hs_error_t err;

    size_t pcre_size = 0, pcre_studysize = 0, hs_size = 0;
    rc =
        pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_SIZE, &pcre_size);
    if (rc) {
        FatalError("pcre_fullinfo returned error %d\n", rc);
        return;
    }
    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_STUDYSIZE,
                       &pcre_studysize);
    if (rc) {
        FatalError("pcre_fullinfo returned error %d\n", rc);
        return;
    }

    if (pcre_data->hs_db != NULL) {
        err = hs_database_size(pcre_data->hs_db, &hs_size);
        if (err != HS_SUCCESS) {
            FatalError("hs_database_size returned error %d\n", err);
            return;
        }
    }

    total_pcre_count++;
    total_pcre_size += pcre_size + pcre_studysize;
    total_hyperscan_size += hs_size;
}
#endif // INTEL_HYPERSCAN

void SnortPcreInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    PcreData *pcre_data;
    OptFpList *fpl;
    void *pcre_dup;

    /*
     * allocate the data structure for pcre
     */
    pcre_data = (PcreData *) SnortAlloc(sizeof(PcreData));

    SnortPcreParse(sc, data, pcre_data, otn);

    otn->pcre_flag = 1;

    fpl = AddOptFuncToList(SnortPcre, otn);
    fpl->type = RULE_OPTION_TYPE_PCRE;

    if (add_detection_option(sc, RULE_OPTION_TYPE_PCRE, (void *)pcre_data, &pcre_dup) == DETECTION_OPTION_EQUAL)
    {
#ifdef DEBUG_RULE_OPTION_TREE
        LogMessage("Duplicate PCRE:\n%d %s\n%d %s\n\n",
            pcre_data->options, pcre_data->expression,
            ((PcreData *)pcre_dup)->options,
            ((PcreData *)pcre_dup)->expression);
#endif

        if (pcre_data->expression)
            free(pcre_data->expression);
        if (pcre_data->pe)
            free(pcre_data->pe);
        if (pcre_data->re)
            free(pcre_data->re);
#ifdef INTEL_HYPERSCAN
        if (pcre_data->hs_db)
            hs_free_database(pcre_data->hs_db);
#endif

        free(pcre_data);
        pcre_data = pcre_dup;
    }

#ifdef INTEL_HYPERSCAN
    CalcPcreSize(pcre_data);
#endif

    /*
     * attach it to the context node so that we can call each instance
     * individually
     */
    fpl->context = (void *) pcre_data;

    if (pcre_data->options & SNORT_PCRE_RELATIVE)
        fpl->isRelative = 1;

    if (otn->ds_list[PLUGIN_PCRE] == NULL)
        otn->ds_list[PLUGIN_PCRE] = (void *)pcre_data;

    return;
}

static inline void ValidatePcreHttpContentModifiers(PcreData *pcre_data)
{
    if( pcre_data->options & SNORT_PCRE_RELATIVE )
        FatalError("%s(%d): PCRE unsupported configuration : both relative & uri options specified\n",
                file_name, file_line);

    if( pcre_data->options & SNORT_PCRE_RAWBYTES )
        FatalError("%s(%d): PCRE unsupported configuration : both rawbytes & uri options specified\n",
                file_name, file_line);
}

#ifdef INTEL_HYPERSCAN

static int hyperscan_fixed_width(const char *re, unsigned int hs_flags) {
    hs_expr_info_t *info = NULL;
    hs_compile_error_t *compile_error = NULL;

    hs_error_t err = hs_expression_info(re, hs_flags, &info, &compile_error);
    if (err != HS_SUCCESS) {
        hs_free_compile_error(compile_error);
        return 0;
    }

    if (!info) {
        return 0;
    }

    int fixed_width = (info->min_width == info->max_width &&
            info->max_width != 0xffffffff);
    free(info);
    return fixed_width;
}

static void HyperscanBuild(PcreData *pcre_data, const char *re,
                           int pcre_compile_flags) {
    if (pcre_data == NULL || pcre_data->re == NULL || pcre_data->pe == NULL ||
        re == NULL) {
        return;
    }

    /* Note that we also allow PCRE_UNGREEDY even though there is no Hyperscan
     * flag for it. Greedy/ungreedy semantics make no difference for the
     * prefilter use case, where the match offset reported by Hyperscan is not
     * used. */

    const int supported_pcre_flags =
        PCRE_CASELESS | PCRE_DOTALL | PCRE_MULTILINE | PCRE_UNGREEDY;
    if (pcre_compile_flags & ~supported_pcre_flags) {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "fail, pcre '%s' unsupported flags=%d\n",
                                pcre_data->expression,
                                pcre_compile_flags & ~supported_pcre_flags));
        return;
    }

    int hs_flags = HS_FLAG_ALLOWEMPTY;
    if (pcre_compile_flags & PCRE_CASELESS)
        hs_flags |= HS_FLAG_CASELESS;
    if (pcre_compile_flags & PCRE_DOTALL)
        hs_flags |= HS_FLAG_DOTALL;
    if (pcre_compile_flags & PCRE_MULTILINE)
        hs_flags |= HS_FLAG_MULTILINE;

    hs_error_t err;
    hs_compile_error_t *compile_error = NULL;

    /* First, we attempt to compile the pattern with full Hyperscan support. */
    err = hs_compile(re, hs_flags, HS_MODE_BLOCK, NULL, &pcre_data->hs_db,
                     &compile_error);
    if (err != HS_SUCCESS) {
        pcre_data->hs_db = NULL; // safety
        if (compile_error) {
            hs_free_compile_error(compile_error);
        }
    }

    /* If the first attempt failed, we use Hyperscan's prefiltering support to
     * attempt to build a simplified version of the pattern. */
    if (!pcre_data->hs_db) {
        hs_flags |= HS_FLAG_PREFILTER;
        err = hs_compile(re, hs_flags, HS_MODE_BLOCK, NULL, &pcre_data->hs_db,
                         &compile_error);
        if (err != HS_SUCCESS) {
            pcre_data->hs_db = NULL; // safety
            if (compile_error) {
                hs_free_compile_error(compile_error);
            }
        }
    }

    if (!pcre_data->hs_db) {
        LogMessage("Hyperscan could not prefilter PCRE: %s\n", pcre_data->expression);
        return;
    }

    pcre_data->hs_flags = hs_flags;

    // Ensure that the scratch region can handle this database.
    err = hs_alloc_scratch(pcre_data->hs_db, &pcreScratch);
    if (err != HS_SUCCESS) {
        FatalError("hs_alloc_scratch() failed: returned error %d\n", err);
    }

    if (!(hs_flags & HS_FLAG_PREFILTER) && hyperscan_fixed_width(re, hs_flags)) {
        pcre_data->hs_noconfirm = 1;
    }
}

#endif // INTEL_HYPERSCAN

void SnortPcreParse(struct _SnortConfig *sc, char *data, PcreData *pcre_data, OptTreeNode *otn)
{
    const char *error;
    char *re, *free_me;
    char *opts;
    char delimit = '/';
    int erroffset;
    int compile_flags = 0;
    unsigned http = 0;

    if(data == NULL)
    {
        FatalError("%s (%d): pcre requires a regular expression\n",
                   file_name, file_line);
    }

    free_me = SnortStrdup(data);
    re = free_me;

    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1])) re[strlen(re)-1] = '\0';
    while (isspace((int)*re)) re++;

    if(*re == '!') {
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while(isspace((int)*re)) re++;
    }

    /* now we wrap the RE in double quotes.  stupid snort parser.... */
    if(*re != '"') {
        printf("It isn't \"\n");
        goto syntax;
    }
    re++;

    if(re[strlen(re)-1] != '"')
    {
        printf("It isn't \"\n");
        goto syntax;
    }

    /* remove the last quote from the string */
    re[strlen(re) - 1] = '\0';

    /* 'm//' or just '//' */

    if(*re == 'm')
    {
        re++;
        if(! *re) goto syntax;

        /* Space as a ending delimiter?  Uh, no. */
        if(isspace((int)*re)) goto syntax;
        /* using R would be bad, as it triggers RE */
        if(*re == 'R') goto syntax;

        delimit = *re;
    }
    else if(*re != delimit)
        goto syntax;

    pcre_data->expression = SnortStrdup(re);

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if (opts == NULL)
        goto syntax;

    if(!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while(*opts != '\0') {
        switch(*opts) {
        case 'i':  compile_flags |= PCRE_CASELESS;            break;
        case 's':  compile_flags |= PCRE_DOTALL;              break;
        case 'm':  compile_flags |= PCRE_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE_EXTENDED;            break;

            /*
             * these are pcre specific... don't work with perl
             */
        case 'A':  compile_flags |= PCRE_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE_UNGREEDY;            break;

            /*
             * these are snort specific don't work with pcre or perl
             */
        case 'R':  pcre_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'B':  pcre_data->options |= SNORT_PCRE_RAWBYTES; break;
        case 'O':  pcre_data->options |= SNORT_OVERRIDE_MATCH_LIMIT; break;
        case 'U':  pcre_data->options |= SNORT_PCRE_HTTP_URI; http++; break;
        case 'P':  pcre_data->options |= SNORT_PCRE_HTTP_BODY;  http++; break;
        case 'H':  pcre_data->options |= SNORT_PCRE_HTTP_HEADER;  http++; break;
        case 'M':  pcre_data->options |= SNORT_PCRE_HTTP_METHOD;  http++; break;
        case 'C':  pcre_data->options |= SNORT_PCRE_HTTP_COOKIE;  http++; break;
        case 'I':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_URI; http++; break;
        case 'D':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_HEADER; http++; break;
        case 'K':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_COOKIE; http++; break;
        case 'S':  pcre_data->options |= SNORT_PCRE_HTTP_STAT_CODE; http++; break;
        case 'Y':  pcre_data->options |= SNORT_PCRE_HTTP_STAT_MSG; http++; break;

        default:
            FatalError("%s (%d): unknown/extra pcre option encountered\n", file_name, file_line);
        }
        opts++;
    }

    if ( http > 1 )
        ParseWarning("at most one HTTP buffer may be indicated with pcre");

    if(pcre_data->options & (SNORT_PCRE_HTTP_BUFS))
        ValidatePcreHttpContentModifiers(pcre_data);

    /* now compile the re */
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre: compiling %s\n", re););
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, NULL);

    if(pcre_data->re == NULL)
    {
        FatalError("%s(%d) : pcre compile of \"%s\" failed at offset "
                   "%d : %s\n", file_name, file_line, re, erroffset, error);
    }


    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, 0, &error);

    if (pcre_data->pe)
    {
        if ((ScPcreMatchLimit() != -1) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT)
            {
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }
        }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
        if ((ScPcreMatchLimitRecursion() != -1) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION)
            {
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
        }
#endif
    }
    else
    {
        if (!(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
             ((ScPcreMatchLimit() != -1) || (ScPcreMatchLimitRecursion() != -1)))
        {
            pcre_data->pe = (pcre_extra *)SnortAlloc(sizeof(pcre_extra));
            if (ScPcreMatchLimit() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
            if (ScPcreMatchLimitRecursion() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
#endif
        }
    }

    if(error != NULL)
    {
        FatalError("%s(%d) : pcre study failed : %s\n", file_name,
                   file_line, error);
    }

    PcreCapture(sc, pcre_data->re, pcre_data->pe);

    PcreCheckAnchored(pcre_data);

#ifdef INTEL_HYPERSCAN
    HyperscanBuild(pcre_data, re, compile_flags);
#endif

    free(free_me);

    return;

 syntax:
    free(free_me);

    FatalError("%s Line %d => unable to parse pcre regex %s\n",
               file_name, file_line, data);

}

void PcreCheckAnchored(PcreData *pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == NULL) || (pcre_data->re == NULL) || (pcre_data->pe == NULL))
        return;

    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_OPTIONS, (void *)&options);
    switch (rc)
    {
        /* pcre_fullinfo fails for the following:
         * PCRE_ERROR_NULL - the argument code was NULL
         *                   the argument where was NULL
         * PCRE_ERROR_BADMAGIC - the "magic number" was not found
         * PCRE_ERROR_BADOPTION - the value of what was invalid
         * so a failure here means we passed in bad values and we should
         * probably fatal error */

        case 0:
            /* This is the success code */
            break;

        case PCRE_ERROR_NULL:
            FatalError("%s(%d) pcre_fullinfo: code and/or where were NULL.\n",
                       __FILE__, __LINE__);

        case PCRE_ERROR_BADMAGIC:
            FatalError("%s(%d) pcre_fullinfo: compiled code didn't have "
                       "correct magic.\n", __FILE__, __LINE__);

        case PCRE_ERROR_BADOPTION:
            FatalError("%s(%d) pcre_fullinfo: option type is invalid.\n",
                       __FILE__, __LINE__);

        default:
            FatalError("%s(%d) pcre_fullinfo: Unknown error code.\n",
                       __FILE__, __LINE__);
    }

    if ((options & PCRE_ANCHORED) && !(options & PCRE_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be reevaluted
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre_data->options |= SNORT_PCRE_ANCHORED;
    }
}

#ifdef INTEL_HYPERSCAN

struct hs_context {
    int matched;
    int *found_offset;
};

static int hyperscan_callback(unsigned int id, unsigned long long from,
                              unsigned long long to, unsigned int flags,
                              void *ctx) {
    struct hs_context *hsctx = ctx;

    hsctx->matched = 1;
    *(hsctx->found_offset) = (int)to; // safe, as buffer has int len

    return 1; // halt matching
}

// Return 1 when we find the pattern, 0 when we don't.
static int hyperscan_search(const PcreData *pcre_data, const char *buf, int len,
                            int start_offset, int *found_offset) {
    struct hs_context hsctx;
    hsctx.matched = 0;
    hsctx.found_offset = found_offset;

    // XXX: we currently ignore start_offset, which might be used to reduce the
    // size of the buffer being scanned. Need to be careful with anchors,
    // assertions etc.

    hs_error_t err = hs_scan(pcre_data->hs_db, buf, len, 0, pcreScratch,
                             hyperscan_callback, &hsctx);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        // An error occurred, fall through to pcre
        LogMessage("hs_scan returned error %d\n", err);
        return 0;
    }

    if (hsctx.matched == 0) {
        // No matches, no need to run pcre.

#if INTEL_HYPERSCAN_CORRECTNESS_TEST
        // For correctness testing, run PCRE as well and ensure that it
        // produces the same result.
        int result =
            pcre_exec(pcre_data->re, pcre_data->pe, buf, len, start_offset, 0,
                      snort_conf->pcre_ovector, snort_conf->pcre_ovector_size);
        if (result >= 0) {
            LogMessage("err=%d, result=%d\n", err, result);
            FatalError("Hyperscan said pattern wouldn't match, pcre says "
                       "otherwise. Pattern is %s and options are %x\n",
                       pcre_data->expression, pcre_data->options);
        }
#endif

        return 0;
    }

    return 1;
}

#endif // INTEL_HYPERSCAN

/**
 * Perform a search of the PCRE data.
 *
 * @param pcre_data structure that options and patterns are passed in
 * @param buf buffer to search
 * @param len size of buffer
 * @param start_offset initial offset into the buffer
 * @param no_offset_required if a match is found, the caller doesn't need its offset
 * @param found_offset pointer to an integer so that we know where the search ended
 *
 * *found_offset will be set to -1 when the find is unsucessful OR the routine is inverted
 *
 * @return 1 when we find the string, 0 when we don't (unless we've been passed a flag to invert)
 */
static int pcre_search(const PcreData *pcre_data,
                       const char *buf,
                       int len,
                       int start_offset,
                       int no_offset_required,
                       int *found_offset)
{
    int matched;
    int result;

    if(pcre_data == NULL
       || buf == NULL
       || len <= 0
       || start_offset < 0
       || start_offset >= len
       || found_offset == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Returning 0 because we didn't have the required parameters!\n"););
        return 0;
    }

    *found_offset = -1;

#ifdef INTEL_HYPERSCAN
    // Prefilter with Hyperscan if available; if Hyperscan says the buffer
    // cannot match this PCRE, we can fall out here.
    if (pcre_data->hs_db) {
        int hs_match = hyperscan_search(pcre_data, buf, len, start_offset, found_offset);
        int is_prefiltering = pcre_data->hs_flags & HS_FLAG_PREFILTER;

        // If the pattern is inverted and we're not prefiltering AND
        // start_offset was zero, we don't have to do confirm in PCRE.
        if (pcre_data->options & SNORT_PCRE_INVERT) {
            if (start_offset == 0 && !is_prefiltering) {
                return !hs_match;
            } else if (!hs_match) {
                // Hyperscan didn't match, so pcre_exec will not match, so
                // return that the INVERTED pcre did match.
                return 1;
            } else {
                // Hyperscan did match, we need to confirm with pcre as we're
                // prefiltering.
                goto pcre_confirm;
            }
        }

        // Note: we must do confirm in PCRE if a start_offset was specified.
        if (start_offset == 0) {
            if (pcre_data->hs_noconfirm || (!is_prefiltering && no_offset_required)) {
                return hs_match; // No confirm necessary.
            }
        }

        if (!hs_match) {
            // No match in Hyperscan, so no PCRE match can occur.
            return 0;
        }

        // Otherwise, Hyperscan claims there might be a match. Fall through to
        // post-confirm with PCRE.
    }

pcre_confirm:

#endif // INTEL_HYPERSCAN

    result = pcre_exec(pcre_data->re,  /* result of pcre_compile() */
                       pcre_data->pe,  /* result of pcre_study()   */
                       buf,            /* the subject string */
                       len,            /* the length of the subject string */
                       start_offset,   /* start at offset 0 in the subject */
                       0,              /* options(handled at compile time */
                       snort_conf->pcre_ovector,      /* vector for substring information */
                       snort_conf->pcre_ovector_size);/* number of elements in the vector */

    if(result >= 0)
    {
        matched = 1;
        /* From the PCRE man page:
         * When a match is successful, information about captured substrings is returned in pairs of integers,
         * starting at the beginning of ovector, and continuing up to two-thirds of its length at the most.
         * The first element of a pair is set to the offset of the first character in a substring, and the
         * second is set to the offset of the first character after the end of a substring. The first pair,
         * ovector[0] and ovector[1], identify the portion of the subject string matched by the entire pattern.
         * The next pair is used for the first capturing subpattern, and so on. The value returned by
         * pcre_exec() is the number of pairs that have been set. If there are no capturing subpatterns, the
         * return value from a successful match is 1, indicating that just the first pair of offsets has been set.
         *
         * In Snort's case, the ovector size only allows for the first pair and a single int for scratch space.
         */
        *found_offset = snort_conf->pcre_ovector[1];
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Setting Doe_ptr and found_offset: %p %d\n",
                                doe_ptr, found_offset););
    }
    else if(result == PCRE_ERROR_NOMATCH)
    {
        matched = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre_exec error : %d \n", result););
        return 0;
    }

    /* invert sense of match */
    if(pcre_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    return matched;
}

int SnortPcre(void *option_data, Packet *p)
{
    PcreData *pcre_data = (PcreData *)option_data;
    int found_offset = -1;  /* where is the ending location of the pattern */
    const uint8_t *base_ptr, *end_ptr, *start_ptr;
    int dsize;
    int length; /* length of the buffer pointed to by base_ptr  */
    int matched = 0;
    uint8_t rst_doe_flags = 1;
    unsigned hb_type;
    DEBUG_WRAP(char *hexbuf;)

    PROFILE_VARS;
    PREPROC_PROFILE_START(pcrePerfStats);

    //short circuit this for testing pcre performance impact
    if (ScNoPcre())
    {
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    /* This is the HTTP case */
    if ( (hb_type = pcre_data->options & SNORT_PCRE_HTTP_BUFS) )
    {
        const HttpBuffer* hb = GetHttpBuffer(hb_type);

        if ( hb )
        {
            matched = pcre_search(
                pcre_data, (const char*)hb->buf, hb->length, 0, 1, &found_offset);

            if ( matched )
            {
                /* don't touch doe_ptr on URI contents */
                PREPROC_PROFILE_END(pcrePerfStats);
                return DETECTION_OPTION_MATCH;
            }
        }
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }
    /* end of the HTTP case */

    if( !(pcre_data->options & SNORT_PCRE_RAWBYTES))
    {
        if(Is_DetectFlag(FLAG_ALT_DETECT))
        {
            dsize = DetectBuffer.len;
            start_ptr = DetectBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "using alternative detect buffer in pcre!\n"););
        }
        else if(Is_DetectFlag(FLAG_ALT_DECODE))
        {
            dsize = DecodeBuffer.len;
            start_ptr = DecodeBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "using alternative decode buffer in pcre!\n"););
        }
        else
        {
            if(IsLimitedDetect(p))
                dsize = p->alt_dsize;
            else
                dsize = p->dsize;
            start_ptr = p->data;
        }
    }
    else
    {
        dsize = p->dsize;
        start_ptr = p->data;
    }

    base_ptr = start_ptr;
    end_ptr = start_ptr + dsize;

    /* doe_ptr's would be set by the previous content option */
    if(pcre_data->options & SNORT_PCRE_RELATIVE && doe_ptr)
    {
        if(!inBounds(start_ptr, end_ptr, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "pcre bounds check failed on a relative content match\n"););
            PREPROC_PROFILE_END(pcrePerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking relative offset\n"););
        base_ptr = doe_ptr;
        rst_doe_flags = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking absolute offset\n"););
        base_ptr = start_ptr;
    }

    length = end_ptr - base_ptr;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "pcre ... base: %p start: %p end: %p doe: %p length: %d\n",
                            base_ptr, start_ptr, end_ptr, doe_ptr, length););

    DEBUG_WRAP(hexbuf = hex(base_ptr, length);
               DebugMessage(DEBUG_PATTERN_MATCH, "pcre payload: %s\n", hexbuf);
               free(hexbuf);
               );

    matched = pcre_search(pcre_data, (const char *)base_ptr, length, pcre_data->search_offset, 0, &found_offset);

    /* set the doe_ptr if we have a valid offset */
    if(found_offset > 0)
    {
        UpdateDoePtr(((uint8_t *) base_ptr + found_offset), rst_doe_flags);
    }

    if (matched)
    {
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_MATCH;
    }

    /* finally return 0 */
    PREPROC_PROFILE_END(pcrePerfStats);
    return DETECTION_OPTION_NO_MATCH;
}
