/*
** Copyright (c) 2015-2016, Intel Corporation.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hyperscan.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"

#define INITIAL_PATTERN_ARRAY_ALLOC_SIZE 10

// Summary information; this is global and static for now.
typedef struct _HyperscanSummary {
    unsigned int db_count; // number of databases
    size_t db_bytes;       // total bytes compiled
    size_t scratch_size;   // size of scratch space
} HyperscanSummary;

static HyperscanSummary summary;

HyperscanPm *HyperscanNew(void (*user_free)(void *p),
                          void (*option_tree_free)(void **p),
                          void (*neg_list_free)(void **p)) {
    HyperscanPm *pm = SnortAlloc(sizeof(HyperscanPm));
    pm->user_free = user_free;
    pm->option_tree_free = option_tree_free;
    pm->neg_list_free = neg_list_free;

    pm->patterns_capacity = INITIAL_PATTERN_ARRAY_ALLOC_SIZE;
    pm->patterns = SnortAlloc(sizeof(HyperscanPattern) * pm->patterns_capacity);

    return pm;
}

void HyperscanFree(HyperscanPm *pm) {
    if (!pm) {
        return;
    }

    unsigned int i = 0;
    for (; i < pm->patterns_len; i++) {
        HyperscanPattern *hp = &pm->patterns[i];
        free(hp->pattern);
        if (pm->user_free && hp->user_data) {
            pm->user_free(hp->user_data);
        }
        if (pm->neg_list_free && hp->neg_list) {
            pm->neg_list_free(&hp->neg_list);
        }
        if (pm->option_tree_free && hp->rule_option_tree) {
            pm->option_tree_free(&hp->rule_option_tree);
        }
    }

    hs_free_database(pm->db);
    free(pm->patterns);
    free(pm);
}

HyperscanContext *HyperscanNewContext() {
    HyperscanContext *ctx = SnortAlloc(sizeof(HyperscanContext));
    ctx->scratch = NULL;
    return ctx;
}

void HyperscanFreeContext(HyperscanContext *ctx) {
    if (!ctx) {
        return;
    }
    hs_free_scratch(ctx->scratch);
    free(ctx);
}

// Render the given literal as a hex-escaped pattern.
static
char *makeHex(const unsigned char *pat, unsigned patlen) {
    size_t hexlen = patlen * 4;
    char *hexbuf = SnortAlloc(hexlen + 1);
    unsigned i;
    char *buf;
    for (i = 0, buf = hexbuf; i < patlen; i++, buf += 4) {
        snprintf(buf, 5, "\\x%02x", (unsigned char)pat[i]);
    }
    hexbuf[hexlen] = '\0';
    return hexbuf;
}

int HyperscanAddPattern(struct _SnortConfig *sc, HyperscanPm *pm,
                        unsigned char *pat, int patlen, int nocase, int offset,
                        int depth, int negative, void *id, int iid) {
    if (!pm) {
        return -1;
    }

    // Reallocate patterns array if it's at capacity.
    if (pm->patterns_len + 1 > pm->patterns_capacity) {
        unsigned growth = pm->patterns_capacity / 2 > 0 ? pm->patterns_capacity / 2 : 1;
        pm->patterns_capacity += growth;
        HyperscanPattern *tmp = SnortAlloc(sizeof(HyperscanPattern) * pm->patterns_capacity);
        memcpy(tmp, pm->patterns, sizeof(HyperscanPattern) * pm->patterns_len);
        free(pm->patterns);
        pm->patterns = tmp;
    }

    HyperscanPattern *hp = &pm->patterns[pm->patterns_len];
    hp->user_data = id;
    hp->pattern = makeHex(pat, patlen);
    hp->pattern_len = patlen;
    hp->nocase = nocase;
    hp->offset = offset;
    hp->depth = depth;
    hp->negative = negative;
    hp->id = iid;
    hp->pattern_id = pm->patterns_len++;

    return 0;
}

int HyperscanCompileWithSnortConf(struct _SnortConfig *sc, HyperscanPm *pm,
                                  int (*build_tree)(struct _SnortConfig *,
                                                    void *id,
                                                    void **existing_tree),
                                  int (*neg_list_func)(void *id, void **list)) {
    if (!pm) {
        return -1;
    }

    // The Hyperscan compiler takes its patterns in a group of arrays.
    const unsigned num_patterns = pm->patterns_len;
    const char **patterns = SnortAlloc(num_patterns * sizeof(char *));
    unsigned int *flags = SnortAlloc(num_patterns * sizeof(unsigned int));
    unsigned int *ids = SnortAlloc(num_patterns * sizeof(unsigned int));
    hs_expr_ext_t *exts = SnortAlloc(num_patterns * sizeof(hs_expr_ext_t));
    const hs_expr_ext_t **ext =
        SnortAlloc(num_patterns * sizeof(hs_expr_ext_t *));

    unsigned int i = 0;
    for (; i < num_patterns; i++) {
        const HyperscanPattern *hp = &pm->patterns[i];
        patterns[i] = hp->pattern;
        flags[i] = HS_FLAG_SINGLEMATCH;
        if (hp->nocase) {
            flags[i] |= HS_FLAG_CASELESS;
        }
        ids[i] = i;
        exts[i].flags = 0;
        if (hp->offset != 0) {
            exts[i].flags |= HS_EXT_FLAG_MIN_OFFSET;
            exts[i].min_offset = hp->offset + hp->pattern_len;
        }
        if (hp->depth != 0) {
            exts[i].flags |= HS_EXT_FLAG_MAX_OFFSET;
            exts[i].max_offset = hp->offset + hp->depth;
        }

        ext[i] = &exts[i];
    }

    hs_compile_error_t *compile_error = NULL;
    hs_error_t error = hs_compile_ext_multi(patterns, flags, ids, ext,
                num_patterns, HS_MODE_BLOCK, NULL, &(pm->db), &compile_error);

    free(patterns);
    free(flags);
    free(ids);
    free(exts);
    free(ext);

    if (compile_error != NULL) {
        FatalError("hs_compile_multi() failed: %s (expression: %d)\n",
                   compile_error->message, compile_error->expression);
        hs_free_compile_error(compile_error);
        return -1;
    }

    if (error != HS_SUCCESS) {
        FatalError("hs_compile_multi() failed: error %d\n", error);
        return -1;
    }

    // Share the global Hyperscan context, and ensure that it has enough
    // scratch for this database.
    if (!sc->hyperscan_ctx) {
        FatalError("No Hyperscan context structure!\n");
        return -1;
    }
    pm->ctx = sc->hyperscan_ctx;
    error = hs_alloc_scratch(pm->db, &pm->ctx->scratch);

    if (error != HS_SUCCESS) {
        FatalError("hs_alloc_scratch() failed: error %d\n", error);
        return -1;
    }

    size_t scratch_size = 0;
    error = hs_scratch_size(pm->ctx->scratch, &scratch_size);
    if (error != HS_SUCCESS) {
        FatalError("hs_scratch_size() failed: error %d\n", error);
        return -1;
    }

    size_t db_size = 0;
    error = hs_database_size(pm->db, &db_size);
    if (error != HS_SUCCESS) {
        FatalError("hs_database_size() failed: error %d\n", error);
        return -1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "Built Hyperscan database: %u patterns, %zu bytes\n",
                            num_patterns, db_size));

    // Construct Snort's neg lists and option trees.
    for (i = 0; i < num_patterns; i++) {
        HyperscanPattern *hp = &pm->patterns[i];
        if (hp->negative) {
            neg_list_func(hp->user_data, &hp->neg_list);
        } else {
            build_tree(sc, hp->user_data, &hp->rule_option_tree);
        }

        build_tree(sc, NULL, &hp->rule_option_tree);
    }

    // Update summary info.
    summary.db_count++;
    summary.db_bytes += db_size;
    summary.scratch_size = scratch_size;

    return 0;
}

// Match callback, called by hs_scan for every match.
static
int onMatch(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags, void *ctx) {
    const HyperscanPm *pm = ctx;
    const HyperscanPattern *hp = &pm->patterns[id];

    if (pm->match(hp->user_data, hp->rule_option_tree, 0, pm->data,
                  hp->neg_list) > 0) {
        return 1; // Halt matching.
    }

    return 0; // Continue matching.
}

int HyperscanSearch(HyperscanPm *pm, unsigned char *t, int tlen,
                    int (*match)(void *id, void *tree, int index, void *data,
                                 void *neg_list),
                    void *data) {
    pm->data = data;
    pm->match = match;

    hs_error_t error = hs_scan(pm->db, (const char *)t, tlen, 0,
                               pm->ctx->scratch, onMatch, pm);

    if (error != HS_SUCCESS) {
        FatalError("hs_scan() failed: error %d\n", error);
    }

    return 0;
}

int HyperscanGetPatternCount(HyperscanPm *pm) {
    if (!pm) {
        return 0;
    }
    return pm->patterns_len;
}

void HyperscanPrintInfo(HyperscanPm *pm) {
    size_t db_size = 0;
    hs_database_size(pm->db, &db_size);

    char *info = NULL;
    hs_database_info(pm->db, &info);

    unsigned int min_len = ~0U;
    unsigned int max_len = 0;
    unsigned int total_len = 0;
    unsigned int nocase_count = 0;
    unsigned int offset_count = 0;
    unsigned int depth_count = 0;
    unsigned int negative_count = 0;

    unsigned int i;
    for (i = 0; i < pm->patterns_len; i++) {
        const HyperscanPattern *hp = &pm->patterns[i];
        total_len += hp->pattern_len;
        if (hp->pattern_len < min_len) {
            min_len = hp->pattern_len;
        }
        if (hp->pattern_len > max_len) {
            max_len = hp->pattern_len;
        }
        if (hp->nocase) {
            nocase_count++;
        }
        if (hp->offset) {
            offset_count++;
        }
        if (hp->depth) {
            depth_count++;
        }
        if (hp->negative) {
            negative_count++;
        }
    }

    LogMessage("+--[Pattern Matcher:Hyperscan]--------------------------------\n");
    LogMessage("| Number of patterns : %u\n", pm->patterns_len);
    LogMessage("|    with nocase     : %u\n", nocase_count);
    LogMessage("|    with offset     : %u\n", offset_count);
    LogMessage("|    with depth      : %u\n", depth_count);
    LogMessage("|    with negative   : %u\n", negative_count);
    LogMessage("| Min pattern length : %u\n", min_len);
    LogMessage("| Max pattern length : %u\n", max_len);
    LogMessage("| Avg pattern length : %.2f\n", (float)total_len / pm->patterns_len);
    LogMessage("|\n");
    LogMessage("| Database size (KB) : %.2f\n", (float)db_size / 1024);
    LogMessage("| Database info      : %s\n", info);
    LogMessage("+-------------------------------------------------------------\n");

    free(info);
}

void HyperscanPrintSummary() {
    LogMessage("+--[ Intel Hyperscan Summary ]--------------------------------\n");
    LogMessage("| Hyperscan version   : %s\n", hs_version());
    LogMessage("| Number of databases : %u\n", summary.db_count);
    LogMessage("| Memory (MB)         : %.2f\n", (float)summary.db_bytes / (1024 * 1024));
    LogMessage("| Scratch (KB)        : %.2f\n", (float)summary.scratch_size / 1024);
    LogMessage("+-------------------------------------------------------------\n");
}
