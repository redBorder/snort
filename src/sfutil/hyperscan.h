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

#include <hs.h>

#ifndef SNORT_HYPERSCAN_H
#define SNORT_HYPERSCAN_H

struct _SnortConfig;

typedef struct _HyperscanPattern {
    char *pattern;
    unsigned int pattern_len;
    unsigned int nocase;
    unsigned int offset;
    unsigned int depth;
    unsigned int negative;
    int id;                 /* pattern id passed in from mpse */
    unsigned int pattern_id; /* actual pattern id */

    void *user_data;
    void *rule_option_tree;
    void *neg_list;
} HyperscanPattern;

// Context shared between all Hyperscan matchers.
typedef struct _HyperscanContext {
    hs_scratch_t *scratch;
} HyperscanContext;

typedef struct _HyperscanPm {
    hs_database_t *db;
    HyperscanContext *ctx;
    HyperscanPattern *patterns;
    unsigned int patterns_len; // number of elements
    unsigned int patterns_capacity; // allocated capacity

    /* Temporary data for match callback */
    void *data;
    int (*match)(void *id, void *tree, int index, void *data, void *neg_list);

    void (*user_free)(void *);
    void (*option_tree_free)(void **);
    void (*neg_list_free)(void **);
} HyperscanPm;

/*
 * Prototypes
 */

HyperscanPm *HyperscanNew(void (*userfree)(void *p),
                          void (*optiontreefree)(void **p),
                          void (*neg_list_free)(void **p));
void HyperscanFree(HyperscanPm *pm);

HyperscanContext *HyperscanNewContext();
void HyperscanFreeContext(HyperscanContext *ctx);

int HyperscanAddPattern(struct _SnortConfig *sc, HyperscanPm *pm,
                        unsigned char *pat, int patlen, int nocase, int offset,
                        int depth, int negative, void *id, int iid);

int HyperscanCompileWithSnortConf(struct _SnortConfig *sc, HyperscanPm *pp,
                                  int (*build_tree)(struct _SnortConfig *,
                                                    void *id,
                                                    void **existing_tree),
                                  int (*neg_list_func)(void *id, void **list));

int HyperscanSearch(HyperscanPm *pm, unsigned char *t, int tlen,
                    int (*match)(void *id, void *tree, int index, void *data,
                                 void *neg_list),
                    void *data);

int HyperscanGetPatternCount(HyperscanPm *pm);

void HyperscanPrintInfo(HyperscanPm *pm);

void HyperscanPrintSummary();

#endif // SNORT_HYPERSCAN_H
