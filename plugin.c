#include <nfp/mem_atomic.h>

#include <pif_plugin.h>

//#include <pkt_ops.h>

#include <pif_headers.h>

#include <nfp_override.h>

#include <pif_common.h>

#include <std/hash.h>

#include <nfp/me.h>

#include <nfp.h>

#include <stdlib.h>

#define BUCKET_SIZE 7

__shared __export __addr40 __emem uint32_t i;

int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
    __xwrite uint32_t integer;
    integer = rand()%10 + 1;
    mem_write_atomic(&integer, &i, sizeof(integer));
    return PIF_PLUGIN_RETURN_FORWARD;
}

