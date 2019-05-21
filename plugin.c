#include <nfp/mem_atomic.h>

#include <pif_plugin.h>

//#include <pkt_ops.h>

#include <pif_headers.h>

#include <nfp_override.h>

#include <pif_common.h>

#include <std/hash.h>

#include <nfp/me.h>

#include <nfp.h>


#define BUCKET_SIZE 7


#define STATE_TABLE_SIZE 0xFF /* 16777200 state table entries available */

#define VAL_1X 1
#define VAL_2X VAL_1X, VAL_1X
#define VAL_4X VAL_2X, VAL_2X
#define VAL_8X VAL_4X, VAL_4X
#define VAL_16X VAL_8X, VAL_8X
#define VAL_32X VAL_16X, VAL_16X
#define VAL_64X VAL_32X, VAL_32X
#define VAL_128X VAL_64X, VAL_64X
#define VAL_256X VAL_128X, VAL_128X
#define VAL_512X VAL_256X, VAL_256X
#define VAL_1024X VAL_512X, VAL_512X
#define VAL_2048X VAL_1024X, VAL_1024X
#define VAL_4096X VAL_2048X, VAL_2048X
typedef struct bucket_entry {

    uint32_t key[3]; /* ip1, ip2, ports */

}bucket_entry;


typedef struct bucket_list {
    uint32_t row[BUCKET_SIZE];
    uint32_t heap_size;
    uint32_t suggestion[BUCKET_SIZE + 1];
    struct bucket_entry entry[BUCKET_SIZE];

}bucket_list;

typedef struct suggested_export {
    
    uint32_t arr_index[BUCKET_SIZE];
    
}suggested_export;
volatile __emem __export uint32_t global_semaphores[STATE_TABLE_SIZE + 1] = {VAL_256X};
__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE + 1];
__shared __export __addr40 __emem uint32_t arr;
void semaphore_down(volatile __declspec(mem addr40) void * addr) {
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    SIGNAL_PAIR my_signal_pair;
    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;
    do {
        xfer = 1;
        __asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
            sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
        }
        sleep(500);
    } while (xfer == 0);
}
void semaphore_up(volatile __declspec(mem addr40) void * addr) {
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;
    __asm {
        mem[incr, --, addr_hi, <<8, addr_lo, 1];
    }
}
int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers,

                        MATCH_DATA_T *match_data)

{

    
    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t update_hash_value;

    uint32_t update_hash_key[3];

    __xwrite uint32_t tmp_b_info;

    __addr40 uint32_t *key_addr;

    __xrw uint32_t key_val_rw[3];

    __xread uint32_t hash_key_r[3];
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t z = 0;
//    __xwrite uint32_t heap_size_rw;
//    __xwrite uint32_t temp = 0;
    __addr40 __emem bucket_list *b_info;

    uint32_t largest;
    uint32_t root;
    uint32_t swap;
    uint32_t reverse;
    uint32_t heap_arr_index[BUCKET_SIZE];
    __xread uint32_t heap_size_r;
    __xread uint32_t heap_arr_r[BUCKET_SIZE];
//    __xrw uint32_t suggestion_rw[3] = {0,0,0};
    __xrw uint64_t exportReset = 0;
//    uint32_t minimum;
    __xrw uint32_t index_check;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);



    /* TODO: Add another field to indicate direction ?*/

    update_hash_key[0] = ipv4->srcAddr;

    update_hash_key[1] = ipv4->dstAddr;

    update_hash_key[2] = (udp->srcPort << 16) | udp->dstPort;



    key_val_rw[0] = ipv4->srcAddr;

    key_val_rw[1] = ipv4->dstAddr;

    key_val_rw[2] = (udp->srcPort << 16) | udp->dstPort;


    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 1);

    update_hash_value &= (STATE_TABLE_SIZE);
    
    
    semaphore_down(&global_semaphores[update_hash_value]);
//    mem_read_atomic(&heap_size_r, &state_hashtable[update_hash_value].heap_size, sizeof(heap_size_r));
//    if(heap_size_r < BUCKET_SIZE){
    
    for (i = 0; i < BUCKET_SIZE; i++) {
        mem_read_atomic(hash_key_r, state_hashtable[update_hash_value].entry[i].key, sizeof(hash_key_r));
//        mem_incr32(&b_info->heap_size);
        if (hash_key_r[0] == update_hash_key[0] &&
            hash_key_r[1] == update_hash_key[1] &&
            hash_key_r[2] == update_hash_key[2] ) { /* Hit */
            __xrw uint32_t count;
            b_info = &state_hashtable[update_hash_value];
            count = 1;
            mem_test_add(&count,&b_info->row[i], 1 << 2);
            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
                count = 2;
                mem_add32(&count,&b_info->row[i], 1 << 2);
            } else if (count == 0xFFFFFFFF) {
                mem_incr32(&b_info->row[i]);
            }
            break;
        }
        else if (hash_key_r[0] == 0) {
            b_info = &state_hashtable[update_hash_value];
            key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[i].key;
            tmp_b_info = 1;
            mem_write_atomic(&tmp_b_info, &b_info->row[i], sizeof(tmp_b_info));
            mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));
//            mem_incr32(&b_info->heap_size);
            break;
        }
    }
    if (i == BUCKET_SIZE){
        key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[1].key;
        mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));
        //        //        mem_incr32(&b_info->heap_size);
    }
    
//    }
    semaphore_up(&global_semaphores[update_hash_value]);
//    if (i == BUCKET_SIZE){
////        key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[0].key;
////        mem_write_atomic(&exportReset,(__addr40 void *)key_addr, sizeof(exportReset));
//        //        mem_incr32(&b_info->heap_size);
//    }
    
//    mem_write_atomic(&exportIndex,&arr, sizeof(exportIndex));
//    /* If bucket full, drop */
//    if (i == BUCKET_SIZE){
//    mem_read_atomic(&heap_size_r, &state_hashtable[update_hash_value].heap_size, sizeof(heap_size_r));
//    if(heap_size_r == BUCKET_SIZE){
//        mem_read_atomic(heap_arr_r, state_hashtable[update_hash_value].row, sizeof(heap_arr_r));
//        for (z = 0; z < BUCKET_SIZE; z++){
//            heap_arr_index[z] = z;
//        }
//        for (j = 0; j <= BUCKET_SIZE / 2 - 1; j++){
//            reverse = BUCKET_SIZE / 2 - 1 - j;
//            while(1){
//                largest = reverse; // Initialize largest as root
//
//                // If left child is larger than root
//                if (2*reverse + 1 < BUCKET_SIZE && heap_arr_r[heap_arr_index[2*reverse + 1]] > heap_arr_r[heap_arr_index[largest]])
//                    largest = 2*reverse + 1;
//
//                // If right child is larger than largest so far
//                if (2*reverse + 2 < BUCKET_SIZE && heap_arr_r[heap_arr_index[2*reverse + 2]] > heap_arr_r[heap_arr_index[largest]])
//                    largest = 2*reverse + 2;
//
//                // If largest is not root
//                if (largest != reverse)
//                {
//                    swap = heap_arr_index[largest];
//                    heap_arr_index[largest] = heap_arr_index[reverse];
//                    heap_arr_index[reverse] = swap;
//                }else{
//                    break;
//                }
//                reverse = largest;
//            }
//        }
////
////        // One by one extract an element from heap
//        for (j = 0; j <= BUCKET_SIZE - 1; j++)
//        {
//            reverse = BUCKET_SIZE - 1 - j;
//            // Move current root to end
//            swap = heap_arr_index[0];
//            heap_arr_index[0] = heap_arr_index[reverse];
//            heap_arr_index[reverse] = swap;
//
//            root = 0;
//            while(1){
//                largest = root; // Initialize largest as root
//
//                // If left child is larger than root
//                if (2*root + 1 < reverse && heap_arr_r[heap_arr_index[2*root + 1]] > heap_arr_r[heap_arr_index[largest]])
//                    largest = 2*root + 1;
//
//                // If right child is larger than largest so far
//                if (2*root + 2 < reverse && heap_arr_r[heap_arr_index[2*root + 2]] > heap_arr_r[heap_arr_index[largest]])
//                    largest = 2*root + 2;
//
//                // If largest is not root
//                if (largest != root)
//                {
//                    swap = heap_arr_index[largest];
//                    heap_arr_index[largest] = heap_arr_index[root];
//                    heap_arr_index[root] = swap;
//                }else{
//                    break;
//                }
//                root = largest;
//            }
//        }
//    index_check = 1;
////    mem_write_atomic(&index_check,&arr, sizeof(index_check));
//    b_info = &state_hashtable[update_hash_value];
//    key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[index_check].key;
//    tmp_b_info = 1;
//    mem_write_atomic(&tmp_b_info, &b_info->row[index_check], sizeof(tmp_b_info));
//    mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));
//            mem_decr32(&b_info->heap_size);
//    //        if(update_hash_value == STATE_TABLE_SIZE){
//    //            index_check = heap_arr_index[1];
//    //            mem_write_atomic(&index_check,&arr, sizeof(index_check));}
//
//
//        }
//    }

    

    return PIF_PLUGIN_RETURN_FORWARD;

}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {


    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t hash_value;

    uint32_t  hash_key[3];

    __xread uint32_t hash_key_r[3];

    __addr40 __emem bucket_list *b_info;

    uint32_t i;
    __xrw uint32_t count;
    __addr40 uint32_t *key_addr;
    __xrw uint64_t exportReset = 0;
    __xread uint32_t heap_size_r;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);
    
    /* TODO: Add another field to indicate direction ?*/

    hash_key[0] = ipv4->srcAddr;

    hash_key[1] = ipv4->dstAddr;

    hash_key[2] = (udp->srcPort << 16) | udp->dstPort;

    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);

    hash_value &= (STATE_TABLE_SIZE);
    
    for (i = 0; i < BUCKET_SIZE; i++) {
        mem_read_atomic(hash_key_r, state_hashtable[hash_value].entry[i].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */
        
        if (hash_key_r[0] == 0) {
            continue;
        }

        if (hash_key_r[0] == hash_key[0] &&

            hash_key_r[1] == hash_key[1] &&

            hash_key_r[2] == hash_key[2] ) { /* Hit */
            
            b_info = &state_hashtable[hash_value];
            
            count = 1;

            mem_test_add(&count,&b_info->row[i], 1 << 2);
            

            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */

                count = 2;

                mem_add32(&count,&b_info->row[i], 1 << 2);

            } else if (count == 0xFFFFFFFF) {

                mem_incr32(&b_info->row[i]);

            }
            
            return PIF_PLUGIN_RETURN_FORWARD;
        }

    }
//    mem_incr32(&arr);

  if (pif_plugin_state_update(headers, match_data) == PIF_PLUGIN_RETURN_DROP) {

        return PIF_PLUGIN_RETURN_DROP;
    }
    return PIF_PLUGIN_RETURN_FORWARD;
}

