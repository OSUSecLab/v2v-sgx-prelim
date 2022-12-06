#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"
#include "Enclave_t.h"
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "common.h"


#include "sgx_tcrypto.h"
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
} 



sgx_status_t seal_keys(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    

    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);

    return status;
}


int verify_dsk_timestamp(int ts){

    return 1;
}

int verify_dsk_location(struct GPSloc loc){

    return 1;
}


struct GPSloc get_trusted_loc(){

    struct GPSloc loc = {40.741895, -73.989308}; 
    return loc;
}


int get_trusted_ts(){

    return 12;
}

int array_equal(uint8_t* a, uint8_t* b, int len){

    
    for (int i = 0; i < len; i++)
    {
        if(a[i] != b[i]){
            return 0;  
        }
    }

    return 1;

}


// this function is not used here. It is used at sender side code  
sgx_status_t prepare_broadcast(sgx_sealed_data_t* sealed_data, size_t sealed_size, char *encMessageOut, size_t encMessageOutLen) {
    

    cav_db_s cav_db;
    uint32_t cav_db_s_len = sizeof(cav_db);   


    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)&cav_db, &cav_db_s_len);


    int verifTS = verify_dsk_timestamp(cav_db.ts);
    int verifLoc = verify_dsk_location(cav_db.loc);

    printf("\n Prepare Broadcast :");
    printf("%d :", cav_db.ts);
    printf("%d :", cav_db.vrk);
    printf("%.6f :", cav_db.loc.latitude);
    printf("%.6f :", cav_db.loc.longitude);
    printf("%d :", cav_db.vrl_count);



      int riid = (cav_db.vrk - cav_db.rst)/ cav_db.ri;

    struct vrk_riid_s vrk_riid  = {cav_db.vrk, riid};  


    broadcast_s broadcast_payload;
    char bsm[BSM_SIZE] =  "Congestion at Olentengy";
    memcpy(broadcast_payload.bsm, bsm, strlen(bsm)+1);

    broadcast_payload.ts = get_trusted_ts();
    broadcast_payload.loc = get_trusted_loc();
    // broadcast_payload.ts = 11;
    // broadcast_payload.loc.latitude = 40.741895;
    // broadcast_payload.loc.longitude = -73.989308;
 

    sgx_sha256_msg((const uint8_t *) &vrk_riid, sizeof(vrk_riid_s), (sgx_sha256_hash_t*) &broadcast_payload.tid);

    ocall_print_uint8_array(broadcast_payload.tid, 32);


    // uint8_t *origMessage = (uint8_t *) broadcast_payload;
    int broadcast_s_size = sizeof(broadcast_s);
    uint8_t p_dst[MAX_ENC_MSG_SIZE] = {0};

    // Generate the IV (nonce)
    sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

    sgx_rijndael128GCM_encrypt(
        &cav_db.dsk,
        (const uint8_t *) &broadcast_payload, sizeof(broadcast_s), 
        p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) (p_dst));

    memcpy(encMessageOut,p_dst,encMessageOutLen);


    // -------------------------------- local testing code --------------------------------------------------------

    // uint8_t *rcvdEncMessage = (uint8_t *) encMessageOut;
    // uint8_t p_dst_dec[MAX_ENC_MSG_SIZE] = {0};
    // size_t rcvdEncMessageInLen = encMessageOutLen;

    // size_t resultOutLen = broadcast_s_size; 
    // char *resultOut = (char *) malloc((resultOutLen)*sizeof(char));

    // sgx_rijndael128GCM_decrypt(
    //     &cav_db.dsk,
    //     rcvdEncMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
    //     resultOutLen,
    //     p_dst_dec,
    //     rcvdEncMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
    //     NULL, 0,
    //     (sgx_aes_gcm_128bit_tag_t *) rcvdEncMessage);


    
    // memcpy(resultOut, p_dst_dec, resultOutLen);

    // broadcast_s* broadcast_payload_rcv = (broadcast_s*)  resultOut ; 

    // printf("%s",broadcast_payload_rcv->bsm);    
    // printf("%d",broadcast_payload_rcv->ts);    
    // printf("%d",broadcast_payload_rcv->loc);    


    return status;
}


sgx_status_t receive_broadcast(char *rcvdEncMessageIn, size_t rcvdEncMessageInLen,  char *resultOut, size_t resultOutLen) {
    

      cav_db_s cav_db;
    uint32_t cav_db_s_len = sizeof(cav_db);   

    // sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)&cav_db, &cav_db_s_len);    
    
    uint8_t temp_key[KEY_SIZE] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };  
    

    memcpy(cav_db.dsk, temp_key, KEY_SIZE); 
    cav_db.loc.latitude = 40.741895;
    cav_db.loc.longitude = -73.989308;

    cav_db.rst = 1;
    cav_db.ts = 2;
    cav_db.vrk = 3;
    cav_db.ri = 4;


    cav_db.vrl_count = 0;
    for (int i = 0; i < 100; i++)
    {
        cav_db.vrl[i] = i + 21;
        ++cav_db.vrl_count;
    }
  


    int verifTS = verify_dsk_timestamp(cav_db.ts);
    int verifLoc = verify_dsk_location(cav_db.loc);

    //  printf("\n receive_broadcast :");
    // printf("%d :", cav_db.ts);
    // printf("%d :", cav_db.vrk);
    // printf("%.6f :", cav_db.loc.latitude);
    // printf("%.6f :", cav_db.loc.longitude);
    // printf("%d :", cav_db.vrl_count);



    int broadcast_s_size = sizeof(broadcast_s);


    uint8_t *rcvdEncMessage = (uint8_t *) rcvdEncMessageIn;
    uint8_t p_dst[MAX_ENC_MSG_SIZE] = {0};

    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &cav_db.dsk,
        rcvdEncMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        resultOutLen,
        p_dst,
        rcvdEncMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) rcvdEncMessage);


    
    memcpy(resultOut, p_dst, resultOutLen);

    broadcast_s* rcv = (broadcast_s*)  p_dst ; 

    printf("\nInside Msg : %s\n",rcv->bsm);    
    

    int riid = (cav_db.vrk - cav_db.rst)/ cav_db.ri;


    // printf("\n RCV TID :");
    // ocall_print_uint8_array(rcv->tid, 32);   

    // printf("\nMatch :%d", array_equal(rcv->tid, rcv->tid, 32)) ;

    for (int i = 0; i < cav_db.vrl_count ; i++)
     {

        struct vrk_riid_s vrk_riid  = {cav_db.vrl[i], riid};  
        uint8_t tid[32]; 

        sgx_sha256_msg((const uint8_t *) &vrk_riid, sizeof(vrk_riid_s), (sgx_sha256_hash_t*) &tid);
        
        // printf("\n Revoked TID :");
        // ocall_print_uint8_array(tid, 32);

        // printf("\nMatch :%d", array_equal(rcv->tid, tid, 32)) ;
     }
    
    

    return status;
}

