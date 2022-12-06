#ifndef COMMON_H_
#define COMMON_H_

#define KEY_SIZE 16
#define KEYSEAL_FILE "DSK-VRK.seal"
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12
#define MAX_ENC_MSG_SIZE 2048
#define BSM_SIZE 100


struct GPSloc{

    float latitude;
    float longitude;
};

struct cav_db_s
    {
        uint8_t dsk[KEY_SIZE]; 
        struct GPSloc loc; 
        int ts;

        int vrk; 
        int rst; 
        int ri;


        int vrl[100];
        int vrl_count;


    };


struct vrk_riid_s
    {
        
        int vrk;
        int riid;

    };

struct broadcast_s
    {
        
        char bsm[BSM_SIZE];
        uint8_t tid[32];
        int ts;
        struct GPSloc loc;


    };

// // item
// struct Item {
//     char  title[MAX_ITEM_SIZE];
//     char  username[MAX_ITEM_SIZE];
//     char  password[MAX_ITEM_SIZE];
// };
// typedef struct Item item_t;

// // COMMON
// struct COMMON {
//     item_t items[MAX_ITEMS];
//     size_t size;
//     char master_password[MAX_ITEM_SIZE];
// };
// typedef struct COMMON COMMON_t;



#endif // COMMON_H_