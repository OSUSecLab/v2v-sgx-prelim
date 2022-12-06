#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <sstream>
#include <fstream>
#include <sys/time.h>
using namespace std;
using namespace std::chrono;


#include "common.h"


#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#define PORT 8080

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;



// OCall implementations
void ocall_print(const char* str) {
    printf("%s", str);
    // cout << to_string(str)<< endl;
}



string hexStr(uint8_t *data, int len)
{
     stringstream ss;
     ss << hex;

     for( int i(0) ; i < len; ++i )
         ss << setw(2) << setfill('0') << (int)data[i] <<" " ;

     return ss.str();
}


// OCall implementations
void ocall_print_uint8_array(uint8_t* array, size_t len) {
    // cout << "len " << len << endl;
for (int i = 0; i < len; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", array[i]);
    }
    printf("\n");
}



std::string makeFixedLength(const int i, const int length)
{
    std::ostringstream ostr;

    if (i < 0)
        ostr << '-';

    ostr << std::setfill('0') << std::setw(length) << (i < 0 ? -i : i);

    return ostr.str();
}


void print_time(){


    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    std::cout << to_string(ms) << std::endl;


    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();

    typedef std::chrono::duration<int, ratio_multiply<std::chrono::hours::period, ratio<8>>::type> Days; /* UTC: +8:00 */

    Days days = std::chrono::duration_cast<Days>(duration);
        duration -= days;
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
        duration -= seconds;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        duration -= milliseconds;
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
        duration -= microseconds;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);

    cout << hours.count() << ":"
              << minutes.count() << ":"
              << seconds.count() << "."
              << makeFixedLength(milliseconds.count(), 3) 
              << makeFixedLength(microseconds.count(), 3) << std::endl;
}



int main(int argc, char const *argv[]) {



    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }


    sgx_status_t ecall_status;
    size_t cav_db_s_size = sizeof(cav_db_s);
    size_t sealed_size = sizeof(sgx_sealed_data_t) + cav_db_s_size;
    sgx_status_t status; 


   
   // -----------------manual seal create --------------------------------- 

    // cout << "manual seal create" << endl;
    
    // cav_db_s ptrSeal;
    // uint8_t temp_key[KEY_SIZE] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };  
    

    // memcpy(ptrSeal.dsk, temp_key, KEY_SIZE); 
    // ptrSeal.loc.latitude = 40.741895;
    // ptrSeal.loc.longitude = -73.989308;

    // ptrSeal.rst = 1;
    // ptrSeal.ts = 2;
    // ptrSeal.vrk = 3;
    // ptrSeal.ri = 4;

    // ptrSeal.vrl_count = 0;
    // for (int i = 0; i < 10; i++)
    // {
    //     ptrSeal.vrl[i] = i + 21;
    //     ++ptrSeal.vrl_count;
    // }


    

    // uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);


    // status = seal_keys(global_eid, &ecall_status,
    //         (uint8_t*)&ptrSeal, cav_db_s_size,
    //         (sgx_sealed_data_t*)sealed_data, sealed_size);


    // if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
    //     return 1;
    // }



    // // //  -----------------------save to file --------------------------------------------------

    
    // ofstream sfile(KEYSEAL_FILE, ios::out | ios::binary);
    // if (sfile.fail()) {return 1;}
    // sfile.write((const char*) sealed_data, sealed_size);
    // sfile.close();




    // ----------------------------- connect socket  -------------------------------------
     int sock = 0, valread;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "192.168.1.23", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    printf("send time :");
    print_time();

    
    //  // ------------------------------------enclave prepartion -----------------------------------------------

    size_t broadcast_s_size = sizeof(broadcast_s);
    

    // The encrypted message will contain the MAC, the IV, and the broadcast struct size.
    size_t encMessageLen = SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + broadcast_s_size ; 
    char *encMessage = (char *) malloc((encMessageLen)*sizeof(char));



    cout << "Prepare Boradcast: " <<  endl;
    status = prepare_broadcast(global_eid, &ecall_status,
              encMessage, encMessageLen);


    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    
     // -------------------------------------Send Broadcast --------------------------------------------------------
    
    cout << " Send Broadcast " << endl;
    send(sock , encMessage , encMessageLen , 0 );



    // size_t resultOutLen = broadcast_s_size;
    // char *resultOut = (char *) malloc((resultOutLen)*sizeof(char));

    //     status = receive_broadcast(global_eid, &ecall_status,
    //         (sgx_sealed_data_t*)sealedFile, sealed_size
    //           , encMessage, encMessageLen
    //           , resultOut, resultOutLen);

       
    return 0;
}
