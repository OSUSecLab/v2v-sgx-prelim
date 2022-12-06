#include <boost/asio.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/archive/binary_iarchive.hpp> 
#include <boost/archive/binary_oarchive.hpp> 

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>
#include <chrono>

using namespace std::chrono;
using namespace std;
using boost::asio::ip::tcp;
using namespace boost::asio;
using ip::tcp;
using std::string;
using std::cout;
using std::endl;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;


#include <array>
#include <memory>
#include <type_traits>

#include <ctime>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/conf.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/time.h>



#define HEADERSIZE 10 
#define ECDH_PUB_KEY_SIZE 65 


// Smart pointers to wrap openssl C types that need explicit free
using BIO_ptr = unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = unique_ptr<X509, decltype(&X509_free)>;
using ASN1_TIME_ptr = unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;





void aes_init()
{
    static int init=0;
    if (init==0)
    {
        EVP_CIPHER_CTX e_ctx, d_ctx;
 
        //initialize openssl ciphers
        OpenSSL_add_all_ciphers();
 
        //initialize random number generator (for IVs)
        int rv = RAND_load_file("/dev/urandom", 32);
    }
}
 
std::vector<unsigned char> aes_128_gcm_encrypt(std::string plaintext, std::string key)
{
    aes_init();
 
    size_t enc_length = plaintext.length()*3;
    std::vector<unsigned char> output;
    output.resize(enc_length,'\0');
 
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));
    std::copy( iv, iv+16, output.begin()+16);
 
    int actual_size=0, final_size=0;
    EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    EVP_EncryptInit(e_ctx, EVP_aes_128_gcm(), (const unsigned char*)key.c_str(), iv);
    EVP_EncryptUpdate(e_ctx, &output[32], &actual_size, (const unsigned char*)plaintext.data(), plaintext.length() );
    EVP_EncryptFinal(e_ctx, &output[32+actual_size], &final_size);
    EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    std::copy( tag, tag+16, output.begin() );
    std::copy( iv, iv+16, output.begin()+16);
    output.resize(32 + actual_size+final_size);
    EVP_CIPHER_CTX_free(e_ctx);
    return output;
}
 
std::string aes_128_gcm_decrypt(std::vector<unsigned char> ciphertext, std::string key)
{
    aes_init();
 
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    std::copy( ciphertext.begin(),    ciphertext.begin()+16, tag);
    std::copy( ciphertext.begin()+16, ciphertext.begin()+32, iv);
    std::vector<unsigned char> plaintext; plaintext.resize(ciphertext.size(), '\0');
 
    int actual_size=0, final_size=0;
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(d_ctx, EVP_aes_128_gcm(), (const unsigned char*)key.c_str(), iv);
    EVP_DecryptUpdate(d_ctx, &plaintext[0], &actual_size, &ciphertext[32], ciphertext.size()-32 );
    EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal(d_ctx, &plaintext[actual_size], &final_size);
    EVP_CIPHER_CTX_free(d_ctx);
    plaintext.resize(actual_size + final_size, '\0');
 
    return string(plaintext.begin(),plaintext.end());
}



std::string make_string(boost::asio::streambuf& streambuf)
{
  return {boost::asio::buffers_begin(streambuf.data()), 
          boost::asio::buffers_end(streambuf.data())};
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


string cert_to_pem_string(X509* x509)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_out, x509);
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    string pem = string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return pem;
}

// Convert the contents of an openssl BIO to a std::string
string bio_to_string(const BIO_ptr& bio, const int& max_len)
{
    // We are careful to do operations based on explicit lengths, not depending
    // on null terminated character streams except where we ensure the terminator

    // Create a buffer and zero it out
    char buffer[max_len];
    memset(buffer, 0, max_len);
    // Read one smaller than the buffer to make sure we end up with a null
    // terminator no matter what
    BIO_read(bio.get(), buffer, max_len - 1);
    return string(buffer);
}



int sig_verify(const char* cert_pem, const char* intermediate_pem)
{
    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, intermediate_pem);
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *signing_key=X509_get_pubkey(issuer);
 
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, cert_pem);
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
 
    int result = X509_verify(x509, signing_key);

    //  if (result == 1) {
    // cout << " validated OK. either trusted or self signed.";
    // } else {
    //     // validation failed
    //     int err = X509_STORE_CTX_get_error(c);
    // }
 
    EVP_PKEY_free(signing_key);
    BIO_free(b);
    BIO_free(c);
    X509_free(x509);
    X509_free(issuer);
 
    return result;
}
 
void cert_info(const char* cert_pem)
{
    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, cert_pem);
    X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
 
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
 
    //Subject
    BIO_printf(bio_out,"Subject: ");
    X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
    BIO_printf(bio_out,"\n");
 
    //Issuer
    BIO_printf(bio_out,"Issuer: ");
    X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
    BIO_printf(bio_out,"\n");
 
    //Public Key
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    EVP_PKEY_free(pkey);
 
    //Signature
    X509_signature_print(bio_out, x509->sig_alg, x509->signature);
    BIO_printf(bio_out,"\n");
 
    BIO_free(bio_out);
    BIO_free(b);
    X509_free(x509);
}


void send_obj(tcp::socket& sock, string msgOut){


  // Write to server.
  boost::asio::streambuf write_buffer;
  std::ostream output(&write_buffer);
  output << makeFixedLength(msgOut.size(), HEADERSIZE) << msgOut;
  // std::cout << "Writing: " << make_string(write_buffer) << std::endl;
  

  int bytes_transferred = boost::asio::write(sock, write_buffer);

}

std::string rcv_obj_str(tcp::socket& sock){


  // Read from client -- header 
  boost::asio::streambuf read_buffer;
  int header_size = boost::asio::read(sock, read_buffer,
      boost::asio::transfer_exactly(HEADERSIZE));
  // std::cout << "Header: " << make_string(read_buffer) << std::endl;
  int msg_size = std::stoi(make_string(read_buffer)); 
  read_buffer.consume(HEADERSIZE); // Remove data that was read.


  int msg_size_x = boost::asio::read(sock, read_buffer,
      boost::asio::transfer_exactly(msg_size));

  // std::cout << "Second Read Size: " << msg_size_x << std::endl;
  // std::cout << "Second Read Buffer: " <<  make_string(read_buffer) << std::endl;

  return make_string(read_buffer);

}



string read_(tcp::socket & socket) {
       boost::asio::streambuf buf;
       boost::asio::read_until( socket, buf, "\n" );
       string data = boost::asio::buffer_cast<const char*>(buf.data());
       return data;
}
void send_(tcp::socket & socket, const string& message) {
       const string msg = message + "\n";
       boost::asio::write( socket, boost::asio::buffer(message) );
}

//----------------------------------------------------------------------
X509 *new_x509(const char* cert_bytes)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, cert_bytes);
    X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    BIO_free(bio_mem);
    return x509;
}
//----------------------------------------------------------------------
X509_CRL *new_CRL(const char* crl_filename)
{
    BIO *bio = BIO_new_file(crl_filename, "r");
    X509_CRL *crl_file=d2i_X509_CRL_bio(bio,NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
    BIO_free(bio);
    return crl_file;
}

//----------------------------------------------------------------------
int is_revoked_by_crl(X509 *x509, X509 *issuer, X509_CRL *crl_file, int max_check)
{
    int is_revoked = -1;
    if (issuer)
    {
        EVP_PKEY *ikey=X509_get_pubkey(issuer);
        ASN1_INTEGER *serial = X509_get_serialNumber(x509);
 
        if (crl_file && ikey && X509_CRL_verify(crl_file, ikey))
        {
            is_revoked = 0;
            STACK_OF(X509_REVOKED) *revoked_list = crl_file->crl->revoked;
            for (int j = 0; j < max_check && !is_revoked; j++)
            {
                X509_REVOKED *entry = sk_X509_REVOKED_value(revoked_list, j);
                if (entry->serialNumber->length==serial->length)
                {
                    if (memcmp(entry->serialNumber->data, serial->data, serial->length)==0)
                    {
                        is_revoked=1;
                    }
                }
            }
        }
    }
    return is_revoked;
}

struct msg12{

    string cert_pem_str;
    int nonce; 
    unsigned char ec_pub[ECDH_PUB_KEY_SIZE];
    int ec_agree_len; 

       template <typename Archive>
      void serialize(Archive& ar, const unsigned int version)
      {
        ar & cert_pem_str;
        ar & nonce;
        ar & ec_pub;
        ar & ec_agree_len;
      };

};


int main() {

//------------------------------- Load local certificate ------------- 
// 

  const char cert_filestr[] = "cert_v2_ca_signed.pem";
             EVP_PKEY *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *certV2 = NULL;
  int ret;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (certV2 = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  string certV2_pemStr = cert_to_pem_string(certV2);
  // cout<< certV2_pemStr << endl;


//---------------------------------------------------------------------- Load CA certificate ------------- 
// 

    char ca_cert_file[] = "cert_ca_self_signed.pem";
    FILE *fp = fopen(ca_cert_file, "r");
    if (!fp) {
        fprintf(stderr, "unable to open: %s\n", ca_cert_file);
        return EXIT_FAILURE;
    }

    X509 *certCA = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!certCA) {
        fprintf(stderr, "unable to parse certificate in: %s\n", ca_cert_file);
        fclose(fp);
        return EXIT_FAILURE;
    }

    string certCA_pemStr = cert_to_pem_string(certCA);
      // cout<< certCA_pemStr << endl; 

  
// -------------------------------------------- connect socket abd receive data ----------------------


  boost::asio::io_service io_service;

  tcp::acceptor acceptor_(io_service,  tcp::endpoint( boost::asio::ip::address::from_string("192.168.1.23"), 1234 ) );
  
  tcp::socket socket(io_service);
  acceptor_.accept(socket);


  // -------------------------------------------- Compute  ECDH ----------------------


  OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;
    
    ECDH < ECP >::Domain ecB( CURVE );


    SecByteBlock privB(ecB.PrivateKeyLength()), pubB(ecB.PublicKeyLength());
    ecB.GenerateKeyPair(rng, privB, pubB);
    


// -------------------------------------------- random nonce ----------------------
  int nonceB = rand();
  // cout << "nonceB :" << nonceB << endl;



    string rcv_obj = rcv_obj_str(socket); 

   // get binary content
    std::istringstream iss(rcv_obj);
    boost::archive::binary_iarchive ia(iss);
    struct msg12 msg_rcv;
    ia & (msg_rcv);
    // std::cout << "Rcv Cert PEM str: " << msg_rcv.cert_pem_str << std::endl;
    // std::cout << "Rcv nonceA: " << msg_rcv.nonce << std::endl;
    // std::cout << "Rcv ec_agree_len: " << msg_rcv.ec_agree_len << std::endl;
    // std::cout << "Rcv AgreedValueLength() from A: " << msg_rcv.ec_agree_len << std::endl;

    // std::cout << "Msg ec_pub: " << msg_rcv.ec_pub << std::endl;

    // Integer pubA_int_rcv;
    // pubA_int_rcv.Decode(msg_rcv.ec_pub, ECDH_PUB_KEY_SIZE);
    // cout << "pubA_int_rcv :" << std::hex << pubA_int_rcv << endl;


//---------------------------------------------------------------------- Verify Peer certificate with CA ------------- 

  int rc1 = sig_verify(const_cast<char*>(msg_rcv.cert_pem_str.c_str()), const_cast<char*>(certCA_pemStr.c_str()));

  cout << "cert_sig_verify_result :" << rc1 <<endl;

//---------------------------------------------------------------------- Verify Cert Revocation ------------- 



    const char issuer1_bytes[] = "-----BEGIN CERTIFICATE-----" "\n"
"MIIDrDCCApSgAwIBAgIQCssoukZe5TkIdnRw883GEjANBgkqhkiG9w0BAQwFADBh" "\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" "\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD" "\n"
"QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaMEwxCzAJBgNVBAYTAlVT" "\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJjAkBgNVBAMTHURpZ2lDZXJ0IEVDQyBT" "\n"
"ZWN1cmUgU2VydmVyIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ghC6nfYJN6g" "\n"
"LGSkE85AnCNyqQIKDjc/ITa4jVMU9tWRlUvzlgKNcR7E2Munn17voOZ/WpIRllNv" "\n"
"68DLP679Wz9HJOeaBy6Wvqgvu1cYr3GkvXg6HuhbPGtkESvMNCuMo4IBITCCAR0w" "\n"
"EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwNAYIKwYBBQUHAQEE" "\n"
"KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQgYDVR0f" "\n"
"BDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv" "\n"
"YmFsUm9vdENBLmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYc" "\n"
"aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAdBgNVHQ4EFgQUo53mH/naOU/A" "\n"
"buiRy5Wl2jHiCp8wHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDQYJ" "\n"
"KoZIhvcNAQEMBQADggEBAMeKoENL7HTJxavVHzA1Nm6YVntIrAVjrnuaVyRXzG/6" "\n"
"3qttnMe2uuzO58pzZNvfBDcKAEmzP58mrZGMIOgfiA4q+2Y3yDDo0sIkp0VILeoB" "\n"
"UEoxlBPfjV/aKrtJPGHzecicZpIalir0ezZYoyxBEHQa0+1IttK7igZFcTMQMHp6" "\n"
"mCHdJLnsnLWSB62DxsRq+HfmNb4TDydkskO/g+l3VtsIh5RHFPVfKK+jaEyDj2D3" "\n"
"loB5hWp2Jp2VDCADjT7ueihlZGak2YPqmXTNbk19HOuNssWvFhtOyPNV6og4ETQd" "\n"
"Ea8/B6hPatJ0ES8q/HO3X8IVQwVs1n3aAr0im0/T+Xc=" "\n"
"-----END CERTIFICATE-----" "\n";
 
    //download these files first...
    //wget http://crl3.digicert.com/ssca-ecc-g1.crl
    //wget http://curl.haxx.se/ca/cacert.pem

 
    // X509 * x509 = new_x509(cert1_bytes);
    X509 * issuer = new_x509(issuer1_bytes);
    X509 * peer_cert = new_x509(const_cast<char*>(msg_rcv.cert_pem_str.c_str()));
    
    // BIO *bio_peer_cert = BIO_new(BIO_s_mem());
    // BIO_puts(bio_peer_cert, msg_rcv.cert_pem_str);
    // X509 * peer_cert = PEM_read_bio_X509(bio_peer_cert, NULL, NULL, NULL);
 

    // vector<string> crl_urls = x509_crl_urls(x509);
    // for(size_t i=0,ix=crl_urls.size(); i<ix; i++)
    // {
    //     cout << crl_urls[i] << endl;
    // }
    
    X509_CRL *crl_file = new_CRL("ssca-ecc-g1.crl");
    int max_check = 100; 
    int is_revoked = is_revoked_by_crl(peer_cert, issuer, crl_file, max_check);
    if (is_revoked== 0) cout << "Method 1: Not Revoked" << endl;
    if (is_revoked== 1) cout << "Method 1: Revoked" << endl;
    if (is_revoked==-1) cout << "Method 1: Revocation Unknown" << endl;


//---------------------------------------------------------------------- Derive EDDH Keys ------------- 

  if(msg_rcv.ec_agree_len != ecB.AgreedValueLength())
    throw runtime_error("Shared secret size mismatch");
    
    SecByteBlock sharedB(ecB.AgreedValueLength());

    const bool rtn2 = ecB.Agree(sharedB, privB, msg_rcv.ec_pub);
    Integer b;
    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    cout << " shared Key (B): " << std::hex << b << endl;


//---------------------------------------------------------------------- Send Msg 2 ------------- 


   struct msg12 msg_send;
   
   msg_send.nonce = nonceB; 
   msg_send.ec_agree_len = (int)(ecB.AgreedValueLength()); 
   msg_send.cert_pem_str = certV2_pemStr; 
   // cout<< "pubB.SizeInBytes(): " << pubB.SizeInBytes() << endl;
   std::copy(pubB.BytePtr(), pubB.BytePtr() + pubB.SizeInBytes(), msg_send.ec_pub); 
   

    // Integer pubB_int;
    // pubB_int.Decode(pubB.BytePtr(), pubB.SizeInBytes());
    // cout << "Send pubB_int :" << std::hex << pubB_int << endl;
    
    // Integer ec_pub_int;
    // ec_pub_int.Decode(msg_send.ec_pub, ECDH_PUB_KEY_SIZE);
    // cout << "Send ec_pub_int :" << std::hex << ec_pub_int << endl;
      

 // binary archive with stringstream
    std::ostringstream archive_stream;
    boost::archive::binary_oarchive oa(archive_stream);
    oa & (msg_send);
    std::string outbound_data = archive_stream.str(); 

    send_obj(socket, outbound_data);

//---------------------------------------------------------------------- REceive encrypted BSM ------------- 
  

     aes_init();
 
    //create a sample key
    // unsigned char key_bytes[16];
    // RAND_bytes(sharedA, sharedA.SizeInBytes());
    string key = string((char *)sharedB.BytePtr(), sharedB.SizeInBytes());


    // cout << "string encryption key :" << key << endl; 

  // Read from client -- header 
  boost::asio::streambuf read_buffer;
  int header_size = boost::asio::read(socket, read_buffer,
      boost::asio::transfer_exactly(HEADERSIZE));
  // std::cout << "Read: " << make_string(read_buffer) << std::endl;
  int msg_size = std::stoi(make_string(read_buffer)); 

  read_buffer.consume(HEADERSIZE); // Remove data that was read.


  int msg_size_x = boost::asio::read(socket, read_buffer,
      boost::asio::transfer_exactly(msg_size));
  // std::cout << "Read More: " << make_string(read_buffer) << std::endl;
  

  std::vector<unsigned char> cipherRcv(boost::asio::buffers_begin(read_buffer.data()), 
          boost::asio::buffers_end(read_buffer.data()));

     //decrypt
    string out = aes_128_gcm_decrypt(cipherRcv, key);
    cout << out << endl;



  cout << "rcv: ";
  print_time();

    // send_(socket, "Hello From Server!");
    // cout << "Servent sent Hello message to Client!" << endl;


   EVP_PKEY_free(pkey);
  X509_free(certCA);
  X509_free(certV2);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);



  // return 0;


}

