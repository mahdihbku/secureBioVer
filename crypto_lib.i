%module crypto_lib
%include "cdata.i"
%{

/* Put header files here or function declarations like below */
#define SWIG_FILE_WITH_INIT
#define SWIG_PYTHON_STRICT_BYTE_CHAR
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include <mcl/bn_c256.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define N 1024

extern int prepare_system(int threads_count);
extern void get_serialized_G1_G2(char *serialized_G1_G2);
extern int new_server(char *params_file);
extern int load_server(char *params_file);
extern void get_serialized_pub_keys(char *serialized_pub_keys);
extern void set_client_info_from_buf(char *new_client_info);
extern int load_enrolled_client(char *client_file);
extern int save_enrolled_client();
extern int generate_keys(char *priv_filename, char *pub_filename, char *rx_filename);
extern int load_keys(char *priv_filename, char *pub_filename, char *rx_filename);
extern int new_client(char *G1_G2_buf, char *G1_G2_file, char *priv_filename, char *pub_filename, char *rx_filename);
extern int load_client(char *G1_G2_file, char *priv_filename, char *pub_filename, char *rx_filename);
extern void set_x_get_Enc_X(char *x, char *out_Enc_X_buf);
extern void set_y_get_Enc_minus_Y(char *y, char *out_Enc_minus_Y_buf);
extern void check_client_authentication(char *in_buf, char *client_auth_msg);
extern void partially_decrypt(char *in_buf, char *out_buf);
extern int server_decryption(char *in_buf, int decryption_table_max_value);
extern int precompute_lookup_table(int max_value);
extern void get_client_encrypted_score(char *encrypted_score_buf);
extern void set_client_encrypted_score(char *in_buf);
extern void test();

%}

%include "typemaps.i"
%include "cstring.i"

extern int prepare_system(int threads_count);
extern int new_server(char *params_file);
extern int load_server(char *params_file);
extern void set_client_info_from_buf(char *new_client_info);
extern int load_enrolled_client(char *client_file);
extern int save_enrolled_client(char *dir);
extern int generate_keys(char *priv_filename, char *pub_filename, char *rx_filename);
extern int load_keys(char *priv_filename, char *pub_filename, char *rx_filename);
extern int new_client(char *G1_G2_buf, char *G1_G2_file, char *priv_filename, char *pub_filename, char *rx_filename);
extern int load_client(char *G1_G2_file, char *priv_filename, char *pub_filename, char *rx_filename);
extern int server_decryption(char *in_buf, int decryption_table_max_value);
extern int precompute_lookup_table(int max_value);
extern void set_client_encrypted_score(char *in_buf);
extern void test();


%cstring_chunk_output(char *serialized_G1_G2, 32+2*32);    // G1|G2
extern void get_serialized_G1_G2(char *serialized_G1_G2);


%cstring_chunk_output(char *serialized_pub_keys, 32+2*32);     // H1_c|H2_c
extern void get_serialized_pub_keys(char *serialized_pub_keys);


%cstring_chunk_output(char *out_Enc_X_buf, 2*N*(32+2*32));    // X1_c|X2_c
extern void set_x_get_Enc_X(char *x, char *out_Enc_X_buf);

%cstring_chunk_output(char *out_Enc_minus_Y_buf, 2*N*(32+2*32));  // |Y1_c|Y2_c
extern void set_y_get_Enc_minus_Y(char *y, char *out_Enc_minus_Y_buf);


%cstring_chunk_output(char *client_auth_msg, 3*12*32);  // h1|h2|h3
extern void check_client_authentication(char *in_buf, char *client_auth_msg);


%cstring_chunk_output(char *out_buf, 6*12*32+6*32); // c1|c2|c3|a[0]|a[1]|a[2]|c[0]|c[1]|c[2]|res[0]|res[1]|res[2]
extern void partially_decrypt(char *in_buf, char *out_buf);

%cstring_chunk_output(char *encrypted_score_buf, 4*12*32); // h1|h2|h3|c4
extern void get_client_encrypted_score(char *encrypted_score_buf);