#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <sys/time.h>
// #include <mcl/bn_c384.h>
#include <mcl/bn_c384_256.h>
// #include <mcl/bn_c256.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <omp.h>

// common parameters:
// #define N 512 	// feature vector size
#define N 1024
int G1_size;	// = mclBn_getG1ByteSize();
int Fp_size;	// = G1_size;
int G2_size;	// = 2 * G1_size;
int GT_size;	// = 12 * G1_size;
const int true = 1;
const int false = 0;
// server parameters:
unsigned char **str; // powers of z -- precomputed accepted scores
mclBnG1 G1_s;
mclBnG2 G2_s;
mclBnGT z_s;
unsigned int server_t = 1;	// nbr of threads to be created by the server
unsigned int server_elems_per_thread = 0;	// will be =N/server_t
// clients' info on server:
#define MAX_CLIENTS 1000
typedef struct client_info {
	char ID_s[20];	// client's id
	mclBnG1 H1_s;	// H1: public key in G1
	mclBnG2 H2_s;	// H2: public key in G2
	mclBnG1 *X1_s;	// encrypted feature vector X in G1
	mclBnG2 *X2_s;	// encrypted feature vector X in G2
	mclBnGT h1_s, h2_s, h3_s, c4_s;	// encrypted final score
	int client_info_set;	// boolean. 1: client ID_s, H1_s, H2_s, X1_s, and X2_s are set. 0: if not
	int client_enc_score_set;	// boolean. 1: h1_s, h2_s, h3_s, c4_s are set. 0: if not
} client_s;
// to be shared by server threads
typedef struct sub_func_parameters {
	int thread_index;
	unsigned char *Y1_Y2_buf;
	mclBnGT *e1, *e2, *e3, *e4;
	client_s *client;
} sub_func_vars;
client_s clients_table[MAX_CLIENTS];
int enrolled_clients_count = 0;
#define MAXTHREADS 1024
// client parameters:
char ID_c[20];	// client's id
mclBnFr s1, s2, *rx;	// private keys in G1, G2
mclBnG1 G1_c, H1_c;	// H1: public key in G1
mclBnG2 G2_c, H2_c;	// H2: public key in G2
mclBnGT z_c;



// TODO delete
double print_time(struct timeval *start, struct timeval *end)
{
	double usec;

	usec = (end->tv_sec*1000000 + end->tv_usec) - (start->tv_sec*1000000 + start->tv_usec);
	return usec/1000.0;
}

// print buffer buf of size buf_size
void print_buf(unsigned char* buf, size_t buf_size) {
	if (buf_size < 20)	// small buffer
		for (size_t i = 0; i < buf_size; i++)
			printf("%02X", buf[i]);
	else {	// big buffer
		for (size_t i = 0; i < 10; i++)
			printf("%02X", buf[i]);
		printf("...");
		for (size_t i = buf_size-10; i < buf_size; i++)
			printf("%02X", buf[i]);
	}
	printf("\n");
}

// save buf to file
int buf2file(unsigned char *file_name, char* buf, size_t buf_size) {
	FILE *file_p = fopen(file_name, "wb");
	if(file_p == NULL) {
		printf("buf2file: error opening file!\n");   
		abort();             
	}
	fwrite(buf, buf_size, 1, file_p);
	fclose(file_p);
	return 1;
}

// append buf to file
int buf2file_app(unsigned char *file_name, char* buf, size_t buf_size) {
	FILE *file_p = fopen(file_name, "a");
	if(file_p == NULL) {
		printf("buf2file: error opening file!\n");   
		abort();             
	}
	fwrite(buf, buf_size, 1, file_p);
	fclose(file_p);
	return 1;
}

/**
	read file to buf
	@note buf must be allocated outsied
*/
int file2buf(unsigned char *file_name, char* buf, size_t buf_size) {
	FILE *file_p = fopen(file_name, "rb");
	if(file_p == NULL) {
		printf("file2buf: error opening file %s!\n", file_name);   
		abort();
	}
	fread(buf, buf_size, 1, file_p);
	fclose(file_p);
	return 1;
}

// hash compare function (for sort)
int comp(const void *a, const void *b) { 
    const unsigned char **ia = (const unsigned char **)a;
    const unsigned char **ib = (const unsigned char **)b;
    return -memcmp(*ia, *ib, GT_size);
}

int brutefore_decrypt(unsigned char *x, unsigned char **A, int max) {
	for (int i = 0; i < max; i++)
		if (memcmp(A[i], x, GT_size) == 0)
			return i;
	return -1;
}

// binary search function (reverse order)
int binsearch(unsigned char *x, unsigned char **A, int l, int h) {
	int lo = l;
	int hi = h;
	while (lo < hi) {
		int mid = lo + (hi - lo) / 2;
		if (memcmp(A[mid], x, GT_size) == 0)
			return mid;
		if (memcmp(A[mid], x, GT_size) > 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
}

/**
	(client/server) set and initialize the system parameters
*/
int prepare_system(int threads_count) {

	// initialize PRNGs
	srand(time(0));
	if (!RAND_load_file("/dev/urandom", 1024))
		abort();

	// Initialize mcl library
	int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR); // MCL_BLS12_381
	// int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("Error initializing curve = %d\n", ret);
		abort();
	}

	mclBn_verifyOrderG1(1);
	mclBn_verifyOrderG2(1);

	G1_size = mclBn_getG1ByteSize();
	Fp_size = mclBn_getFpByteSize();
	G2_size = 2 * G1_size;
	GT_size = 12 * G1_size;


	// TODO TO DELETE ///////////////////////////
	// printf("----G1_size=%d Fp_size=%d G2_size=%d GT_size=%d\n", G1_size, Fp_size, G2_size, GT_size);
	// unsigned char temp_bufG1[G1_size];
// unsigned char temp_bufG2[G2_size];
	// mclBnG1 temp_G1;
	// mclBnG2 temp_G2;
	// mclBnGT temp_z;
	// // ulong n = mclBnG1_serialize(temp_bufG1, G1_size, &temp_G1);
	// printf("----mclBnG1_serialize=%lu\n", mclBnG1_serialize(temp_bufG1, G1_size, &temp_G1));
	// printf("----mclBnG2_serialize=%lu\n", mclBnG2_serialize(temp_bufG2, G2_size, &temp_G2));

	// printf("----mclBnG1_deserialize=%lu\n", mclBnG1_deserialize(&temp_G1, temp_bufG1, G1_size));
	// printf("----mclBnG2_deserialize=%lu\n", mclBnG2_deserialize(&temp_G2, temp_bufG2, G2_size));
	/////////////////////////////////////////////

	server_t = threads_count;
	server_elems_per_thread = N/server_t;
	if (N%server_t!= 0) server_elems_per_thread++;
	
}

/**
	(server) return serialized G1 and G2
	@note buf of size G1_size+G2_size must be allocated outside
*/
void get_serialized_G1_G2(unsigned char *buf) {

	// printf("mclBnG1_serialize = %zu\n", mclBnG1_serialize(buf, G1_size, &G1_s));
	// printf("mclBnG2_serialize = %zu\n", mclBnG2_serialize(buf+G1_size, G2_size, &G2_s));

	if (!mclBnG1_serialize(buf, G1_size, &G1_s) || !mclBnG2_serialize(buf+G1_size, G2_size, &G2_s)) {
		printf("get_serialized_G1_G2: Error in serialization\n");
		abort();
	}
}

/**
	(server) generate new random generators G1, G2 and z = e(G1,G2)
*/
int new_server(unsigned char *params_file) {
	mclBnG1_hashAndMapTo(&G1_s, "Generator for group G1", 22);
	mclBnG2_hashAndMapTo(&G2_s, "Generator for group G2", 22);
	mclBn_pairing(&z_s, &G1_s, &G2_s);

	// save G1 and G2 to params_file
	unsigned char buf[G1_size+G2_size];
	get_serialized_G1_G2(buf);
	buf2file(params_file, buf, G1_size+G2_size);
}

/**
	(server) load G1 and G2 from params_file
*/
int load_server(unsigned char *params_file) {
	unsigned char buf[G1_size+G2_size];
	file2buf(params_file, buf, G1_size+G2_size);
	if (!mclBnG1_deserialize(&G1_s, buf, G1_size) || !mclBnG2_deserialize(&G2_s, buf+G1_size, G2_size)) {
		printf("load_server: Error in deserializing\n");
		abort();
	}
	mclBn_pairing(&z_s, &G1_s, &G2_s);
}

/**
	(client) return serialized H1_c and H2_c
	@note buf of size G1_size+G2_size must be allocated outside
*/
void get_serialized_pub_keys(unsigned char *buf) {
	if (!mclBnG1_serialize(buf, G1_size, &H1_c) || !mclBnG2_serialize(buf+G1_size, G2_size, &H2_c)) {
		printf("get_serialized_pyb_keys: Error in serialization\n");
		abort();
	}
}

// (server) deserializing ID, H1_s, H2_s, X1_s, X2_s
void set_client_info_from_buf(unsigned char *buf) {
	unsigned char *ptr = buf;

	client_s client;

	memcpy(client.ID_s, buf, 20);
	ptr += 20;

	// TODO check if client not already enrolled

	if (mclBnG1_deserialize(&client.H1_s, ptr, G1_size) != G1_size) {
		printf("set_client_info_from_buf: Error in deserializing client.H1_s\n");
		abort();
	}
	if (mclBnG2_deserialize(&client.H2_s, ptr+G1_size, G2_size) != G2_size) {
		printf("set_client_info_from_buf: Error in deserializing client.H2_s\n");
		abort();
	}
	// printf("mclBnG1_deserialize = %zu\n", mclBnG1_deserialize(&client.H1_s, ptr, G1_size));
	// printf("mclBnG2_deserialize = %zu\n", mclBnG2_deserialize(&client.H2_s, ptr+G1_size, G2_size));

	if (!mclBnG1_deserialize(&client.H1_s, ptr, G1_size) || !mclBnG2_deserialize(&client.H2_s, ptr+G1_size, G2_size)) {
		printf("set_client_info_from_buf: Error in deserialization\n");
		abort();
	}
	ptr += G1_size + G2_size;

	client.X1_s = (mclBnG1 *) malloc(2*N*sizeof(mclBnG1));
	client.X2_s = (mclBnG2 *) malloc(2*N*sizeof(mclBnG2));

	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG1_deserialize(&client.X1_s[i], ptr, G1_size)) {
			printf("set_client_info_from_buf: Error in deserialization\n");
			abort();
		}
		ptr += G1_size;
	}

	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG2_deserialize(&client.X2_s[i], ptr, G2_size)) {
			printf("set_client_info_from_buf: Error in deserialization\n");
			abort();
		}
		ptr += G2_size;
	}

	client.client_info_set = true;
	client.client_enc_score_set = false;

	clients_table[0] = client;
	enrolled_clients_count++;

}

// convert buffer to hex string. outsz must be = insz*2+1
void tohex(unsigned char * in, size_t insz, unsigned char * out, size_t outsz) {
	assert(outsz == insz*2+1);
    unsigned char *pin = in;
    const unsigned char *hex = "0123456789ABCDEF";
    unsigned char *pout = out;
    for(; pin < in+insz; pout+=2, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
    }
	*pout = 0;
    // pout[-1] = 0;
}

// (server) load already enrolled client
int load_enrolled_client(unsigned char *client_file) {
	assert (strlen(client_file) < 255);

	unsigned char _buf[20 + G1_size+G2_size + 2*N*(G1_size+G2_size)];	// ID_s|H1_s|H2_s|X1_s|X2_s
	if (!file2buf(client_file, _buf, 20 + G1_size+G2_size + 2*N*(G1_size+G2_size))) {
		printf("load_enrolled_client: unable to load client info from file: %s\n", client_file);
		return 0;
	}
	set_client_info_from_buf(_buf);
	return 1;
}

// (server) save current client info to file id.data
int save_enrolled_client(unsigned char *dir) {
	assert (strlen(dir) < 200);

	client_s* client = &clients_table[0];

	char client_filename[strlen(dir) + 40 + 6];	// = "dir/id_in_hex.data"
	strcpy(client_filename, dir);
	char ID_s_hex[41];
	tohex(client->ID_s, 20, ID_s_hex, 41);
	strcat(client_filename, ID_s_hex);
	strcat(client_filename, ".data");

	unsigned char _buf[20 + G1_size+G2_size + 2*N*(G1_size+G2_size)];	// ID_s|H1_s|H2_s|X1_s|X2_s
	unsigned char *ptr = _buf;
	memcpy(ptr, client->ID_s, 20);	ptr += 20;
	mclBnG1_serialize(ptr, G1_size, &client->H1_s);	ptr += G1_size;
	mclBnG2_serialize(ptr, G2_size, &client->H2_s);	ptr += G2_size;

	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG1_serialize(ptr, G1_size, &client->X1_s[i])) {
			printf("save_enrolled_client: Error in serialization\n");
			abort();
		}
		ptr += G1_size;
	}

	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG2_serialize(ptr, G2_size, &client->X2_s[i])) {
			printf("save_enrolled_client: Error in serialization\n");
			abort();
		}
		ptr += G2_size;
	}
	if (!buf2file(client_filename, _buf, 20 + G1_size+G2_size + 2*N*(G1_size+G2_size))) {
		printf("save_enrolled_client: unable to load client info from file: %s\n", client_filename);
		return 0;
	}
	// printf("save_enrolled_client: client info saved to file: %s\n", client_filename);

	return 1;
}

/**
	(client) generate client private and public keys, in addition to rx
*/
int generate_keys(unsigned char *priv_filename, unsigned char *pub_filename, unsigned char *rx_filename) {
	// compute random private keys for G1 and G2
	if (mclBnFr_setByCSPRNG(&s1) || mclBnFr_setByCSPRNG(&s2)) {
		printf("generate_keys: Error in setByCSPRNG\n");
		abort();
	}

	// compute public keys for G1 (H1) and G2 (H2)
	mclBnG1_mul(&H1_c, &G1_c, &s1);
	mclBnG2_mul(&H2_c, &G2_c, &s2);
	// random values infused into X and Y
	rx = (mclBnFr *) malloc(N*sizeof(mclBnFr));
	for (int i = 0; i < N; i++)
		if (mclBnFr_setByCSPRNG(&rx[i])) {
			printf("generate_keys: Error in setByCSPRNG\n");
			abort();
		}

	// save generated values to files
	unsigned char priv1_buf[Fp_size], priv2_buf[Fp_size], pub1_buf[G1_size], pub2_buf[G2_size];
	unsigned char *rx_buf = (unsigned char *) malloc(sizeof(unsigned char)*N*Fp_size);
	if (!mclBnFr_serialize(priv1_buf, Fp_size, &s1) || !mclBnFr_serialize(priv2_buf, Fp_size, &s2)) {
		printf("generate_keys: Error in serializing private keys\n");
		abort();
	}
	if (!mclBnG1_serialize(pub1_buf, G1_size, &H1_c) || !mclBnG2_serialize(pub2_buf, G2_size, &H2_c)) {
		printf("generate_keys: Error in serializing public keys\n");
		abort();
	}
	unsigned char *ptr = rx_buf;
	for (int i = 0; i < N; i++) {
		if (!mclBnFr_serialize(ptr, Fp_size, &rx[i])) {
			printf("generate_keys: Error in serializing rx\n");
			abort();
		}
		ptr += Fp_size;
	}

	buf2file(priv_filename, priv1_buf, Fp_size);
	buf2file_app(priv_filename, priv2_buf, Fp_size);
	
	buf2file(pub_filename, pub1_buf, G1_size);
	buf2file_app(pub_filename, pub2_buf, G2_size);

	buf2file(rx_filename, rx_buf, N*Fp_size);

}

/**
	(client) load client saved private and public keys, in addition to rx
*/
int load_keys(unsigned char *priv_filename, unsigned char *pub_filename, unsigned char *rx_filename) {
	unsigned char priv_buf[Fp_size+Fp_size], pub_buf[G1_size+G2_size];
	unsigned char *rx_buf = (unsigned char *) malloc(sizeof(unsigned char)*N*Fp_size);

	file2buf(priv_filename, priv_buf, Fp_size+Fp_size);
	file2buf(pub_filename, pub_buf, G1_size+G2_size);
	file2buf(rx_filename, rx_buf, N*Fp_size);

	if (!mclBnFr_deserialize(&s1, priv_buf, Fp_size) || !mclBnFr_deserialize(&s2, priv_buf+Fp_size, Fp_size)) {
		printf("load_keys: Error in deserializing private keys\n");
		abort();
	}

	if (!mclBnG1_deserialize(&H1_c, pub_buf, G1_size) || !mclBnG2_deserialize(&H2_c, pub_buf+G1_size, G2_size)) {
		printf("load_keys: Error in deserializing public keys\n");
		abort();
	}
	rx = (mclBnFr *) malloc(N*sizeof(mclBnFr));
	unsigned char *ptr = rx_buf;
	for (int i = 0; i < N; i++) {
		if (!mclBnFr_deserialize(&rx[i], rx_buf, Fp_size)) {
			printf("load_keys: Error in deserializing public keys\n");
			abort();
		}
		rx_buf += Fp_size;
	}

}

// (client) creates new client: deserialize G1, G2, generate new keys, save all parameters to files
int new_client(unsigned char *id_G1_G2_buf, unsigned char *id_G1_G2_file, unsigned char *priv_filename, unsigned char *pub_filename, unsigned char *rx_filename) {
	
	memcpy(ID_c, id_G1_G2_buf, 20);

	if (!mclBnG1_deserialize(&G1_c, id_G1_G2_buf+20, G1_size) || !mclBnG2_deserialize(&G2_c, id_G1_G2_buf+20+G1_size, G2_size)) {
		printf("new_client: Error in deserialization\n");
		abort();
	}

	mclBn_pairing(&z_c, &G1_c, &G2_c);

	//save G1 and G2 to file
	buf2file(id_G1_G2_file, id_G1_G2_buf, 20+G1_size+G2_size);
	generate_keys(priv_filename, pub_filename, rx_filename);
}

// (client) read files and get G1, G2, s1, s2, H1_c, H2_c, rx
int load_client(unsigned char *id_G1_G2_file, unsigned char *priv_filename, unsigned char *pub_filename, unsigned char *rx_filename) {
	unsigned char buf[20+G1_size+G2_size];
	file2buf(id_G1_G2_file, buf, 20+G1_size+G2_size);
	memcpy(ID_c, buf, 20);
	if (!mclBnG1_deserialize(&G1_c, buf+20, G1_size) || !mclBnG2_deserialize(&G2_c, buf+20+G1_size, G2_size)) {
		printf("load_server: Error in deserializing\n");
		abort();
	}
	mclBn_pairing(&z_c, &G1_c, &G2_c);
	load_keys(priv_filename, pub_filename, rx_filename);
}

/**
	(client) return Enc_1(x+rx)|Enc_2(x+rx)
	@param x feature vector
*/
void set_x_get_Enc_X(unsigned char *x, unsigned char *Enc_X_buf) {

	// TODO to delete //////////////////////
	// printf("set_x_get_Enc_X: x= ");
	// print_buf(x, N);
	// printf("N=%d\n", N);
	// for (int i = 0; i < 10; i++)
	// 	printf("set_x_get_Enc_X: x[%d]= %d\n", i, (unsigned char) x[i]);
	////////////////////////////////////////

	mclBnFr m, r1;
	mclBnG1 P;
	mclBnG2 Q;
	mclBnG1 *X1_c = (mclBnG1 *) malloc(2*N*sizeof(mclBnG1));	// encrypted feature vector X in G1
	mclBnG2 *X2_c = (mclBnG2 *) malloc(2*N*sizeof(mclBnG2));	// encrypted feature vector X in G2
	// G1
	int j = 0;
	#pragma omp parallel for
	for (int i = 0; i < N; i++) {
		mclBnFr_setByCSPRNG(&r1);
		mclBnFr_setInt(&m, (unsigned char) x[i]);
		mclBnFr_add(&m, &m, &rx[i]);
		mclBnG1_mul(&X1_c[j++], &G1_c, &r1);
		mclBnG1_mul(&X1_c[j], &H1_c, &r1);
		mclBnG1_mul(&P, &G1_c, &m);
		mclBnG1_add(&X1_c[j], &X1_c[j], &P);
		j++;
	}

	// G2
	j = 0;
	#pragma omp parallel for
	for (int i = 0; i < N; i++) {
		mclBnFr_setByCSPRNG(&r1);
		mclBnFr_setInt(&m, (unsigned char) x[i]);
		mclBnFr_add(&m, &m, &rx[i]);
		mclBnG2_mul(&X2_c[j++], &G2_c, &r1);
		mclBnG2_mul(&X2_c[j], &H2_c, &r1);
		mclBnG2_mul(&Q, &G2_c, &m);
		mclBnG2_add(&X2_c[j], &X2_c[j], &Q);
		j++;
	}

	// serialize X1_c and X2_c into Enc_X_buf
	unsigned char *ptr = Enc_X_buf;
	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG1_serialize(ptr, G1_size, &X1_c[i])) {
			printf("set_x_get_Enc1_X: Error in serialization\n");
			abort();
		}
		ptr += G1_size;
	}
	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG2_serialize(ptr, G2_size, &X2_c[i])) {
			printf("set_x_get_Enc1_X: Error in serialization\n");
			abort();
		}
		ptr += G2_size;
	}
}

/**
	(client) set y and compute Enc1(y), Enc2(y)
	@param Enc_minus_Y_buf: Y1|Y2
	@note Enc_minus_Y_buf must be allocated outside (size: 2*N*(G1_size+G2_size))
*/
void set_y_get_Enc_minus_Y(unsigned char *y, unsigned char *Enc_minus_Y_buf) {

	// TODO to delete //////////////////////
	// printf("set_y_get_Enc_minus_Y: y= ");
	// print_buf(y, N);
	////////////////////////////////////////

	mclBnFr m, r1;
	mclBnG1 P;
	mclBnG2 Q;
	mclBnG1 *Y1_c = (mclBnG1 *) malloc(2*N*sizeof(mclBnG1));;	// encrypted feature vector Y in G1
	mclBnG2 *Y2_c = (mclBnG2 *) malloc(2*N*sizeof(mclBnG2));;	// encrypted feature vector Y in G2
	// G1
	int j = 0;
	#pragma omp parallel for
	for (int i = 0; i < N; i++) {
		mclBnFr_setByCSPRNG(&r1);
		mclBnFr_setInt(&m, y[i]);
		mclBnFr_add(&m, &m, &rx[i]);
		mclBnFr_neg(&m, &m);
		mclBnG1_mul(&Y1_c[j++], &G1_c, &r1);
		mclBnG1_mul(&Y1_c[j], &H1_c, &r1);
		mclBnG1_mul(&P, &G1_c, &m);
		mclBnG1_add(&Y1_c[j], &Y1_c[j], &P);
		j++;
	}
	// G2
	j = 0;
	#pragma omp parallel for
	for (int i = 0; i < N; i++) {
		mclBnFr_setByCSPRNG(&r1);
		mclBnFr_setInt(&m, (unsigned char) y[i]);
		mclBnFr_add(&m, &m, &rx[i]);
		mclBnFr_neg(&m, &m);
		mclBnG2_mul(&Y2_c[j++], &G2_c, &r1);
		mclBnG2_mul(&Y2_c[j], &H2_c, &r1);
		mclBnG2_mul(&Q, &G2_c, &m);
		mclBnG2_add(&Y2_c[j], &Y2_c[j], &Q);
		j++;
	}
	// serialize Y1_c and Y2_c into Enc_minus_Y_buf
	unsigned char *ptr = Enc_minus_Y_buf;
	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG1_serialize(ptr, G1_size, &Y1_c[i])) {
			printf("set_y_get_Enc_minus_Y: Error in serialization\n");
			abort();
		}
		ptr += G1_size;
	}
	#pragma omp parallel for
	for (int i = 0; i < 2*N; i++) {
		if (!mclBnG2_serialize(ptr, G2_size, &Y2_c[i])) {
			printf("set_y_get_Enc_minus_Y: Error in serialization\n");
			abort();
		}
		ptr += G2_size;
	}

}

/**
	(server) get client encrypted score
	@param out_buf: h1|h2|h3|c4
	@note out_buf must be allocated outside (size: GT_size*4)
*/
void get_client_encrypted_score(unsigned char *out_buf) {
	unsigned char *ptr = out_buf;

	client_s* client = &clients_table[0];

	mclBnGT_serialize(ptr, GT_size, &client->h1_s);		ptr+=GT_size;
	mclBnGT_serialize(ptr, GT_size, &client->h2_s);		ptr+=GT_size;
	mclBnGT_serialize(ptr, GT_size, &client->h3_s);		ptr+=GT_size;
	mclBnGT_serialize(ptr, GT_size, &client->c4_s);
}

/**
	(server) set client encrypted score
	@param in_buf: h1|h2|h3|c4
*/
void set_client_encrypted_score(unsigned char *in_buf) {
	unsigned char *ptr = in_buf;

	client_s* client = &clients_table[0];

	mclBnGT_deserialize(&client->h1_s, ptr, GT_size);		ptr+=GT_size;
	mclBnGT_deserialize(&client->h2_s, ptr, GT_size);		ptr+=GT_size;
	mclBnGT_deserialize(&client->h3_s, ptr, GT_size);		ptr+=GT_size;
	mclBnGT_deserialize(&client->c4_s, ptr, GT_size);
	client->client_enc_score_set = true;
}

/**
 * @brief To be used to generate threads in function check_client_authentication
 */
void *sub_func(void *vargp) {
	sub_func_vars *parameters = (sub_func_vars *) vargp;
	int start = parameters->thread_index * server_elems_per_thread;
	int end = (parameters->thread_index != server_t - 1) ? start + server_elems_per_thread : N;

	unsigned char *ptr_Y1 = parameters->Y1_Y2_buf + start*2*G1_size;
	unsigned char *ptr_Y2 = parameters->Y1_Y2_buf + 2*N*G1_size + start*2*G2_size;

	mclBnG1 C1, C2, Y1;
	mclBnG2 C3, C4, Y2;
	
	for (int i = start; i < end; i++) {
		mclBnG1_deserialize(&Y1, ptr_Y1, G1_size);
		mclBnG2_deserialize(&Y2, ptr_Y2, G2_size);
		mclBnG1_add(&C1, &parameters->client->X1_s[i*2], &Y1);
		mclBnG2_add(&C3, &parameters->client->X2_s[i*2], &Y2);
		ptr_Y1 += G1_size;
		ptr_Y2 += G2_size;
		mclBnG1_deserialize(&Y1, ptr_Y1, G1_size);
		mclBnG2_deserialize(&Y2, ptr_Y2, G2_size);
		mclBnG1_add(&C2, &parameters->client->X1_s[i*2+1], &Y1);
		mclBnG2_add(&C4, &parameters->client->X2_s[i*2+1], &Y2);
		ptr_Y1 += G1_size;
		ptr_Y2 += G2_size;
		mclBn_pairing(&parameters->e1[i], &C1, &C3);
		mclBn_pairing(&parameters->e2[i], &C1, &C4);
		mclBn_pairing(&parameters->e3[i], &C2, &C3);
		mclBn_pairing(&parameters->e4[i], &C2, &C4);
	}

}

/**
	(server) check client authentication
	@param in_buf: ID|Y1|Y2
	@param out_buf: h1|h2|h3
	@note out_buf must be allocated outside (size: GT_size*3)
*/
void check_client_authentication(unsigned char *in_buf, unsigned char *out_buf) {

	client_s* client = &clients_table[0];	// TODO change 0 to index

	assert (client->client_info_set == true);

	unsigned char *Y1_Y2_buf = in_buf + 20;
	// memcpy(ID_s, ptr, 20);	// TODO get client's info from his ID
	// ptr += 20;

	mclBnGT e1[N], e2[N], e3[N], e4[N];

	sub_func_vars args[MAXTHREADS];
	pthread_t tid[MAXTHREADS];
	for (int v=0; v<server_t; v++) {
		sub_func_vars new_vars = {v, Y1_Y2_buf, e1, e2, e3, e4, client};
		args[v] = new_vars;
		pthread_create(&tid[v], NULL, sub_func, &args[v]);
	}
	for (int v=0; v<server_t; v++)
		pthread_join(tid[v], NULL);

	for (int i = 0; i < N; i++) {
		if (i == 0) {
			client->h1_s = e1[0];
			client->h2_s = e2[0];
			client->h3_s = e3[0];
			client->c4_s = e4[0];
		} else {
			mclBnGT_mul(&client->h1_s, &client->h1_s, &e1[i]);
			mclBnGT_mul(&client->h2_s, &client->h2_s, &e2[i]);
			mclBnGT_mul(&client->h3_s, &client->h3_s, &e3[i]);
			mclBnGT_mul(&client->c4_s, &client->c4_s, &e4[i]);
		}
	}

	// serialize h1, h2, and h3 into out_buf
	if (!mclBnGT_serialize(out_buf, GT_size, &client->h1_s) ||
		!mclBnGT_serialize(out_buf+GT_size, GT_size, &client->h2_s) ||
		!mclBnGT_serialize(out_buf+2*GT_size, GT_size, &client->h3_s)) {
			printf("check_client_authentication: Error in serialization\n");
			abort();
		}

	client->client_enc_score_set = true;

}

/**
	(client) client partially decrypts the server reply and computes non-interactive ZKPs
	@param in_buf: h1|h2|h3
	@param out_buf: c1|c2|c3|a[0]|a[1]|a[2]|c[0]|c[1]|c[2]|res[0]|res[1]|res[2]
	@note out_buf must be allocated outside (size: 6*GT_size+6*Fp_size)
*/
void partially_decrypt(unsigned char *in_buf, unsigned char *out_buf) {

	// deserializing in_buf
	mclBnGT c1, c2, c3, h1_c, h2_c, h3_c;
	mclBnFr m;
	if (!mclBnGT_deserialize(&h1_c, in_buf, GT_size) ||
		!mclBnGT_deserialize(&h2_c, in_buf+GT_size, GT_size) ||
		!mclBnGT_deserialize(&h3_c, in_buf+2*GT_size, GT_size)) {
			printf("partially_decrypt: Error in deserialization\n");
			abort();
		}

	// partially decrypt h1, h2, h3
	mclBnFr_mul(&m, &s1, &s2);
	mclBnGT_pow(&c1, &h1_c, &m);
	mclBnFr_neg(&m, &s1);
	mclBnGT_pow(&c2, &h2_c, &m);
	mclBnFr_neg(&m, &s2);
	mclBnGT_pow(&c3, &h3_c, &m);

	// compute 3 commitments (1 for each of c1, c2, c3)
	mclBnFr *u = (mclBnFr *) malloc(3*sizeof(mclBnFr)); // random values for client's commitments -- 1 for each of 3 ciphertexts
	mclBnGT *a = (mclBnGT *) malloc(3*sizeof(mclBnGT)); // random points for client's commitments -- 1 for each of 3 ciphertexts
	mclBnFr_setByCSPRNG(&u[0]);
	mclBnGT_pow(&a[0], &h1_c, &u[0]);
	mclBnFr_setByCSPRNG(&u[1]);
	mclBnGT_pow(&a[1], &h2_c, &u[1]);
	mclBnFr_setByCSPRNG(&u[2]);
	mclBnGT_pow(&a[2], &h3_c, &u[2]);
	
	// compute the random challenges from the commitments
	unsigned char buf[GT_size], md[512/8];
	mclBnFr *c = (mclBnFr *) malloc(3*sizeof(mclBnFr)); // random values for challenges -- 1 for each of 3 ciphertexts
	mclBnGT_serialize(buf, GT_size, &a[0]);
	SHA512(buf, GT_size, md);
	mclBnFr_setLittleEndian(&c[0], buf, 64);
	mclBnGT_serialize(buf, GT_size, &a[1]);
	SHA512(buf, GT_size, md);
	mclBnFr_setLittleEndian(&c[1], buf, 64);
	mclBnGT_serialize(buf, GT_size, &a[2]);
	SHA512(buf, GT_size, md);
	mclBnFr_setLittleEndian(&c[2], buf, 64);
	
	// compute responses
	mclBnFr *res = (mclBnFr *) malloc(3*sizeof(mclBnFr)); // random values for client's reponses -- 1 for each of 3 ciphertexts
	mclBnFr_mul(&m, &s1, &s2);
	mclBnFr_mul(&res[0], &c[0], &m);
	mclBnFr_add(&res[0], &res[0], &u[0]);
	mclBnFr_neg(&m, &s1);
	mclBnFr_mul(&res[1], &c[1], &m);
	mclBnFr_add(&res[1], &res[1], &u[1]);
	mclBnFr_neg(&m, &s2);
	mclBnFr_mul(&res[2], &c[2], &m);
	mclBnFr_add(&res[2], &res[2], &u[2]);

	// serializing decs_ZKPs
	unsigned char *ptr = out_buf;
	mclBnGT_serialize(ptr, GT_size, &c1);	ptr += GT_size;
	mclBnGT_serialize(ptr, GT_size, &c2);	ptr += GT_size;
	mclBnGT_serialize(ptr, GT_size, &c3);	ptr += GT_size;
	mclBnGT_serialize(ptr, GT_size, &a[0]);	ptr += GT_size;
	mclBnGT_serialize(ptr, GT_size, &a[1]);	ptr += GT_size;
	mclBnGT_serialize(ptr, GT_size, &a[2]);	ptr += GT_size;
	mclBnFr_serialize(ptr, Fp_size, &c[0]);	ptr += Fp_size;
	mclBnFr_serialize(ptr, Fp_size, &c[1]);	ptr += Fp_size;
	mclBnFr_serialize(ptr, Fp_size, &c[2]);	ptr += Fp_size;
	mclBnFr_serialize(ptr, Fp_size, &res[0]);	ptr += Fp_size;
	mclBnFr_serialize(ptr, Fp_size, &res[1]);	ptr += Fp_size;
	mclBnFr_serialize(ptr, Fp_size, &res[2]);
}

/**
	(server) server verifies the ZKPs and decrypts the final score
	@param in_buf: c1|c2|c3|a[0]|a[1]|a[2]|c[0]|c[1]|c[2]|res[0]|res[1]|res[2]
	@return true of decryption successfull
*/
int server_decryption(unsigned char *in_buf, int decryption_table_max_value) {

	client_s* client = &clients_table[0];

	assert (client->client_info_set == true && client->client_enc_score_set == true);

	// deserializing in_buf
	mclBnGT c1, c2, c3;
	mclBnGT *a = (mclBnGT *) malloc(3*sizeof(mclBnGT));
	mclBnFr *c = (mclBnFr *) malloc(3*sizeof(mclBnFr));
	mclBnFr *res = (mclBnFr *) malloc(3*sizeof(mclBnFr));
	unsigned char *ptr = in_buf;
	mclBnGT_deserialize(&c1, ptr, GT_size);	ptr += GT_size;
	mclBnGT_deserialize(&c2, ptr, GT_size);	ptr += GT_size;
	mclBnGT_deserialize(&c3, ptr, GT_size);	ptr += GT_size;
	mclBnGT_deserialize(&a[0], ptr, GT_size);	ptr += GT_size;
	mclBnGT_deserialize(&a[1], ptr, GT_size);	ptr += GT_size;
	mclBnGT_deserialize(&a[2], ptr, GT_size);	ptr += GT_size;
	mclBnFr_deserialize(&c[0], ptr, GT_size);	ptr += Fp_size;
	mclBnFr_deserialize(&c[1], ptr, GT_size);	ptr += Fp_size;
	mclBnFr_deserialize(&c[2], ptr, GT_size);	ptr += Fp_size;
	mclBnFr_deserialize(&res[0], ptr, GT_size);	ptr += Fp_size;
	mclBnFr_deserialize(&res[1], ptr, GT_size);	ptr += Fp_size;
	mclBnFr_deserialize(&res[2], ptr, GT_size);	ptr += Fp_size;

	// verify ZKPs
	unsigned char buf[GT_size], md[512/8];
	mclBnGT e1, e2;
	mclBnGT_serialize(buf, GT_size, &a[0]);
	SHA512(buf, GT_size, md);
	// TODO verify that received_c[0](above) is equal to computed_c[0](bellow)
	mclBnFr_setLittleEndian(&c[0], buf, 64);
	mclBnGT_pow(&e1, &client->h1_s, &res[0]);
	mclBnGT_pow(&e2, &c1, &c[0]);
	mclBnGT_mul(&e2, &e2, &a[0]);
	if (!mclBnGT_isEqual(&e1, &e2)) {
		printf("server_decryption: Verification 1 failed...client cheated :(\n");
		return false;
	}
	mclBnGT_serialize(buf, GT_size, &a[1]);
	SHA512(buf, GT_size, md);
	// TODO verify that received_c[1](above) is equal to computed_c[1](bellow)
	mclBnFr_setLittleEndian(&c[1], buf, 64);
	mclBnGT_pow(&e1, &client->h2_s, &res[1]);
	mclBnGT_pow(&e2, &c2, &c[1]);
	mclBnGT_mul(&e2, &e2, &a[1]);
	if (!mclBnGT_isEqual(&e1, &e2)) {
		printf("server_decryption: Verification 2 failed...client cheated :(\n");
		return false;
	}
	mclBnGT_serialize(buf, GT_size, &a[2]);
	SHA512(buf, GT_size, md);
	// TODO verify that received_c[2](above) is equal to computed_c[2](bellow)
	mclBnFr_setLittleEndian(&c[2], buf, 64);
	mclBnGT_pow(&e1, &client->h3_s, &res[2]);
	mclBnGT_pow(&e2, &c3, &c[2]);
	mclBnGT_mul(&e2, &e2, &a[2]);
	if (!mclBnGT_isEqual(&e1, &e2)) {
		printf("server_decryption: Verification 3 failed...client cheated :(\n");
		return false;
	}

	// decrypt
	mclBnGT_mul(&c1, &c1, &c2);
	mclBnGT_mul(&c1, &c1, &c3);
	mclBnGT_mul(&c1, &c1, &client->c4_s);

	// check whether score < T by brute-forcing
	mclBnGT_serialize(buf, GT_size, &c1);

	int index = binsearch(buf, str, 0, decryption_table_max_value);

	// int index = brutefore_decrypt(buf, str, decryption_table_max_value);
	// printf("server_decryption: index=%d\n", index);	// TODO to delete!!!
	
	if (index < 0)
		return false;
	return true;
	
}

int precompute_lookup_table(int max_value) {
	mclBnFr m, r1;
	mclBnGT c1;

	// precompute discrete log results (server)
	// memory allocation for sorted array
	str = (unsigned char **) malloc(max_value*sizeof(unsigned char *));
	for (int i = 0; i < max_value; i++)
		str[i] = (unsigned char *) calloc(GT_size, sizeof(unsigned char));
	
	mclBnFr_setByCSPRNG(&r1);
	mclBnGT_pow(&c1, &z_s, &r1);
	mclBnFr_setInt(&m, 0);
	mclBnGT_pow(&c1, &z_s, &m);
	mclBnGT_serialize(str[0], GT_size, &c1);
	for (int i = 1; i < max_value; i++) {
		mclBnGT_mul(&c1, &z_s, &c1);
		mclBnGT_serialize(str[i], GT_size, &c1);
	}

	qsort(str, max_value, sizeof(unsigned char *), comp); // sort for binary search
}

int test() {

	prepare_system(1);

	new_server("files/server.data");
	// OR
	// load_server("files/server.data");
	precompute_lookup_table(158400);

	//Enrollment--------------------------------------------------------------------------------------------------------------------------------------------------

	unsigned char G1_G2_buf[G1_size+G2_size];
	get_serialized_G1_G2(G1_G2_buf);

	// SEND G1_G2_buf: SERVER -> CLIENT

	// TODO check if stored G1 and G2 are the same as the received ones. If so, load_client, else, new_client

	unsigned char id_G1_G2_buf[20+G1_size+G2_size];
	get_serialized_G1_G2(id_G1_G2_buf+20);

	new_client(id_G1_G2_buf, "files/client.data", "files/key.priv", "files/key.pub", "files/rx.data");
	// OR
	// load_client("files/client.data", "files/key.priv", "files/key.pub", "files/rx.data");

	// intitialize random feature vecor x (plaintext)
	unsigned char x[N]; // plaintext feature vectors
	for (int i = 0; i < N; i++)
		// x[i] = rand() % 256;
		x[i] = 1;

	unsigned char *client_enrol_buf = (unsigned char *) malloc(sizeof(unsigned char)*(20 + G1_size+G2_size + 2*N*(G1_size+G2_size)));	// ID_c|H1_c|H2_c|X1_c|X2_c
	memcpy(client_enrol_buf, "AAAAAAAAAAAAAAAAAAAA", 20);
	get_serialized_pub_keys(client_enrol_buf+20);

	set_x_get_Enc_X(x, client_enrol_buf+20+G1_size+G2_size);
	// OR
	// load_Enc_X(x, client_enrol_buf+20+G1_size+G2_size);

	// SEND client_enrol_buf: CLIENT -> SERVER

	// enrolling new client;
	set_client_info_from_buf(client_enrol_buf);
	save_enrolled_client("files/");
	//OR
	// load_enrolled_client("AAAAAAAAAAAAAAAAAAAA.data");

	//Authentication------------------------------------------------------------------------------------------------------------------------------------------------

	// intitialize random feature vector y (plaintext)
	unsigned char y[N]; // plaintext feature vectors
	for (int i = 0; i < N; i++)
		if (x[i] < 250)
			y[i] = (x[i] + rand() % 5) % 256;
		else
			y[i] = x[i];

	int score = 0;
	for (int i = 0; i < N; i++)
		score += ((int)(x[i])-(int)(y[i]))*((int)(x[i])-(int)(y[i]));
	printf("Actual squared distance: %d\n", score);
	

	// // compute encrypted vector -(Y+rx) in G1 and G2 (client)
	unsigned char *client_auth_buf = (unsigned char *) malloc(sizeof(unsigned char)*(20 + 2*N*(G1_size+G2_size)));	// ID_c|Y1_c|Y2_c
	memcpy(client_auth_buf, "AAAAAAAAAAAAAAAAAAAA", 20);
	set_y_get_Enc_minus_Y(y, client_auth_buf + 20);
	
	// SEND client_auth_buf: CLIENT -> SERVER

	unsigned char *server_auth_buf = (unsigned char *) malloc(sizeof(unsigned char)*3*GT_size);	// h1|h2|h3
	check_client_authentication(client_auth_buf, server_auth_buf);

	// SEND server_auth_buf: SERVER -> CLIENT
	
	unsigned char *client_ZKPs_challenges = (unsigned char *) malloc(sizeof(unsigned char)*(6*GT_size+6*Fp_size));	// c1|c2|c3|a[0]|a[1]|a[2]|c[0]|c[1]|c[2]|res[0]|res[1]|res[2]
	partially_decrypt(server_auth_buf, client_ZKPs_challenges);

	// SEND client_ZKPs_challenges: CLIENT -> SERVER

	if (server_decryption(client_ZKPs_challenges, 158400))	printf("Success!!\n");
	else	printf("Fail :(\n");

	return 0;

}

int main() {
	test();
}