#!/usr/bin/env python2
import time
import utils
import argparse
import numpy as np
np.set_printoptions(precision=2)
import socket
from multiprocessing import Pool
from random import randint
import binascii

parser = argparse.ArgumentParser()
parser.add_argument('--working_dir',		type=str,	help="Path to directory containing working files.",	default="files/"	)
parser.add_argument('--server_info_file',	type=str,	help="File containing stored server info.",			default="server.data")
parser.add_argument('--serverPort',			type=int,	help="Port of the server.",							default=6546		)
parser.add_argument('--serverIP',			type=str,	help="IP of the server.",							default='127.0.0.1'	)
parser.add_argument('--threshold',			type=float,	help="Similarity threshold.",						default=0.99		)
parser.add_argument('--CPUs',				type=int,	help="Number of parallel CPUs to be used.",			default=4			)
parser.add_argument('--verbose',			help="Show more information.", 									action='store_true'	)
parser.add_argument('--load',				help="Load stored server information from [server_info_file].",	action='store_true'	)
args = parser.parse_args()

# System parameters
server_ip 	= args.serverIP
server_port = args.serverPort
nbr_of_CPUs = args.CPUs
verbose 	= args.verbose
working_dir = args.working_dir
server_file = working_dir + args.server_info_file
threshold 	= (int) (args.threshold * utils.normalizing_multiplier * utils.normalizing_multiplier)
print("threshold= {}".format(threshold))

# Temporary setup	# TODO to delete
verbose = 0

# TODO change place
import crypto_lib
crypto_lib.prepare_system(nbr_of_CPUs)
if args.load:
	crypto_lib.load_server(server_file)
else:
	crypto_lib.new_server(server_file)

crypto_lib.precompute_lookup_table(threshold)

G1_G2_buf = crypto_lib.get_serialized_G1_G2()

def serveClient(connection, client_address):
	client_set = False
	try:
		while True:
			if verbose:	print("serveClient: Wating for data from client {}...".format(client_address))
			data = utils.recvall(connection, utils.SMALL_MSG_SIZE)
			print("serveClient: Received: {}".format(data))
			if data:

				if (data == "init"):
					if verbose:	print("serveClient: Received initialization message from client {}".format(client_address))
					utils.send_msg(connection, G1_G2_buf)
					if verbose:	print("serveClient: G1_G2_buf sent to client {}".format(client_address))
				
				if (data == "enrl"):
					if verbose:	print("serveClient: Received enrollment message from client {}".format(client_address))
					client_enrol_buf = utils.recv_msg(connection)

					enrl_start_time = time.time()

					client_id  = binascii.hexlify(client_enrol_buf[:20]).upper()
					crypto_lib.set_client_info_from_buf(client_enrol_buf)
					crypto_lib.save_enrolled_client(working_dir)
					client_set = True

					enrl_end_time = time.time()

					if verbose:	print("serveClient: Client {} enrolled successfully".format(client_id))
					if verbose:	print("serveClient: Client info saved in: {}".format(working_dir+client_id+".data"))

					print("serveClient: Enrollment time = {} ms".format((enrl_end_time-enrl_start_time)*1000))
				
				if (data == "auth"):
					if verbose:	print("serveClient: Received authentication message from client {}".format(client_address))
					client_auth_buf = utils.recv_msg(connection)

					auth_start_time = time.time()

					client_id  = binascii.hexlify(client_auth_buf[:20]).upper()
					if verbose:	print("serveClient: Client id: {}".format(client_id))
					if not client_set:
						client_info_file  = working_dir + client_id + ".data"
						crypto_lib.load_enrolled_client(client_info_file)
						client_set = True
						if verbose:	print("serveClient: Client info loaded successfully from: {}".format(client_info_file))
					
					loading_done_time = time.time()
					
					server_auth_buf = crypto_lib.check_client_authentication(client_auth_buf)

					auth_end_time = time.time()

					print("serveClient: Loading client info time = {} ms".format((loading_done_time-auth_start_time)*1000))
					print("serveClient: Authentication reply generation time = {} ms".format((auth_end_time-loading_done_time)*1000))

					utils.send_msg(connection, server_auth_buf)
					if verbose:	print("serveClient: ZKPs_challenges sent to client {}".format(client_address))
				
				if (data == "ZKPs"):
					if verbose:	print("serveClient: Received ZKP challenges message from client {}".format(client_address))
					client_ZKPs_challenges = utils.recv_msg(connection)

					dec_start_time = time.time()

					if (crypto_lib.server_decryption(client_ZKPs_challenges, threshold)):
						print("+ Authentication successful (client {} on {})".format(client_id, client_address))
					else:
						print("- Authentication failed ! (client {} on {})".format(client_id, client_address))

					dec_end_time = time.time()
					print("serveClient: Decryption time = {} ms".format((dec_end_time-dec_start_time)*1000))

			else:
				print("serveClient: No more data from client {}".format(client_address))
				break
	finally:
		connection.close()
		print("serveClient: Connection closed with client {}".format(client_address))

def waitForClients():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = (server_ip, server_port)
	sock.bind(server_address)
	sock.listen(10)
	while True:
		print("waitForClients: Waiting for incoming connections on port {}...".format(server_port))
		connection, client_address = sock.accept()
		print("waitForClients: New connection from client {}".format(client_address))
		serveClient(connection, client_address)

if __name__ == '__main__':
    waitForClients()