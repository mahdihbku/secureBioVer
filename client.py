#!/usr/bin/env python2
import binascii
import utils
import argparse
import os
import sys
import numpy as np
np.set_printoptions(precision=2)
import socket
import cv2
from multiprocessing import Pool
from random import randint
import openface
import crypto_lib
import time

parser = argparse.ArgumentParser()
#Capturing options in order:
parser.add_argument('--enrolImage',			type=str,	default="",		help="Image to use for enrollment.")
parser.add_argument('--authImage',			type=str,	default="",		help="Image to use for authentication.")
parser.add_argument('--enrolDevice',		type=int,	default=-1,		help='Capturing device to be used for enrollment. 0 for latop webcam and 1 for usb webcam.')
parser.add_argument('--authDevice',			type=int,	default=-1,		help='Capturing device to be used for authentication. 0 for latop webcam and 1 for usb webcam.')
#Other parameters:
parser.add_argument('--dlibFacePredictor',	type=str,	default=os.path.join(utils.dlibModelDir, "shape_predictor_68_face_landmarks.dat"),	help="Path to dlib's face predictor.")
parser.add_argument('--networkModel',		type=str,	default=os.path.join(utils.openfaceModelDir, 'nn4.small2.v1.t7'),					help="Path to Torch network model.")
parser.add_argument('--imgDim',				type=int,	default=96,		help="Default image dimension.")
parser.add_argument('--serverPort',			type=int,	default=6546,	help="Port of the server.")
parser.add_argument('--serverIP',			type=str,	default="127.0.0.1", help="IP address of the server.")
parser.add_argument('--verbose',			type=int,	default=0,		help="Show more details(execution steps, times...).")
parser.add_argument('--width',				type=int,	default=640,	help='Width of frame.')
parser.add_argument('--height',				type=int,	default=480,	help='Height of frame.')
parser.add_argument('--dir',				type=str,	default="files/", help="Location of stored client information.")
parser.add_argument('--load',				help="Load stored client information from [dir].",	action='store_true')
args = parser.parse_args()

# System parameters
imgDim = args.imgDim
align = openface.AlignDlib(args.dlibFacePredictor)
net = openface.TorchNeuralNet(args.networkModel, imgDim)
server_ip = args.serverIP
server_port = args.serverPort
verbose = args.verbose
load = args.load
enroll = not (args.enrolImage == "" and args.enrolDevice == -1)
client_dir = args.dir
client_data_file = client_dir+"client.data"
priv_key_file = client_dir+"key.priv"
pub_key_file = client_dir+"key.pub"
rx_file = client_dir+"rx.data"

dim = 1024

# Temporary sets	# TODO delete
verbose = 0

def connectToServer():
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_address = (server_ip, server_port)
		sock.connect(server_address)
		return sock
	except socket.error as e:
		print('connectToServer: Connection error:', e)
		sys.exit(1)

if __name__ == '__main__':

	if (not enroll and not load):	# Client info must be given by enrollment or loaded from local files
		raise Exception("main: No enrollment information given. Use: --enrolImage, --enrolDevice, or --load")

	if verbose:	print("main: Connecting to server {}:{}...".format(server_ip, server_port))
	sock = connectToServer()
	if verbose:	print("main: Connected")

	message = "init"
	sock.sendall(message)
	if verbose:	print("main: Initialization message sent")

	if verbose:	print("main: Wating for G1_G2_buf...")
	G1_G2_buf = utils.recv_msg(sock)
	if verbose:	print("main: G1_G2_buf received")

	crypto_lib.prepare_system(1)

	# Enrollment-------------------------------------------------------------------------------------------
	# x = []
	if (enroll):
		enrol_start_time = time.time()
		x = []
		if args.enrolImage != "":
			print("main: Using image {} for enrollment...".format(args.enrolImage))
			x = utils.normalizeRep(utils.getLargestFaceRep(args.enrolImage, imgDim, align, net))
			# print(type(x))
			# print(len(x))
			if len(x) != dim:
				x.extend([0]*(dim-len(x)))
			# print(type(x))
			if len(x) == 0:
				raise Exception("main: Unable to load image: {}".format(args.enrolImage))
		elif args.enrolDevice != -1:
			print("main: Using camera for enrollment...")
			video_capture = cv2.VideoCapture(args.enrolDevice)
			video_capture.set(3, args.width)
			video_capture.set(4, args.height)
			while True:
				ret, frame = video_capture.read()
				repsAndBBs = utils.getAllFacesReps(frame, imgDim, align, net)
				if (repsAndBBs != None):
					reps = repsAndBBs[0]
					if (len(reps) == 0):	# no face in frame
						if args.verbose:	print("main: No face in the frame")
					else:	# face captured
						x = utils.normalizeRep(reps[0])
						if len(x) != dim :
							x.extend([0]*(dim-len(x)))
						print("main: Face captured!")
						break
		else:
			print("main: No source picture to use for enrollment. Quitting!")
			quit()

		serialized_x = utils.serializeRep(x)

		get_x_time = time.time()

		if verbose:	print("main: Generating enrollment message...")
		if not load:
			id = np.random.bytes(20)
			crypto_lib.new_client(id+G1_G2_buf, client_data_file, priv_key_file, pub_key_file, rx_file)
		else:
			crypto_lib.load_client(client_data_file, priv_key_file, pub_key_file, rx_file)

		f = open(client_data_file, "rb")
		id = f.read(20)
		if verbose:	print("main: My id: {}".format(binascii.hexlify(id).upper()))
		pub_keys_buf = crypto_lib.get_serialized_pub_keys()

		loading_client_time = time.time()

		Enc_X_buf = crypto_lib.set_x_get_Enc_X(serialized_x)



		encryption_done_time = time.time()

		client_enrol_buf = id + pub_keys_buf + Enc_X_buf
		if verbose:	print("main: Enrollment message generated")

		if verbose:	print("main: Sending enrollment message...")
		message = 'enrl'
		sock.sendall(message)
		utils.send_msg(sock, client_enrol_buf)
		if verbose:	print("main: Enrollment message sent")
		enrol_end_time = time.time()
		print("main: Generating feature vector time = {} ms".format((get_x_time-enrol_start_time)*1000))
		print("main: Loading client info time = {} ms".format((loading_client_time-get_x_time)*1000))
		print("main: Encryption time = {} ms".format((encryption_done_time-loading_client_time)*1000))
		print("main: Total enrollment time = {} ms".format((enrol_end_time-enrol_start_time)*1000))

	# Authentication----------------------------------------------------------------------------------------

	auth_start_time = time.time()
	if load:
		crypto_lib.load_client(client_data_file, priv_key_file, pub_key_file, rx_file)

	f = open(client_data_file, "rb")
	id = f.read(20)

	loading_client_time = time.time()

	if verbose:	print("main: My loaded id: {}".format(binascii.hexlify(id).upper()))
	if verbose:	print("main: Generating authentication message...")
	y = []
	if args.authImage != "":
		print("main: Using image {} for authentication...".format(args.authImage))
		y = utils.normalizeRep(utils.getLargestFaceRep(args.authImage, imgDim, align, net))
		if len(y) != dim :
			y.extend([0]*(dim-len(y)))
		if len(y) == 0:
			raise Exception("main: Unable to load image: {}".format(args.authImage))
	elif args.authDevice != -1:
		print("main: Using camera for authentication...")
		video_capture = cv2.VideoCapture(args.authDevice)
		video_capture.set(3, args.width)
		video_capture.set(4, args.height)
		while True:
			ret, frame = video_capture.read()
			repsAndBBs = utils.getAllFacesReps(frame, imgDim, align, net)
			if (repsAndBBs != None):
				reps = repsAndBBs[0]
				if (len(reps) == 0):	# no face in frame
					if args.verbose:	print("main: No face in the frame")
				else:	# face captured
					y = utils.normalizeRep(reps[0])
					if len(y) != dim :
						y.extend([0]*(dim-len(y)))
					print("main: Face captured!")
					break
	else:
		print("main: No source picture to use for authentication. Quitting!")
		quit()

	serialized_y = utils.serializeRep(y)

	get_y_time = time.time()

	Enc_minus_Y_buf = crypto_lib.set_y_get_Enc_minus_Y(serialized_y)

	encryption_done_time = time.time()

	client_auth_buf = id + Enc_minus_Y_buf
	if verbose:	print("main: Authentication message generated")
	
	if verbose:	print("main: Sending authentication message...")
	message = 'auth'
	sock.sendall(message)
	utils.send_msg(sock, client_auth_buf)
	if verbose:	print("main: Authentication message sent")

	if verbose:	print("main: Receiving server_auth_buf...")
	server_auth_buf = utils.recv_msg(sock)
	if verbose:	print("main: Authentication message received")

	zkp_start_time = time.time()

	if verbose:	print("main: Generating ZKPs_challenges message...")
	client_ZKPs_challenges = crypto_lib.partially_decrypt(server_auth_buf)

	zkp_end_time = time.time()


	message = 'ZKPs'
	sock.sendall(message)
	utils.send_msg(sock, client_ZKPs_challenges)
	if verbose:	print("main: ZKPs_challenges message sent")

	auth_end_time = time.time()

	print("main: Loading client info time = {} ms".format((loading_client_time-auth_start_time)*1000))
	print("main: Generating feature vector time = {} ms".format((get_y_time-loading_client_time)*1000))
	print("main: Encryption time = {} ms".format((encryption_done_time-get_y_time)*1000))
	print("main: Partial decryption time = {} ms".format((zkp_end_time-zkp_start_time)*1000))
	print("main: Total authentication time = {} ms".format((auth_end_time-auth_start_time)*1000))