import cv2
import os
import struct
import openface
import struct
from bitarray import bitarray
from bitarray.util import serialize, deserialize
import binascii

fileDir				= os.path.dirname(os.path.realpath(__file__))
modelDir			= os.path.join(fileDir, '../openface/', 'models')
suspectsDir			= os.path.join(fileDir, '../openface/', 'suspectsDir')
dlibModelDir		= os.path.join(modelDir, 'dlib')
openfaceModelDir	= os.path.join(modelDir, 'openface')

# System parameters
SMALL_MSG_SIZE = 4
normalizing_adder = 128
normalizing_multiplier = 400

# Get the representation of the largest face in the picture
def getLargestFaceRep(imgPath, imgDim, align, net):
	bgrImg = cv2.imread(imgPath)
	if bgrImg is None:
		return []
	rgbImg = cv2.cvtColor(bgrImg, cv2.COLOR_BGR2RGB)
	bb = align.getLargestFaceBoundingBox(rgbImg)
	if bb is None:
		return []
	alignedFace = align.align(imgDim, rgbImg, bb, landmarkIndices=openface.AlignDlib.OUTER_EYES_AND_NOSE)
	if alignedFace is None:
		return []
	rep = net.forward(alignedFace)
	return rep

# Get the rep and the bounding box of every detected face in the picture
def getAllFacesReps(bgrImg, imgDim, align, net):
    if bgrImg is None:
        return None
    rgbImg = cv2.cvtColor(bgrImg, cv2.COLOR_BGR2RGB)
    bb = align.getAllFaceBoundingBoxes(rgbImg)
    if bb is None:
        return None
    alignedFaces = []
    for box in bb:
        alignedFaces.append(align.align(imgDim, rgbImg, box, landmarkIndices=openface.AlignDlib.OUTER_EYES_AND_NOSE))
    if alignedFaces is None:
        return None
    reps = []
    for alignedFace in alignedFaces:
        reps.append(net.forward(alignedFace))
    return (reps,bb)

def normalizeRep(rep):
	normalizedRep = [int(x*normalizing_multiplier+normalizing_adder) for x in rep]
	for idx in range(len(rep)):
		if normalizedRep[idx] > 255:	normalizedRep[idx] = 255
		elif normalizedRep[idx] < 0:	normalizedRep[idx] = 0
	return normalizedRep

def serializeRep(normalized_rep):
	s = ''
	for idx in range(len(normalized_rep)):
		s += format(normalized_rep[idx], '02x')
	return binascii.a2b_hex(s)

def send_msg(sock, msg):
	# Prefix each message with a 4-byte length (network byte order)
	msg = struct.pack('>I', len(msg)) + msg
	sock.sendall(msg)

def recv_msg(sock):
	# Read message length and unpack it into an integer
	raw_msglen = recvall(sock, 4)
	if not raw_msglen:
		return None
	msglen = struct.unpack('>I', raw_msglen)[0]
	# Read the message data
	return recvall(sock, msglen)

def recvall(sock, n):
	# Helper function to recv n bytes or return None if EOF is hit
	data = b''
	while len(data) < n:
		packet = sock.recv(n - len(data))
		if not packet:
			return None
		data += packet
	return data
