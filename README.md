# secureBioVer
A Practical System for Secure Biometric Authentication in the Presence
of Malicious Adversaries
## Installation
Requires [OpenFace](https://github.com/TadasBaltrusaitis/OpenFace)
```bash
git clone https://github.com/mahdihbku/secureBioVer
cd secureBioVer
./load_crypto_lib.sh
```
## Usage
Server:
```bash
./server.py
./server.py -h # for help
```
Camera:
```bash
./client.py --enrolImage /root/openface/images/examples/lennon-1.jpg --authImage /root/openface/images/examples/lennon-2.jpg
./clinet.py -h # for help
```
