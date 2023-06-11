#!/bin/bash
MCL_LIB_PATH=/root/mcl/lib
export LD_LIBRARY_PATH=$MCL_LIB_PATH
swig -python crypto_lib.i
#gcc -c crypto_lib.c crypto_lib_wrap.c -std=c99 -L$MCL_LIB_PATH -lmclbn256 -lmcl -lcrypto -L$MCL_LIB_PATH -lmclbn256 -lmcl -I/usr/include/python2.7 -fPIC
#gcc -shared crypto_lib.o crypto_lib_wrap.o -L$MCL_LIB_PATH -lmclbn256 -lmcl -lcrypto -o _crypto_lib.so

gcc -c crypto_lib.c crypto_lib_wrap.c -std=c99 -L$MCL_LIB_PATH -lmclbn384_256 -lmcl -lcrypto -L$MCL_LIB_PATH -lmclbn384_256 -lmcl -I/usr/include/python2.7 -fPIC
gcc -shared crypto_lib.o crypto_lib_wrap.o -L$MCL_LIB_PATH -lmclbn384_256 -lmcl -lcrypto -o _crypto_lib.so

python setup.py build_ext --inplace
python -c "import crypto_lib; crypto_lib.prepare_system(1); crypto_lib.prepare_system(1); crypto_lib.test()"
