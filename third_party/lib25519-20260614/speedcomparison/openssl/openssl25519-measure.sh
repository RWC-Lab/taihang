#!/bin/sh

# Prerequisites:
# * 64-bit CPU
# * Debian
# * packages: wget build-essential
# * dedicated account to run this script
# * openssl25519speed.c in the account's home directory

cd

export LD_LIBRARY_PATH="$HOME/lib:$HOME/lib64"
export LIBRARY_PATH="$HOME/lib:$HOME/lib64"
export CPATH="$HOME/include"
export PATH="$HOME/bin:$PATH"

[ -f $HOME/bin/cpucycles-info ] ||
(
  wget -m https://cpucycles.cr.yp.to/libcpucycles-latest-version.txt
  version=$(cat cpucycles.cr.yp.to/libcpucycles-latest-version.txt)
  wget -m https://cpucycles.cr.yp.to/libcpucycles-$version.tar.gz
  tar -xzf cpucycles.cr.yp.to/libcpucycles-$version.tar.gz
  cd libcpucycles-$version
  ./configure --prefix=$HOME && make -j8 install
)

opensslversion=4.0.1
( [ -f $HOME/lib*/libcrypto.so ] &&
  ( openssl version | grep OpenSSL.$opensslversion > /dev/null )
) ||
(
  wget https://www.openssl.org/source/openssl-$opensslversion.tar.gz
  tar -xf openssl-$opensslversion.tar.gz
  cd openssl-$opensslversion
  ./Configure --prefix=$HOME
  make
  make install
)

gcc -o openssl25519speed openssl25519speed.c \
-O3 -I include lib*/libcrypto.so lib/libcpucycles.so

taskset -c 0 ./openssl25519speed > openssl25519speed.out
