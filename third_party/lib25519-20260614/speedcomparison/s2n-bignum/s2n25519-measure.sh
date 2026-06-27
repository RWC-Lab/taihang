#!/bin/sh

# Prerequisites:
# * Intel/AMD or ARM CPU
# * Debian
# * packages: git wget build-essential
# * dedicated account to run this script
# * s2n25519speed.c in the account's home directory

cd

export LD_LIBRARY_PATH="$HOME/lib"
export LIBRARY_PATH="$HOME/lib"
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

[ -f $HOME/bin/randombytes-info ] ||
(
  wget -m https://randombytes.cr.yp.to/librandombytes-latest-version.txt
  version=$(cat randombytes.cr.yp.to/librandombytes-latest-version.txt)
  wget -m https://randombytes.cr.yp.to/librandombytes-$version.tar.gz
  tar -xzf randombytes.cr.yp.to/librandombytes-$version.tar.gz
  cd librandombytes-$version
  ./configure --prefix=$HOME && make -j8 install
)

[ -f $HOME/include/s2n-bignum.h ] ||
(
  git clone https://github.com/awslabs/s2n-bignum
  cd ./s2n-bignum
  git checkout fce78c7c17baee6a60511efe821930d4d049a6c0 # 2026-06-12
  if uname -m | grep 86 > /dev/null
  then
    cd x86
  else
    cd arm
  fi
  make
  mkdir -p $HOME/lib $HOME/include
  cp libs2nbignum.a $HOME/lib
  cp ../include/s2n-bignum.h $HOME/include
)

gcc -o s2n25519speed s2n25519speed.c \
-O3 -I include -ls2nbignum -lcpucycles -lrandombytes

taskset -c 0 ./s2n25519speed > s2n25519speed.out

gcc -o s2n25519speed-alt s2n25519speed.c \
-Dcurve25519_x25519_byte=curve25519_x25519_byte_alt \
-Dcurve25519_x25519base_byte=curve25519_x25519base_byte_alt \
-O3 -I include -ls2nbignum -lcpucycles -lrandombytes

taskset -c 0 ./s2n25519speed-alt > s2n25519speed-alt.out
