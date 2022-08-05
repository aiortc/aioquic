#!/bin/bash

# Copyright 2019, Akamai Technologies, Inc.
# Jake Holland <jholland@akamai.com>
#(MIT-licensed?)

set -e
set -x

# INSTALL_PATH=${HOME}/local_install
DEPS=$PWD/dependencies
mkdir -p "$DEPS"/build

if [ "${INSTALL_PATH}" != "" ]; then
  mkdir -p "${INSTALL_PATH}"
fi

if ! which cmake || ! which automake; then
  sudo apt-get update

  # libmcrx build requirements
  sudo apt-get install -y autoconf automake libtool
fi

if ! [ -e "$DEPS"/build/libmcrx/ ]; then
  git clone https://github.com/GrumpyOldTroll/libmcrx "$DEPS"/build/libmcrx
fi
pushd "$DEPS"/build/libmcrx
./autogen.sh
CONF_EXTRA=
if [ "${INSTALL_PATH}" != "" ]; then
  CONF_EXTRA="--prefix=${INSTALL_PATH}"
fi
# shellcheck disable=SC2086
./configure "${CONF_EXTRA}"
make
popd

pushd "$DEPS"/build/libmcrx && make install && popd

if [ "${INSTALL_PATH}" != "" ]; then
  echo "make sure LD_LIBRARY_PATH has ${INSTALL_PATH}/lib"
fi