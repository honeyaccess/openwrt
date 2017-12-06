#!/bin/bash

OPENWRT=$(realpath $(dirname $0)/..)

echo $OPENWRT

STAGING_DIR=$OPENWRT/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/
export PATH=$STAGING_DIR/bin:$OPENWRT/staging_dir/host/bin:$OPENWRT/scripts:$PATH
export LIB_TOOL_DIR=$STAGING_DIR/lib
export LIB_TARGET_DIR=$STAGING_DIR/usr/lib
export CPLUS_TOOL_INCLUDE_PATH=$STAGIN_DIR/include
export CPLUS_TOOL_USR_INCLUDE_PATH=$STAGING_DIR/usr/include
export CPLUS_TARGET_INCLUDE_PATH=$STAGING_DIR/include
export CPLUS_TARGET_USR_INCLUDE_PATH=$STAGING_DIR/usr/include
export C_INCLUDE_PATH=$CPLUS_TARGET_USR_INCLUDE_PATH

export CC=mips-openwrt-linux-gcc
export CXX=mips-openwrt-linux-g++

export STRIP=$STAGING_DIR/mips-openwrt-linux-uclibc/bin/strip

export STAGING_DIR=$STAGING_DIR/bin


