#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

# Helpful defines for the provisioning process.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$SCRIPT_DIR/../build"
FORMULA_DIR="$SCRIPT_DIR/provision/formula"

HOMEBREW_REPO="https://github.com/Homebrew/brew"
LINUXBREW_REPO="https://github.com/Linuxbrew/brew"

# Set the SHA1 commit hashes for the pinned homebrew Taps.
# Pinning allows determinism for bottle availability, expect to update often.
HOMEBREW_CORE="0e6f293450cf9b54e324e92ea0b0475fd4e0d929"
LINUXBREW_CORE="600e1460c79b9cf6945e87cb5374b9202db1f6a9"
HOMEBREW_DUPES="00df450f28f23aa1013564889d11440ab80b36a5"
LINUXBREW_DUPES="83cad3d474e6d245cd543521061bba976529e5df"

source "$SCRIPT_DIR/lib.sh"
source "$SCRIPT_DIR/provision/lib.sh"

function platform_linux_main() {
  brew_uninstall bison

  # GCC 5x bootstrapping.
  brew_tool patchelf
  brew_tool zlib
  brew_tool binutils
  brew_tool linux-headers
  brew_tool gmp
  brew_tool mpfr
  brew_tool libmpc
  brew_tool isl
  brew_tool pkg-config

  # Build a bottle of a modern glibc.
  brew_tool osquery/osquery-local/glibc

  # Build a bottle for a legacy glibc.
  brew_tool osquery/osquery-local/glibc-legacy

  # GCC 5x.
  brew_tool osquery/osquery-local/gcc

  # Need LZMA for final builds.
  brew_tool osquery/osquery-local/zlib-legacy
  brew_tool osquery/osquery-local/xz
  brew_tool osquery/osquery-local/ncurses
  brew_tool osquery/osquery-local/bzip2

  brew_tool unzip
  brew_tool sqlite
  brew_tool makedepend
  brew_tool libidn
  brew_tool libedit
  brew_tool libtool
  brew_tool m4
  brew_tool autoconf
  brew_tool automake

  # OpenSSL is needed for the final build.
  brew_tool osquery/osquery-local/libxml2
  brew_clean osquery/osquery-local/curl
  brew_tool osquery/osquery-local/openssl

  # Curl and Python are needed for LLVM mostly.
  brew_tool osquery/osquery-local/curl
  brew_tool osquery/osquery-local/python
  brew_tool osquery/osquery-local/cmake --without-docs

  # Linux library secondary dependencies.
  brew_tool osquery/osquery-local/berkeley-db
  brew_tool osquery/osquery-local/popt
  brew_tool osquery/osquery-local/beecrypt

  # LLVM/Clang.
  brew_tool osquery/osquery-local/llvm

  # Util-Linux provides libuuid.
  brew_dependency osquery/osquery-local/util-linux

  platform_posix_main

  # General Linux dependencies and custom formulas for table implementations.
  brew_dependency osquery/osquery-local/libgpg-error
  brew_dependency osquery/osquery-local/libdevmapper
  brew_dependency osquery/osquery-local/libaptpkg
  brew_dependency osquery/osquery-local/libiptables
  brew_dependency osquery/osquery-local/libgcrypt
  brew_dependency osquery/osquery-local/libcryptsetup
  brew_dependency osquery/osquery-local/libudev
  brew_dependency osquery/osquery-local/libaudit
  brew_dependency osquery/osquery-local/libdpkg
  brew_dependency osquery/osquery-local/librpm

}

function platform_darwin_main() {
  brew_tool xz
  brew_tool readline
  brew_tool sqlite
  brew_tool makedepend
  brew_tool clang-format
  brew_tool pkg-config
  brew_tool bison
  brew_tool autoconf
  brew_tool automake
  brew_tool libtool

  brew_dependency osquery/osquery-local/libxml2
  brew_dependency osquery/osquery-local/openssl
  brew_tool osquery/osquery-local/python
  brew_tool osquery/osquery-local/cmake --without-docs

  platform_posix_main
}

 function platform_posix_main() {
  # List of LLVM-compiled dependencies.
  brew_dependency osquery/osquery-local/lz4
  brew_dependency osquery/osquery-local/libmagic
  brew_dependency osquery/osquery-local/pcre
  brew_dependency osquery/osquery-local/boost
  brew_dependency osquery/osquery-local/asio
  brew_dependency osquery/osquery-local/cpp-netlib
  brew_dependency osquery/osquery-local/google-benchmark
  brew_dependency osquery/osquery-local/snappy
  brew_dependency osquery/osquery-local/sleuthkit
  brew_dependency osquery/osquery-local/thrift
  brew_dependency osquery/osquery-local/rocksdb
  brew_dependency osquery/osquery-local/gflags
  brew_dependency osquery/osquery-local/aws-sdk-cpp
  brew_dependency osquery/osquery-local/yara
  brew_dependency osquery/osquery-local/glog
  brew_dependency osquery/osquery-local/linenoise-ng
  brew_dependency osquery/osquery-local/augeas

  # POSIX-shared locally-managed tools.
  brew_dependency osquery/osquery-local/zzuf
  brew_dependency osquery/osquery-local/cppcheck
  brew_dependency osquery/osquery-local/ccache
}

function sysprep() {
  RUN_SYSPREP=false
  if [[ ! -z "$SKIP_DISTRO_MAIN" ]]; then
    if [[ "$SKIP_DISTRO_MAIN" = "False" || "$SKIP_DISTRO_MAIN" = "0" ]]; then
      RUN_SYSPREP=true
    fi
  fi

  if [[ ! "$RUN_SYSPREP" = "true" ]]; then
    return
  fi

  # Each OS/Distro may have specific provisioning needs.
  # These scripts are optional and should installed the needed packages for:
  # 1. A basic ruby interpreter to run brew
  # 2. A GCC compiler to compile a modern glibc/GCC and legacy glibc.
  # 3. Curl, git, autotools, autopoint, and gawk.
  OS_SCRIPT="$SCRIPT_DIR/provision/$OS.sh"
  if [[ -f "$OS_SCRIPT" ]]; then
    log "found $OS provision script: $OS_SCRIPT"
    source "$OS_SCRIPT"
    if [[ "$1" = "build" ]]; then
      distro_main
    fi
  else
    log "your $OS does not use a provision script"
  fi
}

function main() {
  ACTION=$1

  platform OS
  distro $OS DISTRO
  threads THREADS

  if ! hash sudo 2>/dev/null; then
    echo "Please install sudo in this machine"
    exit 1
  fi

  # Setup the osquery dependency directory.
  # One can use a non-build location using OSQUERY_DEPS=/path/to/deps
  if [[ -e "$OSQUERY_DEPS" ]]; then
    DEPS_DIR="$OSQUERY_DEPS"
  else
    DEPS_DIR="/usr/local/osquery"
  fi

  if [[ "$ACTION" = "clean" ]]; then
    do_sudo rm -rf "$DEPS_DIR"
    return
  fi

  # Setup the local ./build/DISTRO cmake build directory.
  if [[ ! -z "$SUDO_USER" ]]; then
    echo "chown -h $SUDO_USER $BUILD_DIR/*"
    chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR" || true
    if [[ $OS = "linux" ]]; then
      chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR/linux" || true
    fi
    chown $SUDO_USER:$SUDO_GID "$WORKING_DIR" > /dev/null 2>&1 || true
  fi

  # Provisioning uses either Linux or Home (OS X) brew.
  if [[ $OS = "darwin" ]]; then
    BREW_TYPE="darwin"
  else
    BREW_TYPE="linux"
  fi

  sysprep $ACTION

  # The dependency directory (DEPS_DIR) will contain our legacy runtime glibc
  # and various compilers/library dependencies.
  if [[ ! -d "$DEPS_DIR" ]]; then
    log "creating build dir: $DEPS_DIR"
    do_sudo mkdir -p "$DEPS_DIR"
    do_sudo chown $USER "$DEPS_DIR" > /dev/null 2>&1 || true
  fi
  cd "$DEPS_DIR"
  # This will install a local tap using a symbol to the formula subdir here.
  export PATH="$DEPS_DIR/bin:$PATH"
  setup_brew "$DEPS_DIR" "$BREW_TYPE"

  if [[ "$ACTION" = "bottle" ]]; then
    brew_bottle "$2"
    return
  elif [[ "$ACTION" = "uninstall" ]]; then
    brew_uninstall "$2"
    return
  elif [[ "$ACTION" = "install" ]]; then
    brew_dependency "$2"
    return
  fi

  if [[ ! -z "$OSQUERY_BUILD_DEPS" ]]; then
    log "[notice]"
    log "[notice] you are choosing to build dependencies instead of installing"
    log "[notice]"
  fi

  log "running unified platform initialization"
  brew_clear_cache
  if [[ "$BREW_TYPE" = "darwin" ]]; then
    platform_darwin_main
  else
    platform_linux_main
  fi
  brew_clear_cache

  cd "$SCRIPT_DIR/../"

  # Additional compilations may occur for Python and Ruby
  export LIBRARY_PATH="$DEPS_DIR/legacy/lib:$DEPS_DIR/lib:$LIBRARY_PATH"

  # Pip may have just been installed.
  log "upgrading pip and installing python dependencies"
  PIP=`which pip`
  $PIP install --upgrade pip
  # Pip may change locations after upgrade.
  PIP=`which pip`
  $PIP install -I -r requirements.txt

  log "running auxiliary initialization"
  initialize $OS
}

<<<<<<< 65ecc2092d05a02dcd5d851da276f501cee5434a
=======
function platform_linux_main() {
  # GCC 5x bootstrapping.
  brew_tool patchelf
  brew_tool zlib
  brew_tool binutils
  brew_tool linux-headers

  # Build a bottle of a modern glibc.
  local_brew_tool glibc
  local_brew_postinstall glibc

  # Build a bottle for a legacy glibc.
  local_brew_tool glibc-legacy
  local_brew_unlink glibc-legacy
  local_brew_link glibc-legacy
  local_brew_postinstall glibc-legacy

  # Additional GCC 5x bootstrapping.
  brew_tool gmp
  brew_tool mpfr
  brew_tool libmpc
  brew_tool isl

  # GCC 5x.
  local_brew_tool gcc
  # Remove gcc-postinstall when GCC is next updated.
  local_brew_postinstall gcc
  set_deps_compilers gcc

  # Need LZMA for final builds.
  local_brew_tool zlib-legacy
  local_brew_tool xz

  # GCC-compiled (C) dependencies.
  brew_tool pkg-config

  # Build a bottle for ncurses
  local_brew_tool ncurses

  # Need BZIP/Readline for final build.
  local_brew_tool bzip2
  brew_tool unzip
  local_brew_tool readline
  brew_tool sqlite
  brew_tool makedepend
  brew_tool libidn

  # Build a bottle for perl and openssl.
  # OpenSSL is needed for the final build.
  # local_brew_tool perl -vd --without-test
  brew_clean curl
  local_brew_tool openssl
  local_brew_postinstall openssl
  local_brew_link openssl

  # LLVM dependencies.
  brew_tool libxml2
  brew_tool libedit
  brew_tool libtool
  brew_tool m4
  brew_tool bison

  # More LLVM dependencies.
  brew_tool autoconf
  brew_tool automake

  # Curl and Python are needed for LLVM mostly.
  local_brew_tool curl
  local_brew_tool python
  local_brew_postinstall python
  local_brew_tool cmake --without-docs

  # Linux library secondary dependencies.
  local_brew_tool berkeley-db
  local_brew_tool popt
  local_brew_tool beecrypt

  # LLVM/Clang.
  local_brew_tool llvm
  set_deps_compilers clang

  # General Linux dependencies.
  local_brew_dependency util-linux

  platform_posix_main

  local_brew_tool zzuf
  local_brew_tool cppcheck
  local_brew_tool ccache

  # Linux specific custom formulas.
  local_brew_dependency libgpg-error
  local_brew_dependency libdevmapper
  local_brew_dependency libaptpkg
  local_brew_dependency libiptables
  local_brew_dependency libgcrypt
  local_brew_dependency libcryptsetup
  local_brew_dependency libudev
  local_brew_dependency libaudit
  local_brew_dependency libdpkg
  local_brew_dependency librpm

  # Restore the compilers to GCC for the remainder of provisioning.
  set_deps_compilers gcc
}

function platform_darwin_main() {
  brew_tool xz
  brew_tool readline
  brew_tool sqlite
  brew_tool makedepend
  brew_tool clang-format

  local_brew_dependency openssl
  local_brew_postinstall openssl
  local_brew_link openssl

  brew_tool pkg-config
  brew_tool autoconf
  brew_tool automake
  brew_tool libtool
  brew_tool bison
  brew_link bison

  local_brew_tool python
  local_brew_postinstall python
  local_brew_tool cmake --without-docs

  platform_posix_main

  local_brew_tool zzuf
  local_brew_tool cppcheck
  local_brew_tool ccache
}

function platform_posix_main() {
  # Tar for acquisition
  local_brew_dependency libtar

  # List of LLVM-compiled dependencies.
  local_brew_dependency linenoise-ng
  local_brew_dependency boost
  local_brew_dependency asio
  local_brew_dependency cpp-netlib
  local_brew_dependency google-benchmark
  local_brew_dependency pcre
  local_brew_dependency lz4
  local_brew_dependency snappy
  local_brew_dependency sleuthkit
  local_brew_dependency libmagic
  local_brew_dependency thrift
  local_brew_dependency rocksdb
  local_brew_dependency gflags
  local_brew_dependency aws-sdk-cpp
  local_brew_dependency yara
  local_brew_dependency glog
}

>>>>>>> [carve] Add libtar to provision for OS X and Linux
check $1 "$2"
main $1 "$2"
