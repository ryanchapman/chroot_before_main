#
# Makefile for chroot_before_main method
# Copyright (C) 2012 Ryan A. Chapman. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, 
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Where to install the library and dchroot binary
#prefix = /usr/local

PROGRAM = dchroot
CFILES = dchroot.c
CC = gcc
LD = gcc
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
libdir = ${exec_prefix}/lib

if COND_ROOT
ENABLE_ROOT = -DENABLE_ROOT
endif

if COND_CHROOT
ENABLE_CHROOT = -DENABLE_CHROOT
endif

all: chroot_before_main.so dchroot

chroot_before_main.so: chroot_before_main.c
	$(CC) $(ENABLE_ROOT) $(ENABLE_CHROOT) -shared -fomit-frame-pointer -fPIC -o chroot_before_main.so chroot_before_main.c

dchroot: dchroot.c
	$(CC) -D PATH_TO_SO="\"${libdir}/chroot_before_main.so\"" -o dchroot dchroot.c

install:
	install -o root -g root -m 0755 dchroot ${bindir}
	install -o root -g root -m 0755 chroot_before_main.so ${libdir}

clean:
	rm -f dchroot chroot_before_main.so
