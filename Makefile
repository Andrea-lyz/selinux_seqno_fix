# SPDX-License-Identifier: GPL-2.0
#
# Wrapper Makefile for out-of-tree builds. The actual obj-m declaration lives
# in `Kbuild` so that kbuild always sees it regardless of how the kernel tree
# evaluates KERNELRELEASE in the recursive M= pass.

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= arm64
LLVM ?= 1

KBUILD_ARGS := -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH)
ifneq ($(O),)
KBUILD_ARGS += O=$(O)
endif

.PHONY: all clean modules modules_install

all: modules

modules:
	$(MAKE) $(KBUILD_ARGS) LLVM=$(LLVM) modules

modules_install:
	$(MAKE) $(KBUILD_ARGS) LLVM=$(LLVM) modules_install

clean:
	$(MAKE) $(KBUILD_ARGS) clean
