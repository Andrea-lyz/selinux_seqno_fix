ifneq ($(KERNELRELEASE),)

obj-m += selinux_seqno_fix.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= arm64
LLVM ?= 1

KBUILD_ARGS := -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH)
ifneq ($(O),)
KBUILD_ARGS += O=$(O)
endif

.PHONY: all clean

all:
	$(MAKE) $(KBUILD_ARGS) LLVM=$(LLVM) modules

clean:
	$(MAKE) $(KBUILD_ARGS) clean

endif
