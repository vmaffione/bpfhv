ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m := bpfhv.o
else
# normal makefile
KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
endif
