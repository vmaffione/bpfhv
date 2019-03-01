KDIR ?= /lib/modules/`uname -r`/build

all: proxy/backend ker

ker:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel PWD=$(PWD)/kernel modules

proxy/backend: proxy/backend.c include/bpfhv-proxy.h include/bpfhv.h
	$(CC) -Wall -Werror -I $(PWD)/include -o $@ $<

clean: ker_clean
	-rm *.o proxy/backend

ker_clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
