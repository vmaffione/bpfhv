KDIR ?= /lib/modules/`uname -r`/build

all: proxy/backend proxy/sring_progs.o ker

ker:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel PWD=$(PWD)/kernel modules

proxy/backend: proxy/backend.c include/bpfhv-proxy.h include/bpfhv.h
	$(CC) -Wall -Werror -I $(PWD)/include -o $@ $<

proxy/sring_progs.o: proxy/sring_progs.c proxy/sring.h include/bpfhv.h
	clang -O2 -Wall -I $(PWD)/include -target bpf -c $< -o $@

clean: ker_clean
	-rm proxy/*.o proxy/backend

ker_clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel PWD=$(PWD)/kernel clean
