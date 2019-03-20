KDIR ?= /lib/modules/`uname -r`/build

LIBS = -lpthread
DEFS =
ifneq ($(WITH_NETMAP),)
LIBS += -lnetmap
DEFS += -DWITH_NETMAP
endif

all: proxy/backend proxy/sring_progs.o proxy/sring_progs_gso.o ker

ker:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel PWD=$(PWD)/kernel modules

proxy/backend: proxy/backend.c include/bpfhv-proxy.h include/bpfhv.h proxy/sring.h
	$(CC) -O2 -g -Wall -Werror -I $(PWD)/include $(DEFS) -o $@ $< $(LIBS)

proxy/sring_progs.o: proxy/sring_progs.c proxy/sring.h include/bpfhv.h
	clang -O2 -Wall -I $(PWD)/include -target bpf -c $< -o $@

proxy/sring_progs_gso.o: proxy/sring_progs.c proxy/sring.h include/bpfhv.h
	clang -O2 -Wall -DWITH_GSO -I $(PWD)/include -target bpf -c $< -o $@

clean: ker_clean
	-rm proxy/*.o proxy/backend

ker_clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel PWD=$(PWD)/kernel clean
