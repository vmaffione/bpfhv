KDIR ?= /lib/modules/`uname -r`/build

all: proxy/backend ker

ker:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel

proxy/backend: proxy/backend.cpp
	$(CXX) -Wall -Werror -o $@ $<

clean: ker_clean
	-rm *.o backend

ker_clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
