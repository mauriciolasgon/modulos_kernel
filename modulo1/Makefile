# Makefile para kfetch_mod
obj-m := kfetch_mod.o          # nome do seu módulo
KDIR   := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean