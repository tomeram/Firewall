ifneq ($(KERNELRELEASE),)
	obj-m := fw.o
	fw-objs := fwmod.o stateless.o statefull.o log.o

else
	KDIR :=/lib/modules/$(shell uname -r)/build
	PDW := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PDW) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PDW) clean

endif