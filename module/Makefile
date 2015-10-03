ifneq ($(KERNELRELEASE),)
	obj-m := fw.o
	fw-objs := fwmod.o stateless.o stateful.o log.o dlp.o zabbix.o sysax.o

else
	KDIR :=/lib/modules/$(shell uname -r)/build
	PDW := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PDW) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PDW) clean

endif
