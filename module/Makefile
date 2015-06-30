obj-m := fw.o

KDIR :=/lib/modules/$(shell uname -r)/build
PDW := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PDW) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PDW) clean