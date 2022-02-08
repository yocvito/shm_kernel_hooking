obj-m += mod.o
obj-m += detectmmap.o
obj-m += print_sys_call_table.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
