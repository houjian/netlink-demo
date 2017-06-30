NAME		:= testnetlink
obj-m		:= $(NAME).o
KERNEL_DIR	?= /lib/modules/$(shell uname -r)/build

$(NAME)-objs:= main.o

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) modules
	cp $(NAME).ko ../$(NAME).ko

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) clean
	rm -f ../$(NAME).ko
