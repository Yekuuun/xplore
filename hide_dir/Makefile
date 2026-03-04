# Configuration
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
HOOKS_DIR := ../lib/hook

# Module à compiler
obj-m := hide_lkm.o
hide_lkm-objs := $(HOOKS_DIR)/ftrace_helper.o hide.o

# Flags de compilation
EXTRA_CFLAGS += -DDEBUG

# Cibles
all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f *~

install:
	make -C $(KDIR) M=$(PWD) modules_install

.PHONY: all clean install