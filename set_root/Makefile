-DKBUILD_MODNAME='"root_lkm"'

# Configuration
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
HOOKS_DIR := ../lib/hook
CREDS_DIR := ../lib/creds

# Module à compiler
obj-m := root_lkm.o
root_lkm-objs := $(HOOKS_DIR)/ftrace_helper.o ${CREDS_DIR}/creds.o root.o

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