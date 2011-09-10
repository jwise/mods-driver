# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
obj-m                  := mods.o
mods-y                 := mods_krnl.o
mods-y                 += mods_dev.o
mods-y                 += mods_mem.o
mods-y                 += mods_irq.o
mods-$(CONFIG_ACPI)    += mods_acpi.o
mods-$(CONFIG_ARM)     += mods_clock.o

# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif
