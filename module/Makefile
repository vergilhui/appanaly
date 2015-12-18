obj-m := module_main.o
#module-objs := send_kernel_msg.o module_main.o
KERNEL_DIR := ~/android/android5.0.2/kernel/goldfish/
CCPATH := $(ANDROID_NDK)/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/bin/
CCPATH_EXT := $(CCPATH)arm-linux-androideabi-
EXTRA_CFLAGS=-fno-pic
ARCH=arm
SUBARCH=arm

all:
	make ARCH=arm CROSS_COMPILE=$(CCPATH_EXT) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -rf *.c~
	rm -rf *.o
	rm -f modules.order
