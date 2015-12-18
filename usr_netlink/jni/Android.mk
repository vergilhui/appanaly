LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := usr_netlink
LOCAL_SRC_FILES := usr_netlink.c
LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
# BUILD_EXECUTABLE generate executable binary file
include $(BUILD_EXECUTABLE)
