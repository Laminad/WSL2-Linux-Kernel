# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wl,-no-as-needed -Wall $(KHDR_INCLUDES)
LDFLAGS += -lpthread
LDLIBS += -lcap

TEST_GEN_PROGS := seccomp_bpf seccomp_benchmark
include ../lib.mk
<<<<<<< HEAD
=======

.PHONY: all clean

BINARIES := seccomp_bpf seccomp_benchmark
CFLAGS += -Wl,-no-as-needed -Wall

seccomp_bpf: seccomp_bpf.c ../kselftest_harness.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -lpthread -o $@

TEST_PROGS += $(BINARIES)
EXTRA_CLEAN := $(BINARIES)

all: $(BINARIES)
>>>>>>> master
