# SPDX-License-Identifier: GPL-2.0
# Makefile for xmon

<<<<<<< HEAD
=======
# Disable clang warning for using setjmp without setjmp.h header
subdir-ccflags-y := $(call cc-disable-warning, builtin-requires-header)

subdir-ccflags-$(CONFIG_PPC_WERROR) += -Werror

>>>>>>> master
GCOV_PROFILE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n
KASAN_SANITIZE := n
KCSAN_SANITIZE := n

# Disable ftrace for the entire directory
<<<<<<< HEAD
ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
=======
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
>>>>>>> master

ccflags-$(CONFIG_PPC64) := $(NO_MINIMAL_TOC)

# Clang stores addresses on the stack causing the frame size to blow
# out. See https://github.com/ClangBuiltLinux/linux/issues/252
ccflags-$(CONFIG_CC_IS_CLANG) += -Wframe-larger-than=4096

obj-y			+= xmon.o nonstdio.o spr_access.o xmon_bpts.o

ifdef CONFIG_XMON_DISASSEMBLY
obj-y			+= ppc-dis.o ppc-opc.o
obj-$(CONFIG_SPU_BASE)	+= spu-dis.o spu-opc.o
endif
