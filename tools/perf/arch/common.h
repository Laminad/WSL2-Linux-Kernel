/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_PERF_COMMON_H
#define ARCH_PERF_COMMON_H

#include <stdbool.h>

<<<<<<< HEAD
struct perf_env;

int perf_env__lookup_objdump(struct perf_env *env, char **path);
=======
int perf_env__lookup_objdump(struct perf_env *env, const char **path);
>>>>>>> master
bool perf_env__single_address_space(struct perf_env *env);

#endif /* ARCH_PERF_COMMON_H */
