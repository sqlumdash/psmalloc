/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#ifndef PSM_H
#define PSM_H

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#if defined(USE_TEST_HOOK) && (USE_TEST_HOOK == 1)
#define PSM_DECLARE_HOOK(name) PSM_EXPORT void (*name ## _hook)(void)
#define PSM_INSERT_HOOK(name) do { if (name ## _hook != NULL) { name ## _hook(); } } while (0)
#else
#define PSM_DECLARE_HOOK(name) 
#define PSM_INSERT_HOOK(name) do { } while (0)
#endif

/* define WIN32 if it runs on Windows, otherwise on linux */
#if defined(_WIN32) || defined(_WIN64)
#include "psm_win.h"
#else /* defined(_WIN32) || defined(_WIN64) */
#include "psm_linux.h"
#endif /* defined(_WIN32) || defined(_WIN64) */

#define PSM_PROCESS_MAX (1024)

/* parameters for auto address */
#define ENABLE_PSM_AUTO_ADDRESS
#define PSM_AUTO_ADDR32_TOP   (0x20000000)
#define PSM_AUTO_ADDR64_TOP   (0x200000000000)
#define PSM_AUTO_ADDR_UNIT    (0x01000000)
#define PSM_AUTO_ADDR32_RANGE (0x20000000)
#define PSM_AUTO_ADDR64_RANGE (0x100000000000)

#define PSM_ALIGNMENT_SIZE(size, alignment) (((size) + (alignment) -1) / (alignment) * (alignment))

#define PSM_PSMHEADER_SIZE (PSM_ALIGNMENT_SIZE(sizeof(PSMHeader), 4096))

#define PSM_REFCOUNT_CLEAN    (0)
#define PSM_REFCOUNT_INACTIVE (-1)

#define PSM_PSMHEADER_MAGIC (0x0141BEEF)
#define PSM_USER_SIZE (8)

typedef struct PSMRefTable {
  PSMProcess proc[PSM_PROCESS_MAX]; /* Process ID using this shared memory. */
  int32_t refcount[PSM_PROCESS_MAX]; /* Reference count of initialization for the process (-1 is deleted entry) */
  PSMHandle pshared_handle[PSM_PROCESS_MAX]; /* Shared information on each processes. */
} PSMRefTable;

typedef struct PSMHeader {
  char top_padding[64]; /* Avoid damage from access violation. */
  char user_data[PSM_USER_SIZE]; /* Common user data area. */
  char user_padding[8]; /* Avoid damage from access violation. */
  uint32_t magic; /* Magic value for quick checking. */
  uint32_t refcount; /* Reference count of initialization. */

  /* Members of runtime checking */
  int32_t process_max; /* Value of PSM_PROCESS_MAX on the first init process. */
  uint32_t header_size; /* Size of PSMHeader */
  uint32_t ptr_size; /* Size of pointer */

  PSMRefTable reftable; /* Reference table of process ID and initialization count for each process */

  /* Place pointers below */
  void *pReqAddress; /* Request map address */
} PSMHeader;

typedef struct PSMPlatformFunctionsType {
  /* PSM functions */
  void (*resetPSMHandle)(PSMHandle h);
  int (*lockPSM)(PSMHandle h);
  int (*unlockPSM)(PSMHandle h);
  int (*preparePSMFile)(PSMHandle h, size_t size);
  int (*emptyPSMFile)(PSMHandle h);
  int (*removePSMFile)(PSMHandle h);
  int (*getPSMFileSize)(PSMHandle h, size_t *size);
  int (*openPSM)(PSMHandle h, const char *name);
  void (*closePSM)(PSMHandle h);
  void (*dupPSMHandle)(PSMHandle h, const PSMHandle rh);
  int (*mapPSM)(PSMHandle h, size_t maplen, void *pReqAddress);
  void (*unmapPSM)(PSMHandle h);
  /* string functions */
  void (*copyString)(char *dest, const char *src, size_t n);
  /* file functions */
  int (*normalizePath)(char *dest, const char *src, size_t dn);
  /* process related functions */
  uint32_t (*getProcessID)(PSMProcess *proc);
  void (*getCurrentProcess)(PSMProcess *pProc);
  int (*isEqualProcess)(PSMProcess proc1, PSMProcess proc2);
  int (*isExistProcess)(PSMProcess proc);
  /* log output function */
  void (*log)(const char *format, ...);
} PSMPlatformFunctionsType;

extern PSM_EXPORT PSMPlatformFunctionsType PSMPlatformFunctions;

PSM_EXPORT void PSMinit(const char *name, const size_t initSize, void *pReqAddress, PSMHandle* pHandle);
PSM_EXPORT void PSMdeinit(const PSMHandle handle);
PSM_EXPORT void *PSMalloc(const PSMHandle handle, const size_t allocSize);
PSM_EXPORT void PSMfree(const PSMHandle handle, void *pAddress);
PSM_EXPORT int PSMgetError(const PSMHandle handle);
PSM_EXPORT void *PSMgetUser(const PSMHandle handle);

#endif /* !PSM_H */
