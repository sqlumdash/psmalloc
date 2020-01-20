/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS 1
#endif /* defined(_WIN32) || defined(_WIN64) */

#if WINDOWS
#include <Windows.h>
#else /* WINDOWS */
#include <unistd.h>
#include <dlfcn.h>
#endif /* WINDOWS */

#include "psm.h"

static char **g_argv;
static int g_argc;

void (**mspace_malloc_in_lock_hook_)(void);
void (**psm_init_in_lock_hook_)(void);
void (**psm_deinit_in_lock_hook_)(void);

#if WINDOWS
#define RTLD_LAZY (0)

static unsigned int sleep(unsigned int seconds) {
  Sleep(seconds * 1000);
  return seconds * 1000;
}

void *dlopen(const char *filename, int flag) {
  (void)filename;
  (void)flag;
  HANDLE hDll = GetModuleHandleA("psm_library.dll");
  return hDll;
}

int dlclose(void *handle) {
  (void)handle;
  return 0;
}

void *dlsym(void *handle, char* symbol) {
  FARPROC addr = NULL;
  addr = GetProcAddress(GetModuleHandle(NULL), symbol);
  if (addr == NULL) {
    HANDLE hDll = handle;
    if (hDll != NULL) {
      addr = GetProcAddress(hDll, symbol);
    }
  }
  return (void *)addr;
}
#define TEST_EXPORT __declspec(dllexport)
#else
#define TEST_EXPORT 
#endif /* WINDOWS */

TEST_EXPORT int simple(void)
{
  int err = 0;
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    printf("Application call PSMgetError to check critical error -> %d\n", err);
    if (pAddress == NULL) {
      PSMdeinit(handle);
      return 1;
    }
    PSMfree(handle, pAddress);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int simple20k(void)
{
  int err = 0;
  PSMHandle handle;

  PSMinit("test.psm", 20*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    printf("Application call PSMgetError to check critical error -> %d\n", err);
    if (pAddress == NULL) {
      PSMdeinit(handle);
      return 1;
    }
    PSMfree(handle, pAddress);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int simple_twice(void)
{
  int err = 0;
  PSMHandle handle;
  int i;

  for (i=0; i< 2; i++) {
    PSMinit("test.psm", 1024*1024, 0, &handle);
    if (handle != NULL) {
      void *pAddress = PSMalloc(handle, 1024);
      err = PSMgetError(handle);
      printf("Application call PSMgetError to check critical error -> %d\n", err);
      if (pAddress == NULL) {
        PSMdeinit(handle);
        return 1;
      }
      PSMfree(handle, pAddress);
      PSMgetError(handle);
      PSMdeinit(handle);
    }
  }

  return 0;
}

static void wait_forever(void)
{
  while(1);
}

TEST_EXPORT int mallocblock_simple(void)
{
  if (mspace_malloc_in_lock_hook_ == NULL) {
    printf("not supported\n");
    exit(-1);
  }
  *mspace_malloc_in_lock_hook_ = &wait_forever;
  return simple();
}

TEST_EXPORT int initblock_simple(void)
{
  if (psm_init_in_lock_hook_ == NULL) {
    printf("not supported\n");
    exit(-1);
  }
  *psm_init_in_lock_hook_ = &wait_forever;
  return simple();
}

TEST_EXPORT int deinitblock_simple(void)
{
  if (psm_deinit_in_lock_hook_ == NULL) {
    printf("not supported\n");
    exit(-1);
  }
  *psm_deinit_in_lock_hook_ = &wait_forever;
  return simple();
}

static void call_simple(void)
{
  simple();
}

TEST_EXPORT int initblock_process_simple(void)
{
  if (psm_init_in_lock_hook_ == NULL) {
    printf("not supported\n");
    exit(-1);
  }
  *psm_init_in_lock_hook_ = &call_simple;
  return simple();
}

TEST_EXPORT int toobigalloc(void)
{
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024*1024);
    if (pAddress) {
      PSMfree(handle, pAddress);
    }
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int toosmallalloc(void)
{
  PSMHandle handle;
  size_t siz;

  for (siz = 64; siz < 1024 * 16; siz+=64) {
    PSMinit("test.psm", siz, 0, &handle);
    printf("handle %p\n", handle);
    if (handle != NULL) {
      void *pAddress = PSMalloc(handle, 2);
      if (pAddress) {
        PSMfree(handle, pAddress);
      } else {
        int err = 0;
        err = PSMgetError(handle);
        printf("PSMgetError %d\n", err);
      }
      PSMdeinit(handle);
    }
  }

  return 0;
}

TEST_EXPORT int simple2(void)
{
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress1 = PSMalloc(handle, 1024);
    void *pAddress2 = PSMalloc(handle, 1024);
    PSMfree(handle, pAddress2);
    PSMfree(handle, pAddress1);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int initalloc(void)
{
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024);
    printf("initalloc allocate %p\n", pAddress);
    if (pAddress == NULL) {
      int err = 0;
      err = PSMgetError(handle);
      printf("Application got NULL from malloc and the critical error status is %d\n", err);
      return 1;
    }
  }

  return 0;
}

TEST_EXPORT int init_twice(void)
{
  PSMHandle handle1, handle2;

  PSMinit("test.psm", 1024*1024, 0, &handle1);
  PSMinit("test.psm", 1024*1024, 0, &handle2);
  if (handle2 == NULL)
    printf("second map is failed ... OK\n");

  if (handle1 != NULL) {
    PSMdeinit(handle1);
  }
  if (handle2 != NULL) {
    PSMdeinit(handle2);
  }

  return 0;
}

TEST_EXPORT int pshared_handle_test(void)
{
  PSMHandle handle1, handle2, handle3;
  char *name ="test.psm";
  size_t size = 1024*1024;

  remove(name);
  PSMinit(name, size, NULL, &handle1);
  assert(handle1);
  PSMinit(name, size, NULL, &handle2);
  assert(handle2);

  PSMdeinit(handle1);
  PSMdeinit(handle2);

  PSMinit(name, size, NULL, &handle3);
  assert(handle3);

  PSMdeinit(handle3);

  return 0;
}

TEST_EXPORT int init_three(void)
{
  PSMHandle handle1, handle2, handle3;

  PSMinit("test1.psm", PSM_AUTO_ADDR_UNIT - 1, 0, &handle1); /* 1 slot */
  printf("test1.psm %p\n", handle1);
  PSMinit("test2.psm", PSM_AUTO_ADDR_UNIT + 1, 0, &handle2); /* 2 slots */
  printf("test2.psm %p\n", handle2);
  PSMinit("test3.psm", PSM_AUTO_ADDR_UNIT, 0, &handle3); /* 1 slot */
  printf("test3.psm %p\n", handle3);
  if (handle1 != NULL) {
    PSMdeinit(handle1);
  }
  if (handle2 != NULL) {
    PSMdeinit(handle2);
  }
  if (handle3 != NULL) {
    PSMdeinit(handle3);
  }

  return 0;
}

TEST_EXPORT int simple_sleep(void)
{
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024);
    sleep(10);
    PSMfree(handle, pAddress);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int initfree(void)
{
  PSMHandle handle;
  int i;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    uintptr_t adr = (uintptr_t)strtoll(g_argv[2], NULL, 16);
    void *pAddress = (void *)adr;
    printf("address %p\n", pAddress);
    printf("%p: %x\n", pAddress, *(uint32_t*)pAddress);
    unsigned char *getUser = (unsigned char *)PSMgetUser(handle);
    printf("getUser address %p\n", getUser);
    for (i=0;i<PSM_USER_SIZE;i++) {
      printf("%02x", getUser[i]);
      if (i==(PSM_USER_SIZE-1)) printf("\n");
    }
    fflush(stdout);
    PSMfree(handle, pAddress);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int initallocwait(void)
{
  PSMHandle handle;
  int i;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    void *pAddress = PSMalloc(handle, 1024);
    printf("address %p\n", pAddress);
    *(uint32_t*)pAddress = (uint32_t)time(NULL);
    printf("%p: %x\n", pAddress, *(uint32_t*)pAddress);
    unsigned char *getUser = (unsigned char *)PSMgetUser(handle);
    printf("getUser address %p\n", getUser);
    for (i=0;i<PSM_USER_SIZE;i++) {
      getUser[i] = i;
      printf("%02x", getUser[i]);
      if (i==(PSM_USER_SIZE-1)) printf("\n");
    }
    fflush(stdout);
    wait_forever();
    PSMfree(handle, pAddress);
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int initwait(void)
{
  PSMHandle handle;

  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    wait_forever();
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int fullalloc(void)
{
  PSMHandle handle;
  const size_t all_size = 1024*1024;
  
  PSMinit("test.psm", all_size, 0, &handle);
  if (handle != NULL) {
    int i;
    int err;
    void *pAddresses[10];
    size_t total = 0;
    const size_t alloc_size = 1024*105;
    for (i=0; i<10; i++) {
      pAddresses[i] = PSMalloc(handle, alloc_size);
      if (pAddresses[i] != NULL)
        total += alloc_size;
      err = PSMgetError(handle);
      printf("%d: %zu/%zu bytes, %.01f %%, PSMalloc = %p, err = %d\n",
             i, total, all_size, (total*100.f/all_size), pAddresses[i], err);
    }
    for (i=0; i<10; i++) {
      if (pAddresses[i] != NULL) {
        PSMfree(handle, pAddresses[i]);
      }
    }
  }
  PSMdeinit(handle);

  return 0;
}

TEST_EXPORT int initnameNULL(void)
{
  PSMHandle handle;
  printf("call PSMinit(NULL, 1024*1024, 0, &handle)\n");
  PSMinit(NULL, 1024*1024, 0, &handle);
  printf("handle should be NULL: %p\n", handle);
  return 0;
}

TEST_EXPORT int initnameEmpty(void)
{
  PSMHandle handle;
  printf("call PSMinit("", 1024*1024, 0, &handle)\n");
  PSMinit("", 1024*1024, 0, &handle);
  printf("handle should be NULL: %p\n", handle);
  return 0;
}

TEST_EXPORT int initlongname(void)
{
  PSMHandle handle;
  size_t name_len = (size_t)strtoll(g_argv[2], NULL, 10);
  char *name = malloc(name_len);
  if (name == NULL) {
    printf("malloc failed\n");
    return 1;
  }
  printf("name length %zu (including null termination)\n", name_len);
  if (name_len == 0) {
    printf("name length should be larger than or equal to 1\n");
    return 1;
  }
  memset(name, 'x', name_len);
  name[name_len-1] = '\0';
  printf("call PSMinit('x' x %zu + '\\0', 1024*1024, 0, &handle)\n", name_len-1);
  PSMinit(name, 1024*1024, 0, &handle);
  free(name);
  if (handle != NULL) {
    int err;
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    if (err) {
      printf("PSMgetError %d\n", err);
    }
    if (pAddress != NULL) {
      PSMfree(handle, pAddress);
    }
    PSMdeinit(handle);
  }
  return 0;
}

TEST_EXPORT int initreqaddr(void)
{
  PSMHandle handle;
  uintptr_t adr = (uintptr_t)strtoll(g_argv[2], NULL, 16);
  void *pAddress = (void *)adr;
  printf("map request address = %p\n", pAddress);

  PSMinit("test.psm", 1024*1024, pAddress, &handle);
  if (handle != NULL) {
    int err;
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    if (err) {
      printf("PSMgetError %d\n", err);
    }
    if (pAddress != NULL) {
      PSMfree(handle, pAddress);
    }
    PSMdeinit(handle);
  }

  return 0;
}

TEST_EXPORT int initnullhandle(void)
{
  PSMinit("test.psm", 1024*1024, 0, NULL);
  return 0;
}

TEST_EXPORT int deinitnullhandle(void)
{
  PSMdeinit(NULL);
  return 0;
}

TEST_EXPORT int allocnullhandle(void)
{
  PSMalloc(NULL, 10);
  return 0;
}

TEST_EXPORT int freenullhandle(void)
{
  PSMHandle handle;
  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    int err;
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    if (err) {
      printf("PSMgetError %d\n", err);
      return 1;
    }
    if (pAddress != NULL) {
      PSMfree(NULL, pAddress);
    }
    PSMdeinit(handle);
  }
  return 0;
}

TEST_EXPORT int freenulladdress(void)
{
  PSMHandle handle;
  PSMinit("test.psm", 1024*1024, 0, &handle);
  if (handle != NULL) {
    int err;
    void *pAddress = PSMalloc(handle, 1024);
    err = PSMgetError(handle);
    if (err) {
      printf("PSMgetError %d\n", err);
    }
    if (pAddress != NULL) {
      PSMfree(handle, NULL);
    }
    PSMdeinit(handle);
  }
  return 0;
}

TEST_EXPORT int geterrornullhandle(void)
{
  int err = PSMgetError(NULL);
  printf("PSMgetError %d\n", err);
  return 0;
}

TEST_EXPORT int allocSize(void)
{
  PSMHandle handle;
  const size_t init_size = 1024*1024;
  PSMinit("test.psm", init_size, 0, &handle);
  if (handle != NULL) {
    int err;
    size_t size = 0;
    for (size = 0; size < init_size; size++) {
      void *pAddress = PSMalloc(handle, size);
      err = PSMgetError(handle);
      printf("size %zu: address %p, err %d\n", size, pAddress, err);
      if (err) {
        printf("PSMgetError %d\n", err);
      }
      if (pAddress != NULL) {
        PSMfree(handle, pAddress);
      }
    }
    PSMdeinit(handle);
  }
  return 0;
}

TEST_EXPORT int htrun(void)
{
  PSMPlatformFunctionsType *pf = &PSMPlatformFunctions;
  PSMHandle handle;
  const size_t obSize = 4 * 1024;
  const size_t init_size = 1024 * 1024;
  const double test_duration = 10 * 60; /* 30 minutes */
  const int obEntries = 10;
  PSMHandle obHandle;
  int writer = 0;
  int seq = 0;
  time_t prev_t;
  time_t start_t;

  if (g_argc > 2 && strncmp(g_argv[2], "first", 6) == 0) {
    obHandle = (PSMHandle)malloc(sizeof(struct PSMHandleTag));
    if (obHandle == NULL) {
      printf("cannot allocate PSMHandle\n");
      return 0;
    }
    pf->resetPSMHandle(obHandle);
    if (pf->openPSM(obHandle, "ht.psm")) return 0;
    if (pf->emptyPSMFile(obHandle)) return 0;
    if (pf->preparePSMFile(obHandle, obSize)) return 0;
    if (pf->mapPSM(obHandle, obSize, NULL)) return 0;
    printf("Outband shared address %p (initiator)\n", obHandle->pMap);
    printf("Outband entries %d\n", obEntries);
    memset(obHandle->pMap, 0, obSize);
    writer = 1;
  } else {
    obHandle = (PSMHandle)malloc(sizeof(struct PSMHandleTag));
    if (obHandle == NULL) {
      printf("cannot allocate PSMHandle\n");
      return 0;
    }
    pf->resetPSMHandle(obHandle);
    if (pf->openPSM(obHandle, "ht.psm")) return 0;
    if (pf->mapPSM(obHandle, obSize, NULL)) return 0;
    printf("Outband shared address %p\n", obHandle->pMap);
    printf("Outband entries %d\n", obEntries);
  }

  PSMinit("test.psm", init_size, 0, &handle);
  if (handle == NULL) return 0;
  prev_t = time(NULL);
  start_t = prev_t;
  while (1) {
    int i;
    time_t t;
    int update = 0;
    for (i = 0; i < obEntries; i++) {
      size_t size;
      void *pAddress;
      pAddress = (void *)*(intptr_t *)((char *)obHandle->pMap + i * sizeof(void *));
      if (writer == 1) {
        if (pAddress == NULL) {
          size = (rand() % ((init_size - 12 * 1024) / obEntries)) + 1;
          pAddress = PSMalloc(handle, size);
          *(intptr_t *)((char *)obHandle->pMap + i * sizeof(void *)) = (intptr_t)pAddress;
          printf("entry(%d) alloc %p\n", i, pAddress);
          update++;
        }
      } else {
        if (pAddress != NULL) {
          PSMfree(handle, pAddress);
          *(intptr_t *)((char *)obHandle->pMap + i * sizeof(void *)) = (intptr_t)NULL;
          printf("entry(%d) free %p\n", i, pAddress);
          update++;
          if ((seq % 100) == 99) {
            printf("deinit / init (writer)\n");
            PSMdeinit(handle);
            PSMinit("test.psm", init_size, 0, &handle);
            if (handle == NULL) return 0;
          }
        }
      }
    }

    t = time(NULL);
    if (update) {
      seq++;
      printf("%s iterate end (%s)\n", asctime(localtime(&t)), writer == 1 ? "writer" : "reader");
      prev_t = t;
    }
    if (difftime(t, prev_t) > 10.0) {
      printf("******* %s stall over 10 seconds (%s)\n", asctime(localtime(&t)), writer == 1 ? "writer" : "reader");
      prev_t = t;
    }
    if (difftime(t, start_t) > test_duration) {
      printf("%s test duration is over (%s)\n", asctime(localtime(&t)), writer == 1 ? "writer" : "reader");
      break;
    }
  }
  PSMdeinit(handle);
  pf->unmapPSM(obHandle);
  pf->closePSM(obHandle);
  free(obHandle);
  return 0;
}

TEST_EXPORT int null_deinit(void)
{
  PSMdeinit(0);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    return simple();
  }

  void *handle = dlopen(NULL, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "cannot dlopen\n");
    exit(EXIT_FAILURE);
  }
  void (*fptr) (void) = dlsym(handle, argv[1]);

  if (!fptr) {
    fprintf(stderr, "cannot find test function %s\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  mspace_malloc_in_lock_hook_ = dlsym(handle, "mspace_malloc_in_lock_hook");
  psm_init_in_lock_hook_ = dlsym(handle, "psm_init_in_lock_hook");
  psm_deinit_in_lock_hook_ = dlsym(handle, "psm_deinit_in_lock_hook");

  g_argc = argc;
  g_argv = argv;
  
  printf("start test %s\n", argv[1]);
  fptr();
  printf("end test %s\n", argv[1]);

  return 0;
}
