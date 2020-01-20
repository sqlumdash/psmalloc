/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include "psm.h"

static pthread_mutex_t psm_process_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef TESTLOG
#define LOG( ...) logging(__VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

static void logging(const char *format, ...) {
  va_list va;

  printf("[%d] ", getpid());
  
  va_start(va, format);
  vprintf(format, va);
  va_end(va);
}

static void resetPSMHandle(PSMHandle h) {
  LOG("  resetPSMHandle\n");
  h->fd = -1;
  h->pMap = NULL;
  h->name[0] = '\0';
  h->pAllocator = NULL;
  h->length = 0;
}

static int openPSM(PSMHandle h, const char *name) {
  int ret = 0;

  LOG("  openPSM\n", h, name);

  h->fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (h->fd == -1) ret = 1;

  LOG("  openPSM open fd %d\n", h->fd);
  LOG("  openPSM ret %d\n", ret);

  return ret;
}

static void closePSM(PSMHandle h) {
  LOG("  closePSM\n");

  if (h->fd != -1) {
    LOG("  closePSM close fd %d\n", h->fd);
    close(h->fd);
  }
}

static void dupPSMHandle(PSMHandle h, PSMHandle rh) {
  LOG("  dupPSMHandle\n");

  int fd_tmp = h->fd;
  memcpy(h, rh, sizeof(struct PSMHandleTag));
  h->fd = fd_tmp;
}

static int mapPSM(PSMHandle h, size_t maplen, void *pReqAddress) {
  int ret = 0;

  LOG("  mapPSM\n");

  h->pMap = mmap(pReqAddress, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, h->fd, 0);

  LOG("  mapPSM mmap %p\n", h->pMap);

  if (h->pMap == MAP_FAILED) {
    ret = 1;
    h->pMap = NULL;
  }

  h->length = maplen;

  if (pReqAddress != NULL && h->pMap != pReqAddress) {
    LOG("  mapPSM cannot map into expected address\n");
    LOG("  mapPSM munmap %p\n", h->pMap);

    munmap(h->pMap, h->length);
    h->pMap = NULL;
    ret = 1;
  }

  return ret;
}

static void unmapPSM(PSMHandle h) {
  LOG("  unmapPSM\n");

  if (h->pMap != NULL) {
    LOG("  unmapPSM munmap %p\n", h->pMap);
    LOG("  unmapPSM len %ld\n", h->length);

    munmap(h->pMap, h->length);
    h->pMap = NULL;
  }
}

static uint32_t getProcessID(PSMProcess *proc) {
  return *proc;
}

static int lockPSM(PSMHandle h) {
  struct flock flk;
  int ret = 0;
  int tret;

  LOG("  lockPSM\n");

  pthread_mutex_lock(&psm_process_lock);
  
  memset(&flk, 0, sizeof(flk));

  flk.l_type = F_WRLCK;
  flk.l_whence = SEEK_SET;
  flk.l_start = 0;
  flk.l_len = 0;

  tret = fcntl(h->fd, F_SETLKW, &flk);
  if (tret < 0) ret = 1;

  LOG("  lockPSM ret %d\n", ret);

  return ret;
}

static int unlockPSM(PSMHandle h) {
  struct flock flk;
  int ret = 0;

  LOG("  unlockPSM\n");

  memset(&flk, 0, sizeof(flk));

  flk.l_type = F_UNLCK;
  flk.l_whence = SEEK_SET;
  flk.l_start = 0;
  flk.l_len = 0;

  ret = fcntl(h->fd, F_SETLK, &flk);
  if (ret < 0) ret = 1;

  pthread_mutex_unlock(&psm_process_lock);

  LOG("  unlockPSM result %d\n", ret);

  return ret;
}

/* Prepare file size. */
static int preparePSMFile(PSMHandle h, size_t size) {
  off_t pos;
  ssize_t wsize;
  char c = 0;
  off_t org_pos;
  int ret = 0;

  LOG("  preparePSMFile\n", h, size);

  org_pos = lseek(h->fd, 0, SEEK_CUR);
  if (org_pos == -1) ret = 1;

  pos = lseek(h->fd, size-1, SEEK_SET);
  if (pos == -1) ret = 1;

  wsize = write(h->fd, &c, sizeof(char));
  if (wsize != sizeof(char)) ret = 1;

  pos = lseek(h->fd, org_pos, SEEK_SET);
  if (pos == -1) ret = 1;

  ret = 0;
  
  LOG("  preparePSMFile ret %d\n", ret);

  return ret;
}

/* Empty file. */
static int emptyPSMFile(PSMHandle h) {
  int ret = 0;
  int tret;

  LOG("  emptyPSMFile\n");

  tret = ftruncate(h->fd, 0);
  if (tret == -1) ret = 1;

  LOG("  emptyPSMFile ret %d\n", ret);

  return ret;
}

/* Remove file. */
static int removePSMFile(PSMHandle h) {
  int ret = 0;
  int tret;

  LOG("  removePSMFile\n");

  tret = remove(h->name);
  if (tret == -1) ret = 1;

  LOG("  removePSMFile ret %d\n", ret);

  return ret;
}

/* Get file size from file descriptor. */
static int getPSMFileSize(PSMHandle h, size_t *size) {
  int ret = 0;
  struct stat st;

  LOG("  getPSMFileSize\n");
  
  assert( size );

  if (stat(h->name, &st) != 0) {
    ret = 1;
  } else if (!S_ISREG(st.st_mode)) {
    ret = 1;
  }
  *size = st.st_size;

  LOG("  getPSMFileSize ret %d\n", ret);

  return ret;
}

static void getCurrentProcess(PSMProcess* pProc) {
  *pProc = getpid();
}

static int isEqualProcess(PSMProcess proc1, PSMProcess proc2) {
  int ret = 0;
  if (proc1 == proc2)
    ret = 1;
  return ret;
}

static int isExistProcess(PSMProcess proc) {
  int ret = kill(proc, 0);
  if (ret == 0) {
    ret = 1;
  } else {
    assert(errno == ESRCH);
    ret = 0;
  }
  return ret;
}

static void copyString(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  dest[n-1] = '\0';
}

static int normalizePath(char *dest, const char *src, size_t dn) {
  int ret = 0;
  char *rpath = NULL;

  LOG("  normalizePath\n");
  
  rpath = realpath(src, NULL);
  if (rpath == NULL) {
    /* error to get realpath */
    ret = 1;
  } else {
    size_t len = strlen(rpath) + 1;
    if (len > dn) {
      /* too long name */
      ret = 1;
    } else {
      memcpy(dest, rpath, len);
    }
    free(rpath);
  }

  LOG("  normalizePath result %d\n", ret);

  return ret;
}

PSM_EXPORT PSMPlatformFunctionsType PSMPlatformFunctions = {
  resetPSMHandle,
  lockPSM,
  unlockPSM,
  preparePSMFile,
  emptyPSMFile,
  removePSMFile,
  getPSMFileSize,
  openPSM,
  closePSM,
  dupPSMHandle,
  mapPSM,
  unmapPSM,
  copyString,
  normalizePath,
  getProcessID,
  getCurrentProcess,
  isEqualProcess,
  isExistProcess,
  logging,
};
