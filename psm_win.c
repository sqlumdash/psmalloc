/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#include <Windows.h>
#include <stdarg.h>
#include "psm.h"

#ifdef TESTLOG
#define LOG( ...) logging(__VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

static void logging(const char *format, ...) {
  va_list va;

  printf("[%d] ", GetCurrentProcessId());
  
  va_start(va, format);
  vprintf(format, va);
  va_end(va);
}

static int callCreateFileMapping(PSMHandle h, size_t size) {
  int ret = 0;
  HANDLE hMap;
  DWORD high_size = 0;
  uint64_t size64 = size;

  LOG("    CreateFileMapping size %zu\n", size);

  if (sizeof(size_t) > 4) {
    high_size = size64 >> 32;
  }
  hMap = CreateFileMapping(h->hFile, NULL, PAGE_READWRITE, high_size, (DWORD)size, NULL);

  if (hMap == NULL) ret = 1;

  h->hMap = hMap;

  LOG("    CreateFileMapping hMap %p\n", hMap);
  LOG("    CreateFileMapping ret %d\n", ret);

  return ret;
}

static void resetPSMHandle(PSMHandle h) {
  LOG("  resetPSMHandle\n");
  h->hFile = INVALID_HANDLE_VALUE;
  h->hMap = NULL;
  h->pMap = NULL;
  h->name[0] = '\0';
  h->pAllocator = NULL;
  h->length = 0;
}

static int openPSM(PSMHandle h, const char *name) {
  int ret = 0;

  LOG("  openPSM\n", h, name);

  h->hFile = CreateFileA(name, GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (h->hFile == INVALID_HANDLE_VALUE) ret = 1;

  LOG("  openPSM open handle %p\n", h->hFile);
  LOG("  openPSM ret %d\n", ret);

  return ret;
}

static void closePSM(PSMHandle h) {
  LOG("  closePSM\n");

  if (h->hFile != INVALID_HANDLE_VALUE) {
    LOG("  closePSM CloseHandle %p\n", h->hFile);
    CloseHandle(h->hFile);
  }
}

static void dupPSMHandle(PSMHandle h, PSMHandle rh) {
  LOG("  dupPSMHandle\n");

  HANDLE hFile_tmp = h->hFile;
  memcpy(h, rh, sizeof(struct PSMHandleTag));
  h->hFile = hFile_tmp;
}

static int mapPSM(PSMHandle h, size_t maplen, void *pReqAddress) {
  int ret = 0;

  LOG("  mapPSM\n");

  if (h->hMap == NULL) {
    if (callCreateFileMapping(h, maplen)) ret = 1;
  }

  if (h->hMap != NULL) {
    LOG("  mapPSM MapViewOfFileEx\n");
    h->pMap = MapViewOfFileEx(h->hMap, FILE_MAP_WRITE, 0, 0, 0, pReqAddress);
    if ((h->pMap == NULL) || (pReqAddress != NULL && h->pMap != pReqAddress)) ret = 1;
    LOG("  mapPSM MapViewOfFileEx pMap %p\n", h->pMap);
  }

  if (ret == 0) {
    h->length = maplen;
  }

  LOG("  mapPSM ret %d\n", ret);

  return ret;
}

static void unmapPSM(PSMHandle h) {
  LOG("  unmapPSM\n");

  if (h->pMap != NULL) {
    LOG("  unmapPSM UnmapViewOfFile %p\n", h->pMap);

    UnmapViewOfFile(h->pMap);
    h->pMap = NULL;
  }
  if (h->hMap != NULL) {
    LOG("  unmapPSM CloseHandle %p\n", h->hMap);

    CloseHandle(h->hMap);
    h->hMap = NULL;
  }
}

static uint32_t getProcessID(PSMProcess *proc) {
  return *proc;
}

static int lockPSM(PSMHandle h) {
  int ret = 0;
  OVERLAPPED overlapped;
  BOOL bret;

  LOG("  lockPSM\n");

  memset(&overlapped, 0, sizeof(overlapped));

  bret = LockFileEx(h->hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped);
  if (bret == 0) ret = 1;

  LOG("  lockPSM ret %d\n", ret);

  return ret;
}

static int unlockPSM(PSMHandle h) {
  int ret = 0;
  OVERLAPPED overlapped;
  BOOL bret;

  LOG("  unlockPSM\n");

  memset(&overlapped, 0, sizeof(overlapped));

  bret = UnlockFileEx(h->hFile, 0, MAXDWORD, MAXDWORD, &overlapped);
  if (bret == 0) ret = 1;

  LOG("  unlockPSM result %d\n", ret);

  return ret;
}

/* Prepare file size. */
static int preparePSMFile(PSMHandle h, size_t size) {
  int ret;

  LOG("  preparePSMFile\n");

  ret = callCreateFileMapping(h, size);

  LOG("  preparePSMFile ret %d\n", ret);

  return ret;
}

/* Empty file. */
static int emptyPSMFile(PSMHandle h) {
  BOOL bret;
  LARGE_INTEGER i64;
  LARGE_INTEGER i64_cur;
  int ret = 0;

  LOG("  emptyPSMFile\n");

  i64.QuadPart = 0;
  bret = SetFilePointerEx(h->hFile, i64, &i64_cur, FILE_BEGIN);
  if (bret == 0) {
    ret = 1;
  }
  else {
    bret = SetEndOfFile(h->hFile);
    if (bret == 0) {
      ret = 1;
    }
  }

  LOG("  emptyPSMFile ret %d\n", ret);

  return ret;
}

/* Remove file. */
static int removePSMFile(PSMHandle h) {
  int ret = 0;
  BOOL bret;

  LOG("  removePSMFile\n");

  bret = DeleteFileA(h->name);
  if (bret == 0) ret = 1;

  LOG("  removePSMFile ret %d\n", ret);

  return ret;
}

/* Get file size from file descriptor. */
static int getPSMFileSize(PSMHandle h, size_t *size) {
  int ret = 0;
  LARGE_INTEGER i64;
  BOOL bret;
  uint64_t size64;

  LOG("  getPSMFileSize\n");

  bret = GetFileSizeEx(h->hFile, &i64);
  if (bret == 0) ret = 1;

  size64 = i64.QuadPart;

  if (sizeof(size_t) > 4) {
    *size = (size_t)size64;
  } else {
    *size = i64.LowPart;
  }

  LOG("  getPSMFileSize ret %d\n", ret);

  return ret;
}

static void getCurrentProcess(PSMProcess* pProc) {
  *pProc = GetCurrentProcessId();
}

static int isEqualProcess(PSMProcess proc1, PSMProcess proc2) {
  int ret = 0;
  if (proc1 == proc2)
    ret = 1;
  return ret;
}

static int isExistProcess(PSMProcess proc) {
  int ret = 0;
  HANDLE hProcess = INVALID_HANDLE_VALUE;
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, proc);
  if (hProcess != INVALID_HANDLE_VALUE) {
    DWORD status;
    if (GetExitCodeProcess(hProcess, &status) != 0) {
      if (status == STILL_ACTIVE) {
        ret = 1;
      }
    }
    CloseHandle(hProcess);
  }
  return ret;
}

static void copyString(char *dest, const char *src, size_t n) {
  strncpy_s(dest, n, src, n-1);
}

static int normalizePath(char *dest, const char *src, size_t dn) {
  int ret = 0;
  DWORD dret;

  LOG("  normalizePath\n");

  dret = GetFullPathNameA(src, (DWORD)dn, dest, NULL);
  if (dret == 0) {
    ret = 1;
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
