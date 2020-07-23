/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#ifndef PSM_WIN_H
#define PSM_WIN_H

#include <windows.h>

#define PSM_FILEPATH_MAX (MAX_PATH)
#define PSM_REMOVE_SHARED_FILE_POST_CLOSE

typedef DWORD PSMProcess;

typedef struct PSMHandleTag *PSMHandle;

struct PSMHandleTag {
  HANDLE hFile;
  HANDLE hMap;
  void *pMap;
  char name[PSM_FILEPATH_MAX];
  void *pAllocator;
  size_t length;
  PSMProcess proc;
  PSMHandle pshared;
  int pshared_refcount;
};

#if PSM_LIBRARY_BUILD
#define PSM_EXPORT __declspec(dllexport)
#else
#define PSM_EXPORT __declspec(dllimport)
#endif

#endif /* !PSM_WIN_H */
