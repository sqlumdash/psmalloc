/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#ifndef PSM_LINUX_H
#define PSM_LINUX_H

#include <sys/types.h>

#define PSM_FILEPATH_MAX (4096)
#undef PSM_REMOVE_SHARED_FILE_POST_CLOSE

typedef pid_t PSMProcess;

typedef struct PSMHandleTag *PSMHandle;

struct PSMHandleTag {
  int fd;
  void *pMap;
  char name[PSM_FILEPATH_MAX];
  void *pAllocator;
  size_t length;
  PSMProcess proc;
  PSMHandle pshared;
  int pshared_refcount;
};

#define PSM_EXPORT

#endif /* !PSM_LINUX_H */
