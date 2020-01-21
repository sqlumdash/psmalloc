/*
** SPDX-License-Identifier: MIT
**
** Copyright (c) 2019 Toshiba Corporation
*/
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include "psm.h"
#include "psm_dlmalloc.h"

PSM_DECLARE_HOOK(psm_init_in_lock);
PSM_DECLARE_HOOK(psm_deinit_in_lock);

static PSMPlatformFunctionsType *pf = &PSMPlatformFunctions;

#ifdef TESTLOG
#define LOG( ...) pf->log(__VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

static void resetPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;

  memset(pMap, 0, PSM_PSMHEADER_SIZE);

  pHeader->refcount = 0;
  pHeader->process_max = PSM_PROCESS_MAX;
  pHeader->header_size = PSM_PSMHEADER_SIZE;
  pHeader->ptr_size = (uint32_t)sizeof(pMap);
  pHeader->pReqAddress = pMap;
  pHeader->magic = PSM_PSMHEADER_MAGIC;
}

static int checkPSMHeader(void *pMap, int do_address_checking) {
  PSMHeader *pHeader = pMap;

  if ((pHeader->magic != PSM_PSMHEADER_MAGIC) ||
      (pHeader->process_max != PSM_PROCESS_MAX) ||
      (pHeader->header_size != PSM_PSMHEADER_SIZE) ||
      (pHeader->ptr_size != (uint32_t)sizeof(pMap))) {
    LOG("checkPSMHeader: Inconsistent process common settings\n");
    LOG("checkPSMHeader: magic %x\n", pHeader->magic);
    LOG("checkPSMHeader: process_max %d\n", pHeader->process_max);
    LOG("checkPSMHeader: header_size %d\n", pHeader->header_size);
    LOG("checkPSMHeader: ptr_size %d\n", pHeader->ptr_size);
    return 0;
  }

  if (do_address_checking && pHeader->pReqAddress != pMap) {
    LOG("checkPSMHeader: Inconsistent process address Header %p, mapped %p\n", pHeader->pReqAddress, pMap);
    return 0;
  }

  return 1;
}

static void *getReqAddressPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;

  LOG("getReqAddressPSMHeader %p\n", pHeader->pReqAddress);

  return pHeader->pReqAddress;
}

static uint32_t getRefCountPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;

  LOG("getRefCountPSMHeader refcount %u\n", pHeader->refcount);

  return pHeader->refcount;
}

static PSMHandle addRefPSMHeader(void *pMap, PSMHandle handle) {
  PSMHandle pshared_handle = NULL;
  PSMHeader *pHeader = pMap;
  int i;
  int check_entries;
  int inactive_first;
  PSMProcess proc;
  pf->getCurrentProcess(&proc);

  check_entries = 0;
  inactive_first = -1;
  for (i = 0; i < pHeader->process_max; i++) {
    if (pHeader->reftable.refcount[i] == PSM_REFCOUNT_CLEAN) {
      check_entries = i;
      break;
    }
    if (inactive_first == -1 && pHeader->reftable.refcount[i] == PSM_REFCOUNT_INACTIVE) {
      inactive_first = i;
      LOG("addRefPSMHeader: The first inactive entry index %d\n", i);
    }
  }

  if (i == pHeader->process_max) {
    check_entries = pHeader->process_max;
  }

  LOG("addRefPSMHeader: Check entries %d\n", check_entries);

  for (i = 0; i < check_entries; i++) {
    if (pHeader->reftable.refcount[i] > 0 && pf->isEqualProcess(pHeader->reftable.proc[i], proc)) {
      LOG("addRefPSMHeader: Yet another init on the same shared memory and process pid(%d)\n", pf->getProcessID(&proc));
      pHeader->reftable.refcount[i]++;
      pshared_handle = pHeader->reftable.pshared_handle[i];
      break;
    }
  }

  if (i == check_entries) {
    if (inactive_first == -1 && check_entries >= PSM_PROCESS_MAX) {
      LOG("addRefPSMHeader: Reached the max processes PSM_PROCESS_MAX(%d)\n", PSM_PROCESS_MAX);
      return NULL;
    }

    pshared_handle = malloc(sizeof(struct PSMHandleTag));
    if (pshared_handle == NULL) {
      LOG("addRefPSMHeader: Cannot allocate process shared handle\n");
      return NULL;
    }

    if (inactive_first != -1) {
      i = inactive_first;
    }

    LOG("addRefPSMHeader: New init on the process pid (%d) for the shared memory at index %d\n", pf->getProcessID(&proc), i);
    memcpy(&pHeader->reftable.proc[i], &proc, sizeof(PSMProcess));
    pHeader->reftable.refcount[i] = 1;
    pHeader->reftable.pshared_handle[i] = pshared_handle;
    memcpy(pshared_handle, handle, sizeof(struct PSMHandleTag));
    LOG("addRefPSMHeader: Shared PSMHandle is at %p\n", pshared_handle);
  }
  
  pHeader->refcount++;
  LOG("addRefPSMHeader: current refcount %p\n", pHeader->refcount);
  return pshared_handle;
}

static PSMHandle dropRefPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;
  int i, check_processes;
  PSMProcess proc;
  PSMHandle pshared_handle = NULL;

  pf->getCurrentProcess(&proc);
  LOG("current process pid %d\n", pf->getProcessID(&proc));

  check_processes = 0;
  for (i = 0; i < pHeader->process_max; i++) {
    if (pHeader->reftable.refcount[i] == PSM_REFCOUNT_CLEAN) {
      check_processes = i;
      break;
    }
  }

  LOG("dropRefPSMHeader: Check entries %d\n", check_processes);

  for (i = 0; i < check_processes; i++) {
    if (pf->isEqualProcess(pHeader->reftable.proc[i], proc)) {
      pshared_handle = pHeader->reftable.pshared_handle[i];
      pHeader->reftable.refcount[i]--;
      LOG("dropRefPSMHeader: Drop reference at index %d, process %d, refcount %d\n",
              i, pf->getProcessID(&proc), pHeader->reftable.refcount[i]);

      if (pHeader->reftable.refcount[i] == PSM_REFCOUNT_CLEAN) {
        /* Mark as inactive entry */
        pHeader->reftable.refcount[i] = PSM_REFCOUNT_INACTIVE;
        LOG("dropRefPSMHeader: Mark as inactive at index %d\n", i);
        if (pshared_handle) {
          free(pshared_handle);
          LOG("dropRefPSMHeader: Free shared PSMHandle\n");
        }
        pshared_handle = NULL;
        pHeader->reftable.pshared_handle[i] = pshared_handle;
      }
      break;
    }
  }

  if (i == check_processes) {
    LOG("dropRefPSMHeader: Called by unused process %d\n", pf->getProcessID(&proc));
    return pshared_handle;
  }

  pHeader->refcount--;
  return pshared_handle;
}

static PSMHandle refreshRefCountPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;
  int i;
  PSMProcess proc;
  PSMProcess current_proc;
  uint32_t sum_refcount = 0;
  int32_t refcount = 0;
  int ret;
  PSMHandle pshared_handle = NULL;

  pf->getCurrentProcess(&current_proc);
  LOG("current process pid %d\n", pf->getProcessID(&current_proc));

  for (i = 0; i < pHeader->process_max; i++) {
    refcount = pHeader->reftable.refcount[i];
    assert(refcount >= -1);
    memcpy(&proc, &pHeader->reftable.proc[i], sizeof(PSMProcess));

    if (refcount == PSM_REFCOUNT_CLEAN) {
      break;
    } else if (refcount != PSM_REFCOUNT_INACTIVE) {
      /* check for the existance of the process with ID */
      ret = pf->isExistProcess(proc);
      if (ret == 1) {
        /* the process exists */
        sum_refcount += refcount;
        if (pf->isEqualProcess(current_proc, proc))
          pshared_handle = pHeader->reftable.pshared_handle[i];
      } else {
        /* the process does not exist */
        pHeader->reftable.refcount[i] = PSM_REFCOUNT_INACTIVE;
        LOG("refreshRefCountPSMHeader: Found exited process %d\n", pf->getProcessID(&proc));
      }
    }
  }

  if (pHeader->refcount != sum_refcount) {
    pHeader->refcount = sum_refcount;
    LOG("refreshRefCountPSMHeader: Refreshed refcount: current refcount = %d\n", sum_refcount);
  } else {
    LOG("refreshRefCountPSMHeader: All good: current refcount = %d\n", sum_refcount);
  }

  return pshared_handle;
}

#ifdef ENABLE_PSM_AUTO_ADDRESS
static uint64_t calcStrHash64(const char *pstr) {
  uint64_t hval = 0;
  unsigned char ch;

  while( (ch = (unsigned char)*pstr++)!=0 ){
    hval = 0x9e3779b1 * hval + ch;
  }
  return hval;
}

static int tryMapRange(PSMHandle handle, void *pTop,
                       const size_t initSize, const size_t unitSize,
                       uint64_t reqSlots, uint64_t beginSlot, uint64_t endSlot) {
  uint64_t slot;

  for (slot = beginSlot; slot <= endSlot; slot++) {
    /* no enough slots */
    if ((endSlot - slot + 1) < reqSlots)
      break;

    /* try to map from (slot) to (slot + reqSlots) */
    if (pf->mapPSM(handle, initSize, (char*)pTop + slot * unitSize) == 0) {
      return 0;
    }
  }

  return 1;
}
#endif

static void *mapAuto(PSMHandle handle, const size_t initSize) {
#ifdef ENABLE_PSM_AUTO_ADDRESS
  void *pTop = (void*)NULL;
  uint64_t range = 0;
  uint64_t unitSize;
  uint64_t allSlots;
  uint64_t reqSlots;
  uint64_t originSlot;

  if ((uint32_t)sizeof(void *) == sizeof(uint32_t)) {
    pTop = (void*)PSM_AUTO_ADDR32_TOP;
    range = PSM_AUTO_ADDR32_RANGE;
  } else {
    pTop = (void*)PSM_AUTO_ADDR64_TOP;
    range = PSM_AUTO_ADDR64_RANGE;
  }

  unitSize = PSM_AUTO_ADDR_UNIT;
  allSlots = range / unitSize;
  reqSlots = (initSize + unitSize - 1) / unitSize;

  if (reqSlots == 0 || allSlots < reqSlots) {
    goto ret;
  }

  originSlot = calcStrHash64(handle->name) % allSlots;
  LOG("hash slot: %lx\n", originSlot);

  if ((tryMapRange(handle, pTop, initSize, unitSize, reqSlots, originSlot, allSlots-1)) != 0 && (originSlot != 0))
    tryMapRange(handle, pTop, initSize, unitSize, reqSlots, 0, originSlot-1);

ret:
#else
  (void)initSize;
#endif
  LOG("mapAuto: %p\n", handle->pMap);
  return handle->pMap;
}

PSM_EXPORT void PSMinit(const char *name, const size_t initSize, void *pReqAddress, PSMHandle* pHandle) {
  LOG("PSMinit begin: name %s, initSize %ld, pHandle %p\n", name, initSize, pHandle);

  assert(pHandle != NULL);

  int is_locked = 0;
  int release_handle = 1;
  int is_initiator = 0;
  int ret = 0;
  size_t fileSize = 0;
  PSMHandle handle = NULL;
  mspace msp = NULL;
  PSMHandle pshared_handle = NULL;

  *pHandle = NULL;

  if (name == NULL) goto end_of_init;
  if (initSize <= PSM_PSMHEADER_SIZE) goto end_of_init;

  handle = (PSMHandle)malloc(sizeof(struct PSMHandleTag));
  if (handle == NULL) goto end_of_init;
  pf->resetPSMHandle(handle);

  if (pf->openPSM(handle, name)) goto end_of_init;

  if (pf->normalizePath(handle->name, name, PSM_FILEPATH_MAX)) goto end_of_init;
  LOG("PSMinit: normalized path %s\n", handle->name);

  ret = pf->lockPSM(handle);
  if (ret) goto end_of_init;
  is_locked = 1;

  PSM_INSERT_HOOK(psm_init_in_lock);
  
  ret = pf->getPSMFileSize(handle, &fileSize);
  if (ret) goto end_of_init;

  LOG("PSMinit: file size %zu, init size %zu\n", fileSize, initSize);

  if (fileSize != 0) {
    /* Do refresh header first */
    uint32_t refcount = 0;

    if (fileSize >= PSM_PSMHEADER_SIZE) {
      /* Maybe active shared memory with different initSize so need to check header. */
      if (pf->mapPSM(handle, fileSize, NULL)) goto end_of_init;
      pshared_handle = refreshRefCountPSMHeader(handle->pMap);
      refcount = getRefCountPSMHeader(handle->pMap);
      pf->unmapPSM(handle);
    } else {
      /* Maybe it is broken shared memory so just empty it. */
    }

    if (refcount == 0) {
      LOG("PSMinit: force empty unreferenced or invalid shared memory\n");
      pf->emptyPSMFile(handle);
      ret = pf->getPSMFileSize(handle, &fileSize);
      if (ret) goto end_of_init;
    } else {
      LOG("PSMinit: active shared memory.\n");
    }
  }

  if (fileSize == 0) {
    LOG("PSMinit: prepare the shared memory file %s\n", name);
    ret = pf->preparePSMFile(handle, initSize);
    if (ret) goto end_of_init;

    is_initiator = 1;
  }

  ret = pf->getPSMFileSize(handle, &fileSize);
  if (ret) goto end_of_init;

  if (fileSize != initSize) {
    goto end_of_init;
  } else {
    if (is_initiator && pReqAddress == NULL) {
      mapAuto(handle, initSize);
    }

    if (handle->pMap == NULL && pf->mapPSM(handle, initSize, pReqAddress)) goto end_of_init;

    if (is_initiator) {
      msp = create_mspace_with_base((char*)handle->pMap + PSM_PSMHEADER_SIZE,
                                    initSize - PSM_PSMHEADER_SIZE, 1, handle->name);
      LOG("PSMinit: allocator address %p\n", msp);
      resetPSMHeader(handle->pMap);
    } else {
      if (pReqAddress == NULL) {
        if (!checkPSMHeader(handle->pMap, 0)) goto end_of_init;
        /* Re-Mapping with the request address by the initial process. */
        pReqAddress = getReqAddressPSMHeader(handle->pMap);
        if (pReqAddress != handle->pMap) {
          LOG("PSMinit: mapped address %p\n", handle->pMap);
          LOG("PSMinit: expected address %p\n", pReqAddress);
          pf->unmapPSM(handle);
          if (pshared_handle) {
            pf->dupPSMHandle(handle, pshared_handle);
          } else {
            if (pf->mapPSM(handle, initSize, pReqAddress)) goto end_of_init;
          }
        }
        if (!checkPSMHeader(handle->pMap, 1)) goto end_of_init;
      }
      if (pshared_handle) {
        msp = handle->pAllocator;
      } else {
        msp = attach_mspace((char*)handle->pMap + PSM_PSMHEADER_SIZE, handle->name);
      }
    }

    if (msp == NULL) goto end_of_init;

    handle->pAllocator = msp;
    
    if (!addRefPSMHeader(handle->pMap, handle)) {
      goto end_of_init;
    }
  }

  *pHandle = handle;

  /* Keep resouces on success. */
  release_handle = 0;

  LOG("PSMinit: handle %p, pMap %p\n", handle, handle->pMap);

end_of_init:
  if (handle != NULL && release_handle == 1) pf->unmapPSM(handle);
  if (is_locked) pf->unlockPSM(handle);
  if (handle != NULL && release_handle == 1) pf->closePSM(handle);
  if (handle != NULL && release_handle == 1) free(handle);

  LOG("PSMinit end: handle %p\n", *pHandle);
}

PSM_EXPORT void PSMdeinit(const PSMHandle handle) {
  LOG("PSMdeinit begin: handle %p\n", handle);

  PSMHandle pshared_handle = NULL;
  mspace msp = NULL;
  void *pMap = NULL;
  int is_locked = 0;
  int ret = 0;
  LOG("PSMdeinit: handle %p\n", handle);

  if (handle == NULL)
    goto end_of_deinit;

  pMap = handle->pMap;

  ret = pf->lockPSM(handle);
  if (ret) goto end_of_deinit;
  is_locked = 1;

  PSM_INSERT_HOOK(psm_deinit_in_lock);

  msp = handle->pAllocator;

  if (!checkPSMHeader(pMap, 1)) goto end_of_deinit;
  refreshRefCountPSMHeader(pMap);
  pshared_handle = dropRefPSMHeader(pMap);
  if (getRefCountPSMHeader(pMap) == 0) {
    destroy_mspace(msp);
    pf->unmapPSM(handle);
    ret = pf->emptyPSMFile(handle);
    if (ret) goto end_of_deinit;

    ret = pf->removePSMFile(handle);
    if (ret) goto end_of_deinit;
    LOG("PSMdeinit: remove shared memory file (%s)\n", handle->name);
  }
  if (!pshared_handle) pf->unmapPSM(handle);
  pMap = NULL;

end_of_deinit:
  if (handle != NULL) {
    if (is_locked) pf->unlockPSM(handle);
    pf->closePSM(handle);
    free(handle);
  }

  LOG("PSMdeinit end: handle %p\n", handle);
}

PSM_EXPORT void *PSMalloc(const PSMHandle handle, const size_t allocSize) {
  LOG("PSMalloc begin: handle %p, allocSize %ld\n", handle, allocSize);

  void *pAddress = NULL;

  if (handle != NULL) {
    mspace msp = handle->pAllocator;
    pAddress = mspace_malloc(msp, allocSize);
  }

  LOG("PSMalloc end: handle %p, pAddress %p\n", handle, pAddress);
  return pAddress;
}

PSM_EXPORT void PSMfree(const PSMHandle handle, void *pAddress) {
  LOG("PSMfree begin: handle %p, pAddress %p\n", handle, pAddress);

  if (handle != NULL) {
    mspace msp = handle->pAllocator;
    if (pAddress != NULL) {
      mspace_free(msp, pAddress);
    }
  }

  LOG("PSMfree end: handle %p pAddress %p\n", handle, pAddress);
}

PSM_EXPORT int PSMgetError(const PSMHandle handle) {
  LOG("PSMgetError begin: handle %p\n", handle);

  int ret = -1;

  if (handle != NULL) {
    mspace msp = handle->pAllocator;
    ret = mspace_get_ownerdead(msp);
  }

  LOG("PSMgetError end: handle %p, ret=%d\n", handle, ret);

  return ret;
}

PSM_EXPORT void * PSMgetUser(const PSMHandle handle) {
  LOG("PSMgetUser begin: handle %p\n", handle);

  void *user_data = NULL;

  if (handle != NULL) {
    void *pMap = handle->pMap;
    if (!checkPSMHeader(pMap, 1)) {
      return user_data;
    }
    PSMHeader *pHeader = pMap;
    user_data = &(pHeader->user_data[0]);
  }

  LOG("PSMgetUser end: handle %p, ret=%p\n", handle, user_data);

  return user_data;
}
