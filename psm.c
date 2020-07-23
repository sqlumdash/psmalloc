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

  pHeader->total_refcount = 0;
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

static uint32_t getTotalRefCountPSMHeader(void *pMap) {
  PSMHeader *pHeader = pMap;

  LOG("getTotalRefCountPSMHeader refcount %u\n", pHeader->total_refcount);

  return pHeader->total_refcount;
}

static int addRefPSMHeader(void *pMap, PSMHandle handle) {
  PSMHandle pshared_handle = NULL;
  PSMHeader *pHeader = pMap;
  int i;
  int first_clean;
  int first_inactive;
  PSMProcess proc = handle->proc;
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;

  first_clean = 0;
  first_inactive = -1;
  for (i = 0; i < pHeader->process_max; i++) {
    pNode = &(pHeader->reftable.node[i]);
    pPshared = &(pHeader->reftable.pshared_handle[i]);
    if (pNode->refcount == PSM_REFCOUNT_CLEAN) {
      first_clean = i;
      break;
    }
    if (first_inactive == -1 && pNode->refcount == PSM_REFCOUNT_INACTIVE) {
      first_inactive = i;
      LOG("addRefPSMHeader: The first inactive entry index %d\n", i);
    }
    if ((pNode->refcount > 0 || pNode->refcount == PSM_REFCOUNT_INACTIVE_PENDING)
	&& pf->isEqualProcess(pNode->proc, proc)) {
      LOG("addRefPSMHeader: The same shared memory was used previously on the process pid(%d)\n",
	  pf->getProcessID(&proc));
      break;
    }
  }

  if (i == pHeader->process_max) {
    first_clean = pHeader->process_max;
    LOG("addRefPSMHeader: No clean entries\n");
  } else {
    LOG("addRefPSMHeader: The first clean entry index %d\n", first_clean);
  }
  
  if ((pNode->refcount > 0 || pNode->refcount == PSM_REFCOUNT_INACTIVE_PENDING)
      && pf->isEqualProcess(pNode->proc, proc)) {
    if (pNode->refcount == PSM_REFCOUNT_MAX) {
      LOG("addRefPSMHeader: Reached the max reference count on the same process pid(%d)\n",
	  pf->getProcessID(&pNode->proc));
      return 1;
    }
    if (pNode->refcount == PSM_REFCOUNT_INACTIVE_PENDING)
      pNode->refcount = PSM_REFCOUNT_CLEAN;
    pNode->refcount++;
    pshared_handle = *pPshared;
  } else {
    if (first_inactive == -1 && first_clean >= pHeader->process_max) {
      LOG("addRefPSMHeader: Reached the max processes PSM_PROCESS_MAX(%d)\n", pHeader->process_max);
      return 1;
    }

    i = first_clean;
    if (first_inactive != -1) {
      i = first_inactive;
    }

    pNode = &(pHeader->reftable.node[i]);
    pPshared = &(pHeader->reftable.pshared_handle[i]);
    pNode->refcount = 1;
    pNode->refcount_inherit = 0;
    memcpy(&pNode->proc, &proc, sizeof(PSMProcess));
  }

  if (pshared_handle == NULL) {
    pshared_handle = malloc(sizeof(struct PSMHandleTag));
    if (pshared_handle == NULL) {
      LOG("addRefPSMHeader: Cannot allocate process shared handle\n");
      return 1;
    }

    LOG("addRefPSMHeader: New allocation of process shared handle on the process pid (%d) index %d\n",
	pf->getProcessID(&proc), i);
    *pPshared = pshared_handle;

    handle->pshared = pshared_handle;
    memcpy(pshared_handle, handle, sizeof(struct PSMHandleTag));
    
    LOG("addRefPSMHeader: Shared PSMHandle is at %p\n", pshared_handle);
  }
  
  pHeader->total_refcount++;
  LOG("addRefPSMHeader: current refcount %p\n", pHeader->total_refcount);
  return 0;
}

static int dropRefPSMHeader(void *pMap, PSMRefTableNode *pNode) {
  PSMHeader *pHeader = pMap;

  LOG("dropRefPSMHeader: process pid %d\n", pf->getProcessID(&(pNode->proc)));

  if (pNode->refcount <= 0 || pHeader->total_refcount == 0) {
    LOG("dropRefPSMHeader: inconsistent reference count (refcount %d, total_refcount %d)\n",
	pNode->refcount, pHeader->total_refcount);
    return 1;
  }

  pNode->refcount--;
  LOG("dropRefPSMHeader: dropped reference count for process %d, refcount %d\n",
      pf->getProcessID(&(pNode->proc)), pNode->refcount);

  if (pNode->refcount == PSM_REFCOUNT_CLEAN) {
    if (pNode->refcount_inherit == 0) {
      pNode->refcount = PSM_REFCOUNT_INACTIVE;
      LOG("dropRefPSMHeader: inactivate entry\n");
    } else {
      pNode->refcount = PSM_REFCOUNT_INACTIVE_PENDING;
      LOG("dropRefPSMHeader: inactivate pending entry\n");
    }
  }

  pHeader->total_refcount--;
  return 0;
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
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;

  pf->getCurrentProcess(&current_proc);
  LOG("current process pid %d\n", pf->getProcessID(&current_proc));

  for (i = 0; i < pHeader->process_max; i++) {
    pNode = &pHeader->reftable.node[i];
    pPshared = &pHeader->reftable.pshared_handle[i];
    refcount = pNode->refcount;
    assert(refcount >= PSM_REFCOUNT_INACTIVE_PENDING);
    memcpy(&proc, &pNode->proc, sizeof(PSMProcess));

    if (refcount == PSM_REFCOUNT_CLEAN) {
      break;
    } else if (refcount != PSM_REFCOUNT_INACTIVE) {
      /* check for the existance of the process with ID */
      ret = pf->isExistProcess(proc);
      if (refcount == PSM_REFCOUNT_INACTIVE_PENDING)
	refcount = 0;
      refcount += pNode->refcount_inherit;
      if (ret == 1) {
        /* the process exists */
        sum_refcount += refcount;
        if (pf->isEqualProcess(current_proc, proc))
          pshared_handle = *pPshared;
      } else {
        /* the process does not exist */
        pNode->refcount = PSM_REFCOUNT_INACTIVE;
        LOG("refreshRefCountPSMHeader: Found exited process %d\n", pf->getProcessID(&proc));
      }
    }
  }

  if (pHeader->total_refcount != sum_refcount) {
    pHeader->total_refcount = sum_refcount;
    LOG("refreshRefCountPSMHeader: Refreshed refcount: current refcount = %d\n", sum_refcount);
  } else {
    LOG("refreshRefCountPSMHeader: All good: current refcount = %d\n", sum_refcount);
  }

  return pshared_handle;
}

static PSMRefTableNode *getRefTableNode(void *pMap, PSMProcess proc, PSMHandle **ppPshared)
{
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;
  PSMHeader *pHeader = pMap;
  int i;

  for (i = 0; i < pHeader->process_max; i++) {
    if (pHeader->reftable.node[i].refcount == PSM_REFCOUNT_CLEAN)
      break;
    if ((pHeader->reftable.node[i].refcount > 0 || pHeader->reftable.node[i].refcount == PSM_REFCOUNT_INACTIVE_PENDING)
	&& pf->isEqualProcess(pHeader->reftable.node[i].proc, proc)) {
      LOG("getRefTableNode: found the process pid(%d) in the reference table.\n", pf->getProcessID(&proc));
      pNode = &(pHeader->reftable.node[i]);
      pPshared = &(pHeader->reftable.pshared_handle[i]);
      break;
    }
  }

  if (ppPshared) {
    *ppPshared = pPshared;
  }

  LOG("getRefTableNode: reference table node %p\n", pNode);
  return pNode;
}

static int addInheritRefCount(void *pMap, PSMRefTableNode *pNode) {
  PSMHeader *pHeader = pMap;

  if (pNode->refcount_inherit == PSM_REFCOUNT_MAX)
    return 1;
  if (pHeader->total_refcount == PSM_TOTAL_REFCOUNT_MAX)
    return 1;

  pNode->refcount_inherit++;
  pHeader->total_refcount++;

  LOG("addInheritRefCount: Inherit refcount: %d\n", pNode->refcount_inherit);
  LOG("addInheritRefCount: Total refcount: %d\n", pHeader->total_refcount);

  return 0;
}

static int dropInheritRefCount(void *pMap, PSMRefTableNode *pNode) {
  PSMHeader *pHeader = pMap;

  if (pNode->refcount_inherit == 0)
    return 1;
  if (pHeader->total_refcount == 0)
    return 1;

  pNode->refcount_inherit--;
  pHeader->total_refcount--;

  if (pNode->refcount == PSM_REFCOUNT_INACTIVE_PENDING && pNode->refcount_inherit == 0) {
    pNode->refcount = PSM_REFCOUNT_INACTIVE;
    LOG("dropInheritRefCount: inactivate entry\n");
  }

  LOG("dropInheritRefCount: Inherit refcount: %d\n", pNode->refcount_inherit);
  LOG("dropInheritRefCount: Total refcount: %d\n", pHeader->total_refcount);

  return 0;
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

  if ((tryMapRange(handle, pTop, initSize, PSM_AUTO_ADDR_UNIT, reqSlots, originSlot, allSlots-1)) != 0 && (originSlot != 0))
    tryMapRange(handle, pTop, initSize, PSM_AUTO_ADDR_UNIT, reqSlots, 0, originSlot-1);

ret:
#else
  (void)initSize;
#endif
  LOG("mapAuto: %p\n", handle->pMap);
  return handle->pMap;
}

PSM_EXPORT void PSMinit(const char *name, const size_t initSize, void *pReqAddress, PSMHandle* pHandle) {
  int is_locked = 0;
  int release_handle = 1;
  int is_initiator = 0;
  int ret = 0;
  size_t fileSize = 0;
  PSMHandle handle = NULL;
  mspace msp = NULL;
  PSMHandle pshared_handle = NULL;

  LOG("PSMinit begin: name %s, initSize %ld, pHandle %p\n", name, initSize, pHandle);

  assert(pHandle != NULL);
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
      refcount = getTotalRefCountPSMHeader(handle->pMap);
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
	    LOG("PSMinit: duplicate process shared handle\n");
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
    
    if (addRefPSMHeader(handle->pMap, handle)) {
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
  mspace msp = NULL;
  void *pMap = NULL;
  int is_locked = 0;
  int ret = 0;
  int process_final = 0;
  int true_final = 0;
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;

  LOG("PSMdeinit begin: handle %p\n", handle);

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

  pNode = getRefTableNode(pMap, handle->proc, &pPshared);
  if (pNode == NULL || *pPshared == NULL) goto end_of_deinit;
  if (pNode->refcount == 1)
      process_final = 1;
  if (dropRefPSMHeader(pMap, pNode)) goto end_of_deinit;
  if (pNode->refcount == PSM_REFCOUNT_INACTIVE ||
      pNode->refcount == PSM_REFCOUNT_INACTIVE_PENDING) {
    free(*pPshared);
    *pPshared = NULL;
  }
  if (getTotalRefCountPSMHeader(pMap) == 0)
    true_final = 1;

  if (true_final)
    destroy_mspace(msp);
  else if (process_final)
    detach_mspace(msp);
  if (true_final || process_final)
    pf->unmapPSM(handle);

  if (true_final) {
    ret = pf->emptyPSMFile(handle);
    if (ret) goto end_of_deinit;

#if !defined(PSM_REMOVE_SHARED_FILE_POST_CLOSE)
    ret = pf->removePSMFile(handle);
    if (ret) goto end_of_deinit;
    LOG("PSMdeinit: remove shared memory file (%s)\n", handle->name);
#endif
  }
  pMap = NULL;

end_of_deinit:
  if (handle != NULL) {
    if (is_locked) pf->unlockPSM(handle);
    pf->closePSM(handle);
#if defined(PSM_REMOVE_SHARED_FILE_POST_CLOSE)
    if (true_final) { 
      ret = pf->removePSMFile(handle);
      LOG("PSMdeinit: remove shared memory file (%s)\n", handle->name);
    }
#endif
    free(handle);
  }

  LOG("PSMdeinit end: handle %p\n", handle);
}

PSM_EXPORT PSMHandle PSMprepareInherit(const PSMHandle handle) {
  PSMHandle ret_handle = NULL;
  void *pMap = NULL;
  int is_locked = 0;
  int ret = 0;
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;
  
  LOG("PSMprepareInherit begin: handle %p\n", handle);

  if (handle == NULL)
    goto end_of_prepare_inherit;

  ret = pf->lockPSM(handle);
  if (ret) goto end_of_prepare_inherit;
  is_locked = 1;

  pMap = handle->pMap;
  if (!checkPSMHeader(pMap, 1)) goto end_of_prepare_inherit;

  pNode = getRefTableNode(pMap, handle->proc, &pPshared);
  if (pNode == NULL || *pPshared == NULL) goto end_of_prepare_inherit;
  if (addInheritRefCount(pMap, pNode)) goto end_of_prepare_inherit;

  /* The parent pshared_handle's pshared_refcount is used to
     hand over the actual reference count inherited from parent to child */
  (*pPshared)->pshared_refcount = pNode->refcount;

  ret_handle = handle;

end_of_prepare_inherit:
  if (handle != NULL) {
    if (is_locked) pf->unlockPSM(handle);
  }

  LOG("PSMprepareInherit end: handle %p\n", ret_handle);
  return ret_handle;
}

PSM_EXPORT PSMHandle PSMexecuteInherit(const PSMHandle handle) {
  LOG("PSMexecuteInherit begin: handle %p\n", handle);

  PSMHandle ret_handle = NULL;
  void *pMap = NULL;
  mspace msp = NULL;
  int is_locked = 0;
  int ret = 0;
  PSMProcess current_proc;
  PSMHandle parent_pshared_handle = NULL;
  PSMRefTableNode *pNode = NULL;
  PSMHandle *pPshared = NULL;

  LOG("PSMexecuteInherit: handle %p\n", handle);

  if (handle == NULL)
    goto end_of_execute_inherit;

  pf->getCurrentProcess(&current_proc);
  if (pf->isEqualProcess(current_proc, handle->proc)) {
    LOG("PSMexecuteInherit: bad usage\n");
    goto end_of_execute_inherit;
  }

  LOG("PSMexecuteInherit: current process %d inherits resources from process %d.\n",
      pf->getProcessID(&current_proc), pf->getProcessID(&handle->proc));

  ret = pf->lockPSM(handle);
  if (ret) goto end_of_execute_inherit;
  is_locked = 1;

  pMap = handle->pMap;
  if (!checkPSMHeader(pMap, 1)) goto end_of_execute_inherit;

  pNode = getRefTableNode(pMap, handle->proc, NULL);
  if (pNode == NULL || pNode->refcount_inherit <= 0) {
    LOG("PSMexecuteInherit: not prepared for inheritance\n");
    goto end_of_execute_inherit;
  }
  if (dropInheritRefCount(pMap, pNode)) {
    LOG("PSMexecuteInherit: failed to drop reference count\n");
    goto end_of_execute_inherit;
  }

  /* inherited handle is overrided with current process. */
  handle->proc = current_proc;

  parent_pshared_handle = handle->pshared;

  /* We needs the last user of parent pshared handle to free it. */
  LOG("PSMexecuteInherit: pshared_refcount %d\n", parent_pshared_handle->pshared_refcount);
  if (parent_pshared_handle->pshared_refcount > 0)
    parent_pshared_handle->pshared_refcount--;

  if (parent_pshared_handle->pshared_refcount == 0) {
    LOG("PSMexecuteInherit: free unused resources inherited from parent\n");
    detach_mspace(parent_pshared_handle->pAllocator);
    free(parent_pshared_handle);
  }

  pNode = getRefTableNode(pMap, current_proc, &pPshared);
  if (pNode && *pPshared) {
    pf->dupPSMHandle(handle, *pPshared);
    msp = handle->pAllocator;
  } else {
    /* The first user of the process needs to allocate process specific resource for dlmalloc. */
    msp = attach_mspace((char*)pMap + PSM_PSMHEADER_SIZE, handle->name);
  }

  if (msp == NULL) goto end_of_execute_inherit;
  handle->pAllocator = msp;

  if (addRefPSMHeader(pMap, handle)) goto end_of_execute_inherit;

  ret_handle = handle;

end_of_execute_inherit:
  if (handle != NULL) {
    if (is_locked) pf->unlockPSM(handle);
  }

  LOG("PSMexecuteInherit end: handle %p\n", ret_handle);
  return ret_handle;
}

PSM_EXPORT void PSMcancelInherit(const PSMHandle handle) {
  void *pMap = NULL;
  int is_locked = 0;
  PSMRefTableNode *pNode = NULL;

  LOG("PSMcancelInherit begin: handle %p\n", handle);

  if (handle == NULL)
    goto end_of_cancel_inherit;

  if (pf->lockPSM(handle)) goto end_of_cancel_inherit;
  is_locked = 1;

  pMap = handle->pMap;
  if (!checkPSMHeader(pMap, 1)) goto end_of_cancel_inherit;

  pNode = getRefTableNode(pMap, handle->proc, NULL);
  if (pNode == NULL) goto end_of_cancel_inherit;
  if (dropInheritRefCount(pMap, pNode)) {
    LOG("PSMcancelInherit: failed to drop reference count\n");
  }

end_of_cancel_inherit:
  if (handle != NULL) {
    if (is_locked) pf->unlockPSM(handle);
  }

  LOG("PSMcancelInherit end: handle %p\n", handle);
  return;
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
