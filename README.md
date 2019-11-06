## PSMalloc (Process Shared Memory ALLOCator)
PSMalloc is a memory allocator library to share between multiple processes.
The shared memory can be created per shared memory file basis with the fixed size.
The shared memory have the same virtual address in all processes.

## APIs
* PSMinit
This API will map the shared memory file with the name of 'name' and the size of fixed size 'initSize' bytes, and return a PSM handle 'pHandle'.
If the calling process is the first user of the shared memory file, the shared memory file is created at the time of this API call.
The argument 'pReqAddress' is a parameter to specify the virtual address to map the shared memory file. If the virtual address is set
to zero, virtual address will be determined automatically.
If the macro ENABLE_PSM_AUTO_ADDRESS in psm.h is defined, the virtual address is determined at from top of PSM_AUTO_ADDR{32,64}_TOP to top + PSM_AUTO_ADDR{32,64}_RANGE.

* PSMdeinit
This API will unmap the shared memory file. And then it will delete the shared memory file if there is no any other user process other then the calling process.

* PSMalloc
This API will allocate a memory space with the size of 'allocSize' from the shared memory specified by the PSM handle.

* PSMfree
This API will free the memory space allocated by PSMalloc API.

* PSMgetUser
This API returns the fixed address of 8 bytes free space in the shared memory. This space can be used imeddiately after the PSMinit call.

* PSMgetError
This API returns error status of the shared memory file. If the user process exited abnormally at critical section code of PSM mutex, the shared memory is not safe for any further operations. In such condition, PSMgetError return none-zero value.

## Notices
* Shared memory file cleanup
The shared file has user processes information into the file, and the file is deleted if the all of user processes are aknowledged to be disappeared.
If the user process is exited without calling PSMdeinit API, the shared file remains until a subsequent user process calls the PSMinit or PSMdeinit API for the same shared file.

## Supported Platforms
* Windows
* Linux

## How to build PSMalloc
### Linux
<pre>
$ make -f Makefile.linux-gcc
(32bit library will be built with M64=no)
The output library is build/libpsm.so.
</pre>

### Windows (Visual Studio)
<pre>
Browse psm.sln and build the project psm_library.
The output library is bin/{x64,x86}/{Debug,Release}/psm_library.dll.
</pre>

## Lisence
This software is released under the MIT License, see LICENSE file.

Copyright (c) 2019 Toshiba Corporation
