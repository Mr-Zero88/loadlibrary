//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"
#include "hook.h"
#include "mpclient.h"

#define DRIVER_NAME "driver_standable"
#define RVA2VA(image, rva, type) (type)(ULONG_PTR)((void *)image + rva)

#define DBGLINKER(fmt, ...) printf("%s (%s:%d): " fmt "\n", \
                                   DRIVER_NAME, __func__,   \
                                   __LINE__, ##__VA_ARGS__);

// #define DBGLINKER(fmt, ...)

#ifndef NDEBUG
#define ERROR(fmt, ...) printf("%s (%s:%d): " fmt "\n", \
                               DRIVER_NAME, __func__,   \
                               __LINE__, ##__VA_ARGS__);
#else
#define ERROR(fmt, ...)
#endif
#define TRACE1(fmt, ...) printf("%s (%s:%d): " fmt "\n", \
                                DRIVER_NAME, __func__,   \
                                __LINE__, ##__VA_ARGS__);

struct pe_image image = {
    .entry = NULL,
    .name = &"driver_standable.dll",
};

__attribute__((ms_abi)) void *(*_HmdDriverFactory)(const char *pInterfaceName, int *pReturnCode);

int entry()
{
    // Load the driver_standable module.
    DBGLINKER("Loading driver_standable.dll...");
    if (pe_load_library("engine/win64/driver_standable.dll", &image.image, &image.size) == false)
    {
        DBGLINKER("You must add the dll and vdm files to the engine directory");
        return 1;
    }
    DBGLINKER("driver_standable.dll loaded successfully");

    // Handle relocations, imports, etc.
    DBGLINKER("Linking driver_standable.dll...");
    link_pe_images(&image, 1);
    DBGLINKER("driver_standable.dll linked successfully");

    //     PIMAGE_DOS_HEADER DosHeader;
    //     PIMAGE_NT_HEADERS PeHeader;
    //     // Fetch the headers to get base offsets.
    //     DosHeader = (PIMAGE_DOS_HEADER)image.image;
    //     PeHeader = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    //     // Load any additional exports.
    //     if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/mpengine.map"))
    //     {
    // #ifndef NDEBUG
    //         LogMessage("The map file wasn't found, symbols wont be available");
    // #endif
    //     }
    //     else
    //     {
    //         // Calculate the commands needed to get export and map symbols visible in gdb.
    //         if (IsGdbPresent())
    //         {
    //             LogMessage("GDB: add-symbol-file %s %#x+%#x",
    //                        image.name,
    //                        image.image,
    //                        PeHeader->OptionalHeader.BaseOfCode);
    //             LogMessage("GDB: shell bash genmapsym.sh %#x+%#x symbols_%d.o < %s",
    //                        image.image,
    //                        PeHeader->OptionalHeader.BaseOfCode,
    //                        getpid(),
    //                        "engine/driver_standable.map");
    //             LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
    //             __debugbreak();
    //         }
    //     }

    DBGLINKER("Resolving HmdDriverFactory...");
    if (get_export(&image, "HmdDriverFactory", &_HmdDriverFactory) == -1)
    {
        errx(EXIT_FAILURE, "Failed to resolve driver_standable entrypoint");
        return 1;
    }
    DBGLINKER("resolved HmdDriverFactory to %p successfully", _HmdDriverFactory);

    // Call DllMain()
    DBGLINKER("Calling DllMain(MPENENGN, DLL_PROCESS_DETACH, NULL)...");
    image.entry(&image, DLL_PROCESS_ATTACH, NULL); // (PVOID)'MPENENGN'    DLL_PROCESS_DETACH
    DBGLINKER("Engine loaded successfully");

    // Return successfull return code.
    return 0;
}

extern void *HmdDriverFactory(const char *pInterfaceName, int *pReturnCode)
{
    DBGLINKER("HmdDriverFactory(\"%s\", *%p -> %d)", pInterfaceName, pReturnCode, *pReturnCode);
    void *result = _HmdDriverFactory(pInterfaceName, pReturnCode); //
    DBGLINKER("HmdDriverFactory returned %p, with code *%p -> %d", result, pReturnCode, *pReturnCode);
    return result;
}

// Test the driver_standable module.
int main(int argc, char **argv, char **envp)
{
    DBGLINKER("Starting driver_standable test...");
    if (entry() != 0)
        return 1;

    int pReturnCode = 0x0;
    const char *pInterfaceName = "IServerTrackedDeviceProvider_004";
    void *interface = HmdDriverFactory(pInterfaceName, &pReturnCode);
    if (interface == NULL)
    {
        DBGLINKER("Failed to get interface %s with code %d", pInterfaceName, pReturnCode);
        return 1;
    }
    DBGLINKER("Got interface %p %s", interface, interface);
}