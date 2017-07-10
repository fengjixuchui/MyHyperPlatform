// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif

#include "driver.h"
#include "common.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"

extern "C"
{
DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverpDriverUnload;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#endif


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) 
{
    UNREFERENCED_PARAMETER(registry_path);
    PAGED_CODE();

    __debugbreak();

    driver_object->DriverUnload = DriverpDriverUnload;
    
    bool need_reinitialization = false;

    NTSTATUS status = LogInitialization(kLogPutLevelDebug | kLogOptDisableFunctionName, L"\\SystemRoot\\vt.log");// Initialize log functions
    if (status == STATUS_REINITIALIZATION_NEEDED) {
        need_reinitialization = true;
    } else if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = PerfInitialization();// Initialize perf functions
    if (!NT_SUCCESS(status)) {
        LogTermination();
        return status;
    }
    
    status = UtilpInitializePhysicalMemoryRanges();
    if (!NT_SUCCESS(status)) {
        PerfTermination();
        LogTermination();
        return status;
    }
    
    status = PowerCallbackInitialization();// Initialize power callback
    if (!NT_SUCCESS(status)) {
        UtilTermination();
        PerfTermination();
        LogTermination();
        return status;
    }
    
    status = HotplugCallbackInitialization();// Initialize hot-plug callback
    if (!NT_SUCCESS(status)) {
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        LogTermination();
        return status;
    }
    
    status = VmInitialization();// Virtualize all processors
    if (!NT_SUCCESS(status)) {
        HotplugCallbackTermination();
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        LogTermination();
        return status;
    }
    
    if (need_reinitialization) {// Register re-initialization for the log functions if needed
        LogRegisterReinitialization(driver_object);
    }

    return status;
}


_Use_decl_annotations_ static void DriverpDriverUnload(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    PAGED_CODE();

    VmTermination();
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    LogTermination();
}

}  // extern "C"
