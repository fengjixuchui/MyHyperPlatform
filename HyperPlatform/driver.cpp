// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif

#include "driver.h"
#include "common.h"
#include "global_object.h"
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
_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) 
{
    UNREFERENCED_PARAMETER(registry_path);
    PAGED_CODE();

    __debugbreak();

    driver_object->DriverUnload = DriverpDriverUnload;
    
    bool need_reinitialization = false;
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\HyperPlatform.log";
    static const ULONG kLogLevel = (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName : kLogPutLevelDebug | kLogOptDisableFunctionName;
    NTSTATUS status = LogInitialization(kLogLevel, kLogFilePath);// Initialize log functions
    if (status == STATUS_REINITIALIZATION_NEEDED) {
        need_reinitialization = true;
    } else if (!NT_SUCCESS(status)) {
        return status;
    }
    
    if (!DriverpIsSuppoetedOS()) {// Test if the system is supported
        LogTermination();
        return STATUS_CANCELLED;
    }
    
    status = GlobalObjectInitialization();// Initialize global variables
    if (!NT_SUCCESS(status)) {
        LogTermination();
        return status;
    }
    
    status = PerfInitialization();// Initialize perf functions
    if (!NT_SUCCESS(status)) {
        GlobalObjectTermination();
        LogTermination();
        return status;
    }
    
    status = UtilInitialization(driver_object);// Initialize utility functions
    if (!NT_SUCCESS(status)) {
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }
    
    status = PowerCallbackInitialization();// Initialize power callback
    if (!NT_SUCCESS(status)) {
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }
    
    status = HotplugCallbackInitialization();// Initialize hot-plug callback
    if (!NT_SUCCESS(status)) {
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }
    
    status = VmInitialization();// Virtualize all processors
    if (!NT_SUCCESS(status)) {
        HotplugCallbackTermination();
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }
    
    if (need_reinitialization) {// Register re-initialization for the log functions if needed
        LogRegisterReinitialization(driver_object);
    }

    HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
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
    GlobalObjectTermination();
    LogTermination();
}


_Use_decl_annotations_ bool DriverpIsSuppoetedOS()
// Test if the system is one of supported OS versions
{
    PAGED_CODE();

    RTL_OSVERSIONINFOW os_version = {};
    NTSTATUS status = RtlGetVersion(&os_version);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
        return false;
    }
    
    if (!IsX64() && reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {// 4-gigabyte tuning (4GT) should not be enabled
        return false;
    }

    return true;
}

}  // extern "C"
