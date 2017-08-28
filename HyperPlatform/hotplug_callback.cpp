// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements hot-plug callback functions.

#include "hotplug_callback.h"
#include "log.h"
#include "vm.h"

extern "C"
{
static PROCESSOR_CALLBACK_FUNCTION HotplugCallbackpCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, HotplugCallbackInitialization)
#pragma alloc_text(PAGE, HotplugCallbackTermination)
#pragma alloc_text(PAGE, HotplugCallbackpCallbackRoutine)
#endif

static PVOID g_hpp_callback_handle = nullptr;


NTSTATUS HotplugCallbackInitialization() // Registers power callback
{
    PAGED_CODE();

    g_hpp_callback_handle = KeRegisterProcessorChangeCallback(HotplugCallbackpCallbackRoutine, nullptr, 0);
    if (!g_hpp_callback_handle) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


void HotplugCallbackTermination()// Unregister power callback
{
    PAGED_CODE();

    if (g_hpp_callback_handle) {
        KeDeregisterProcessorChangeCallback(g_hpp_callback_handle);
    }
}


static void HotplugCallbackpCallbackRoutine(PVOID callback_context, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT change_context, PNTSTATUS operation_status)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(callback_context);
    UNREFERENCED_PARAMETER(operation_status);

    if (change_context->State != KeProcessorAddCompleteNotify) {
        return;
    }

    NTSTATUS status = VmHotplugCallback(change_context->ProcNumber);//NTDDI_VERSION >= NTDDI_WIN7
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to virtualize the new processors.");
    }
}

}
