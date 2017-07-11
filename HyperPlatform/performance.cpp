// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements performance measurement functions.

#include "performance.h"
#include "log.h"

static PerfCollector::InitialOutputRoutine PerfpInitialOutputRoutine;
static PerfCollector::OutputRoutine PerfpOutputRoutine;
static PerfCollector::FinalOutputRoutine PerfpFinalOutputRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PerfInitialization)
#pragma alloc_text(PAGE, PerfTermination)
#endif

PerfCollector* g_performance_collector;


_Use_decl_annotations_ NTSTATUS PerfInitialization()
{
    PAGED_CODE();

    g_performance_collector = reinterpret_cast<PerfCollector*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PerfCollector), TAG));
    if (!g_performance_collector) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    g_performance_collector->Initialize(PerfpOutputRoutine, PerfpInitialOutputRoutine, PerfpFinalOutputRoutine);// No lock to avoid calling kernel APIs from VMM and race condition here is not an issue.
    return STATUS_SUCCESS;
}


_Use_decl_annotations_ void PerfTermination()
{
    PAGED_CODE();

    if (g_performance_collector) {
        g_performance_collector->Terminate();
        ExFreePoolWithTag(g_performance_collector, TAG);
        g_performance_collector = nullptr;
    }
}


_Use_decl_annotations_ static void PerfpInitialOutputRoutine(void* output_context)
{
    UNREFERENCED_PARAMETER(output_context);
    LOG_INFO("%-45s,%-20s,%-20s", "FunctionName(Line)", "Execution Count", "Elapsed Time");
}


_Use_decl_annotations_ static void PerfpOutputRoutine(const char* location_name, ULONG64 total_execution_count, ULONG64 total_elapsed_time, void* output_context)
{
    UNREFERENCED_PARAMETER(output_context);
    LOG_INFO("%-45s,%20I64u,%20I64u,", location_name, total_execution_count, total_elapsed_time);
}


_Use_decl_annotations_ static void PerfpFinalOutputRoutine(void* output_context)
{
    UNREFERENCED_PARAMETER(output_context);
}
