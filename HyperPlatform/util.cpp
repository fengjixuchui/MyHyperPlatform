// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements primitive utility functions.


#include <intrin.h>

#include "util.h"
#include "asm.h"
#include "log.h"


extern "C"
{
NTSTATUS UtilpInitializePhysicalMemoryRanges();
_IRQL_requires_max_(PASSIVE_LEVEL) static PhysicalMemoryDescriptor *UtilpBuildPhysicalMemoryRanges();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, UtilTermination)
#pragma alloc_text(INIT, UtilpInitializePhysicalMemoryRanges)
#pragma alloc_text(INIT, UtilpBuildPhysicalMemoryRanges)
#pragma alloc_text(PAGE, UtilForEachProcessor)
#endif

PhysicalMemoryDescriptor *g_utilp_physical_memory_ranges;


void UtilTermination() 
// Terminates utility functions
{
    PAGED_CODE();

    if (g_utilp_physical_memory_ranges) {
        ExFreePoolWithTag(g_utilp_physical_memory_ranges, TAG);
    }
}


NTSTATUS UtilpInitializePhysicalMemoryRanges()
// Initializes the physical memory ranges
{
    PAGED_CODE();

    g_utilp_physical_memory_ranges = UtilpBuildPhysicalMemoryRanges();
    if (!g_utilp_physical_memory_ranges)
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


static PhysicalMemoryDescriptor * UtilpBuildPhysicalMemoryRanges()
// Builds the physical memory ranges
{
    PAGED_CODE();

    PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
    if (!pm_ranges) {
        return nullptr;
    }

    PFN_COUNT number_of_runs = 0;
    PFN_NUMBER number_of_pages = 0;
    for (; ; ++number_of_runs)
    {
        PPHYSICAL_MEMORY_RANGE range = &pm_ranges[number_of_runs];
        if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
            break;
        }
        number_of_pages += static_cast<PFN_NUMBER>(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
    }
    if (number_of_runs == 0) {
        ExFreePoolWithTag(pm_ranges, 'hPmM');
        return nullptr;
    }

    SIZE_T memory_block_size = sizeof(PhysicalMemoryDescriptor) + sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
    PhysicalMemoryDescriptor * pm_block = reinterpret_cast<PhysicalMemoryDescriptor *>(ExAllocatePoolWithTag(NonPagedPoolNx, memory_block_size, TAG));
    ASSERT(pm_block);
    RtlZeroMemory(pm_block, memory_block_size);

    pm_block->number_of_runs = number_of_runs;
    pm_block->number_of_pages = number_of_pages;

    for (PFN_COUNT run_index = 0ul; run_index < number_of_runs; run_index++)
    {
        PhysicalMemoryRun * current_run = &pm_block->run[run_index];
        PPHYSICAL_MEMORY_RANGE current_block = &pm_ranges[run_index];
        current_run->base_page = static_cast<ULONG_PTR>(UtilPfnFromPa(current_block->BaseAddress.QuadPart));
        current_run->page_count = static_cast<ULONG_PTR>(BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
    }

    ExFreePoolWithTag(pm_ranges, 'hPmM');
    return pm_block;
}


NTSTATUS UtilForEachProcessor(NTSTATUS (*callback_routine)(void *), void *context) 
// Execute a given callback routine on all processors in PASSIVE_LEVEL.
// Returns STATUS_SUCCESS when all callback returned STATUS_SUCCESS as well.
// When one of callbacks returns anything but STATUS_SUCCESS, this function stops to call remaining callbacks and returns the value.
{
    PAGED_CODE();

    for (ULONG processor_index = 0; processor_index < KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); processor_index++)
    {
        PROCESSOR_NUMBER processor_number = {};
        NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Switch the current processor
        GROUP_AFFINITY affinity = {};
        affinity.Group = processor_number.Group;
        affinity.Mask = 1ull << processor_number.Number;
        GROUP_AFFINITY previous_affinity = {};
        KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);
        status = callback_routine(context);// Execute callback
        KeRevertToUserGroupAffinityThread(&previous_affinity);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}


// VA -> PA
ULONG64 UtilPaFromVa(void *va)
{
    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
    return pa.QuadPart;
}


// VA -> PFN
PFN_NUMBER UtilPfnFromVa(void *va)
{
    return UtilPfnFromPa(UtilPaFromVa(va));
}


// PA -> PFN
PFN_NUMBER UtilPfnFromPa(ULONG64 pa)
{
    return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
}


// PA -> VA
void *UtilVaFromPa(ULONG64 pa)
{
    PHYSICAL_ADDRESS pa2 = {};
    pa2.QuadPart = pa;
    return MmGetVirtualForPhysical(pa2);
}


// PNF -> PA
ULONG64 UtilPaFromPfn(PFN_NUMBER pfn)
{
    return pfn << PAGE_SHIFT;
}


// PFN -> VA
void *UtilVaFromPfn(PFN_NUMBER pfn)
{
    return UtilVaFromPa(UtilPaFromPfn(pfn));
}


void * AllocateContiguousMemory(SIZE_T number_of_bytes)
// Allocates continuous physical memory
{
    PHYSICAL_ADDRESS highest_acceptable_address = {};
    highest_acceptable_address.QuadPart = -1;

    // Allocate NX physical memory
    PHYSICAL_ADDRESS lowest_acceptable_address = {};
    PHYSICAL_ADDRESS boundary_address_multiple = {};

#if (NTDDI_VERSION < NTDDI_WIN8)
    return MmAllocateContiguousMemory(number_of_bytes, highest_acceptable_address);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
    return MmAllocateContiguousNodeMemory(number_of_bytes, lowest_acceptable_address, highest_acceptable_address, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);//×¢Òâ°æ±¾¡£
#endif
}


void UtilFreeContiguousMemory(void *base_address)
// Frees an address allocated by AllocateContiguousMemory()
{
    MmFreeContiguousMemory(base_address);
}


NTSTATUS UtilVmCall(HypercallNumber hypercall_number, void *context)
// Executes VMCALL
{
    __try {
        VmxStatus vmx_status = static_cast<VmxStatus>(AsmVmxCall(static_cast<ULONG>(hypercall_number), context));
        return (vmx_status == VmxStatus::kOk) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS status = GetExceptionCode();
        KdBreakPoint();
        return status;
    }
}


void UtilDumpGpRegisters(const AllRegisters *all_regs, ULONG_PTR stack_pointer)
// Debug prints registers
{
    UNREFERENCED_PARAMETER(all_regs);
    UNREFERENCED_PARAMETER(stack_pointer);

    KIRQL current_irql = KeGetCurrentIrql();
    if (current_irql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    if (current_irql < DISPATCH_LEVEL) {
        KeLowerIrql(current_irql);
    }
}


ULONG_PTR UtilVmRead(VmcsField field)
// Reads natural-width VMCS
{
    size_t field_value = 0;
    VmxStatus vmx_status = static_cast<VmxStatus>(__vmx_vmread(static_cast<size_t>(field), &field_value));
    ASSERT(vmx_status == VmxStatus::kOk);
    return field_value;
}


ULONG64 UtilVmRead64(VmcsField field)
// Reads 64bit-width VMCS
{
    return UtilVmRead(field);
}


// Writes natural-width VMCS
VmxStatus UtilVmWrite(VmcsField field, ULONG_PTR field_value)
{
    return static_cast<VmxStatus>(__vmx_vmwrite(static_cast<size_t>(field), field_value));
}


VmxStatus UtilVmWrite64(VmcsField field, ULONG64 field_value)
// Writes 64bit-width VMCS
{
    return UtilVmWrite(field, field_value);
}


VmxStatus UtilInveptGlobal()
// Executes the INVEPT instruction and invalidates EPT entry cache
{
    InvEptDescriptor desc = {};
    return static_cast<VmxStatus>(AsmInvept(InvEptType::kGlobalInvalidation, &desc));
}


VmxStatus UtilInvvpidIndividualAddress(USHORT vpid, void *address)
// Executes the INVVPID instruction (type 0)
{
    InvVpidDescriptor desc = {};
    desc.vpid = vpid;
    desc.linear_address = reinterpret_cast<ULONG64>(address);
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kIndividualAddressInvalidation, &desc));
}


VmxStatus UtilInvvpidAllContext()
// Executes the INVVPID instruction (type 2)
{
    InvVpidDescriptor desc = {};
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kAllContextInvalidation, &desc));
}


VmxStatus UtilInvvpidSingleContextExceptGlobal(USHORT vpid)
// Executes the INVVPID instruction (type 3)
{
    InvVpidDescriptor desc = {};
    desc.vpid = vpid;
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kSingleContextInvalidationExceptGlobal, &desc));
}

}  // extern "C"
