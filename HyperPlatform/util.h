// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to utility functions.

#pragma once

#include "ia32_type.h"

extern "C"
{
    _Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) NTKERNELAPI _When_(return != NULL, _Post_writable_byte_size_(NumberOfBytes)) PVOID MmAllocateContiguousNodeMemory(
        _In_ SIZE_T NumberOfBytes,
        _In_ PHYSICAL_ADDRESS LowestAcceptableAddress,
        _In_ PHYSICAL_ADDRESS HighestAcceptableAddress,
        _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple, _In_ ULONG Protect,
        _In_ NODE_REQUIREMENT PreferredNode);//Available starting with Windows 8

    /// Represents ranges of addresses
    struct PhysicalMemoryRun {
        ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
        ULONG_PTR page_count;  //!< A number of pages
    };
    static_assert(sizeof(PhysicalMemoryRun) == 0x10, "Size check");

    /// Represents a physical memory ranges of the system
    struct PhysicalMemoryDescriptor {
        PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
        PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
        PhysicalMemoryRun run[1];    //!< ranges of addresses
    };
    static_assert(sizeof(PhysicalMemoryDescriptor) == 0x20, "Size check");

    /// Indicates a result of VMX-instructions
    /// This convention was taken from the VMX-intrinsic functions by Microsoft.
    enum class VmxStatus : unsigned __int8 {
        kOk = 0,                  //!< Operation succeeded
        kErrorWithStatus = 1,     //!< Operation failed with extended status available
        kErrorWithoutStatus = 2,  //!< Operation failed without status available
    };

    enum class HypercallNumber : unsigned __int32 {/// Available command numbers for VMCALL
        kTerminateVmm,            //!< Terminates VMM
        kPingVmm,                 //!< Sends ping to the VMM
        kGetSharedProcessorData,  //!< Terminates VMM
    };

    NTSTATUS UtilpInitializePhysicalMemoryRanges();

    _IRQL_requires_max_(PASSIVE_LEVEL) void UtilTermination();/// Frees all resources allocated for the sake of the Util functions

    extern PhysicalMemoryDescriptor *g_utilp_physical_memory_ranges;

/// Executes \a callback_routine on each processor
/// @param callback_routine   A function to execute
/// @param context  An arbitrary parameter for \a callback_routine
/// @return STATUS_SUCCESS when \a returned STATUS_SUCCESS on all processors
_IRQL_requires_max_(APC_LEVEL) NTSTATUS UtilForEachProcessor(_In_ NTSTATUS (*callback_routine)(void *), _In_opt_ void *context);

/// VA -> PA
/// @param va   A virtual address to get its physical address
/// @return A physical address of \a va, or nullptr
/// @warning
/// It cannot be used for a virtual address managed by a prototype PTE.
ULONG64 UtilPaFromVa(_In_ void *va);

/// VA -> PFN
/// @param va   A virtual address to get its physical address
/// @return A page frame number of \a va, or 0
/// @warning
/// It cannot be used for a virtual address managed by a prototype PTE.
PFN_NUMBER UtilPfnFromVa(_In_ void *va);

/// PA -> PFN
/// @param pa   A physical address to get its page frame number
/// @return A page frame number of \a pa, or 0
PFN_NUMBER UtilPfnFromPa(_In_ ULONG64 pa);

/// PNF -> VA
/// @param pfn   A page frame number to get its virtual address
/// @return A virtual address of \a pfn
void *UtilVaFromPfn(_In_ PFN_NUMBER pfn);

/// Allocates continuous physical memory
/// @param number_of_bytes  A size to allocate
/// @return A base address of an allocated memory or nullptr
_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) void *AllocateContiguousMemory(_In_ SIZE_T number_of_bytes);

/// Executes VMCALL
/// @param hypercall_number   A command number
/// @param context  An arbitrary parameter
/// @return STATUS_SUCCESS if VMXON instruction succeeded
NTSTATUS UtilVmCall(_In_ HypercallNumber hypercall_number, _In_opt_ void *context);

/// Debug prints registers
/// @param all_regs   Registers to print out
/// @param stack_pointer  A stack pointer before calling this function
void UtilDumpGpRegisters(_In_ const AllRegisters *all_regs, _In_ ULONG_PTR stack_pointer);

/// Reads natural-width VMCS
/// @param field  VMCS-field to read
/// @return read value
ULONG_PTR UtilVmRead(_In_ VmcsField field);

/// Writes natural-width VMCS
/// @param field  VMCS-field to write
/// @param field_value  A value to write
/// @return A result of the VMWRITE instruction
VmxStatus UtilVmWrite(_In_ VmcsField field, _In_ ULONG_PTR field_value);

/// Executes the INVEPT instruction and invalidates EPT entry cache
/// @return A result of the INVEPT instruction
VmxStatus UtilInveptGlobal();

/// Executes the INVVPID instruction (type 0)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidIndividualAddress(_In_ USHORT vpid, _In_ void *address);

/// Executes the INVVPID instruction (type 2)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidAllContext();

/// Executes the INVVPID instruction (type 3)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidSingleContextExceptGlobal(_In_ USHORT vpid);

}  // extern "C"

/// Tests if \a value is in between \a min and \a max
/// @param value  A value to test
/// @param min  A minimum acceptable value
/// @param max  A maximum acceptable value
/// @return true if \a value is in between \a min and \a max
template <typename T> bool UtilIsInBounds(_In_ const T &value, _In_ const T &min, _In_ const T &max)
{
    return (min <= value) && (value <= max);
}
