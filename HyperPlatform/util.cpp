// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements primitive utility functions.

#include "util.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "log.h"

extern "C"
{
// Use RtlPcToFileHeader if available.
// Using the API causes a broken font bug on the 64 bit Windows 10 and should be avoided. This flag exist for only further investigation.
static const auto kUtilpUseRtlPcToFileHeader = false;

NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

using RtlPcToFileHeaderType = decltype(RtlPcToFileHeader);

_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) NTKERNELAPI _When_(return != NULL, _Post_writable_byte_size_(NumberOfBytes))
PVOID MmAllocateContiguousNodeMemory(
        _In_ SIZE_T NumberOfBytes,
        _In_ PHYSICAL_ADDRESS LowestAcceptableAddress,
        _In_ PHYSICAL_ADDRESS HighestAcceptableAddress,
        _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple, _In_ ULONG Protect,
        _In_ NODE_REQUIREMENT PreferredNode);

using MmAllocateContiguousNodeMemoryType = decltype(MmAllocateContiguousNodeMemory);

// dt nt!_LDR_DATA_TABLE_ENTRY
struct LdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_initialization_order_links;
  void *dll_base;
  void *entry_point;
  ULONG size_of_image;
  UNICODE_STRING full_dll_name;
  // ...
};

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilpInitializePageTableVariables();
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilpInitializeRtlPcToFileHeader(_In_ PDRIVER_OBJECT driver_object);
_Success_(return != nullptr) static PVOID NTAPI UtilpUnsafePcToFileHeader(_In_ PVOID pc_value, _Out_ PVOID *base_of_image);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilpInitializePhysicalMemoryRanges();
_IRQL_requires_max_(PASSIVE_LEVEL) static PhysicalMemoryDescriptor *UtilpBuildPhysicalMemoryRanges();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, UtilInitialization)
#pragma alloc_text(PAGE, UtilTermination)
#pragma alloc_text(INIT, UtilpInitializePageTableVariables)
#pragma alloc_text(INIT, UtilpInitializeRtlPcToFileHeader)
#pragma alloc_text(INIT, UtilpInitializePhysicalMemoryRanges)
#pragma alloc_text(INIT, UtilpBuildPhysicalMemoryRanges)
#pragma alloc_text(PAGE, UtilForEachProcessor)
#pragma alloc_text(PAGE, GetSystemProcAddress)
#endif

static RtlPcToFileHeaderType *g_utilp_RtlPcToFileHeader;
static LIST_ENTRY *g_utilp_PsLoadedModuleList;
PhysicalMemoryDescriptor *g_utilp_physical_memory_ranges;
static MmAllocateContiguousNodeMemoryType *g_MmAllocateContiguousNodeMemory;

static ULONG_PTR g_utilp_pxe_base = 0;
static ULONG_PTR g_utilp_ppe_base = 0;
static ULONG_PTR g_utilp_pde_base = 0;
static ULONG_PTR g_utilp_pte_base = 0;

static ULONG_PTR g_utilp_pxi_shift = 0;
static ULONG_PTR g_utilp_ppi_shift = 0;
static ULONG_PTR g_utilp_pdi_shift = 0;
static ULONG_PTR g_utilp_pti_shift = 0;

static ULONG_PTR g_utilp_pxi_mask = 0;
static ULONG_PTR g_utilp_ppi_mask = 0;
static ULONG_PTR g_utilp_pdi_mask = 0;
static ULONG_PTR g_utilp_pti_mask = 0;


_Use_decl_annotations_ NTSTATUS UtilInitialization(PDRIVER_OBJECT driver_object)
// Initializes utility functions
{
    PAGED_CODE();

    NTSTATUS status = UtilpInitializePageTableVariables();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = UtilpInitializeRtlPcToFileHeader(driver_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = UtilpInitializePhysicalMemoryRanges();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_MmAllocateContiguousNodeMemory = reinterpret_cast<MmAllocateContiguousNodeMemoryType *>(GetSystemProcAddress(L"MmAllocateContiguousNodeMemory"));
    ASSERT(g_MmAllocateContiguousNodeMemory);//win8��ǰ��MmAllocateContiguousMemory

    return status;
}


_Use_decl_annotations_ void UtilTermination() 
// Terminates utility functions
{
    PAGED_CODE();

    if (g_utilp_physical_memory_ranges) {
        ExFreePoolWithTag(g_utilp_physical_memory_ranges, TAG);
    }
}


_Use_decl_annotations_ static NTSTATUS UtilpInitializePageTableVariables()
// Initializes g_utilp_p*e_base, g_utilp_p*i_shift and g_utilp_p*i_mask.
{
    PAGED_CODE();

#include "util_page_constants.h"  // Include platform dependent constants

    // Check OS version to know if page table base addresses need to be relocated
    RTL_OSVERSIONINFOW os_version = { sizeof(os_version) };
    NTSTATUS status = RtlGetVersion(&os_version);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Win 10 build 14316 is the first version implements randomized page tables
    // Use fixed values if a systems is either: x86, older than Windows 7, or older than build 14316.
    if (os_version.dwMajorVersion < 10 || os_version.dwBuildNumber < 14316)
    {
        g_utilp_pxe_base = kUtilpPxeBase;
        g_utilp_ppe_base = kUtilpPpeBase;
        g_utilp_pxi_shift = kUtilpPxiShift;
        g_utilp_ppi_shift = kUtilpPpiShift;
        g_utilp_pxi_mask = kUtilpPxiMask;
        g_utilp_ppi_mask = kUtilpPpiMask;

        g_utilp_pde_base = kUtilpPdeBase;
        g_utilp_pte_base = kUtilpPteBase;
        g_utilp_pdi_shift = kUtilpPdiShift;
        g_utilp_pti_shift = kUtilpPtiShift;
        g_utilp_pdi_mask = kUtilpPdiMask;
        g_utilp_pti_mask = kUtilpPtiMask;

        return status;
    }

    // Get PTE_BASE from MmGetVirtualForPhysical
    const auto p_MmGetVirtualForPhysical = GetSystemProcAddress(L"MmGetVirtualForPhysical");
    if (!p_MmGetVirtualForPhysical) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    static const UCHAR kPatternWin10x64[] = {
        0x48, 0x8b, 0x04, 0xd0,  // mov     rax, [rax+rdx*8]
        0x48, 0xc1, 0xe0, 0x19,  // shl     rax, 19h
        0x48, 0xba,              // mov     rdx, ????????`????????  ; PTE_BASE
    };
    ULONG_PTR found = reinterpret_cast<ULONG_PTR>(UtilMemMem(p_MmGetVirtualForPhysical, 0x30, kPatternWin10x64, sizeof(kPatternWin10x64)));
    if (!found) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    found += sizeof(kPatternWin10x64);

    ULONG_PTR pte_base = *reinterpret_cast<ULONG_PTR *>(found);
    ULONG_PTR index = (pte_base >> kUtilpPxiShift) & kUtilpPxiMask;
    ULONG_PTR pde_base = pte_base | (index << kUtilpPpiShift);
    ULONG_PTR ppe_base = pde_base | (index << kUtilpPdiShift);
    ULONG_PTR pxe_base = ppe_base | (index << kUtilpPtiShift);

    g_utilp_pxe_base = static_cast<ULONG_PTR>(pxe_base);
    g_utilp_ppe_base = static_cast<ULONG_PTR>(ppe_base);
    g_utilp_pde_base = static_cast<ULONG_PTR>(pde_base);
    g_utilp_pte_base = static_cast<ULONG_PTR>(pte_base);

    g_utilp_pxi_shift = kUtilpPxiShift;
    g_utilp_ppi_shift = kUtilpPpiShift;
    g_utilp_pdi_shift = kUtilpPdiShift;
    g_utilp_pti_shift = kUtilpPtiShift;

    g_utilp_pxi_mask = kUtilpPxiMask;
    g_utilp_ppi_mask = kUtilpPpiMask;
    g_utilp_pdi_mask = kUtilpPdiMask;
    g_utilp_pti_mask = kUtilpPtiMask;

    return status;
}


_Use_decl_annotations_ static NTSTATUS UtilpInitializeRtlPcToFileHeader(PDRIVER_OBJECT driver_object)
// Locates RtlPcToFileHeader
{
    PAGED_CODE();

    if (kUtilpUseRtlPcToFileHeader) {
        const auto p_RtlPcToFileHeader = GetSystemProcAddress(L"RtlPcToFileHeader");
        if (p_RtlPcToFileHeader) {
            g_utilp_RtlPcToFileHeader = reinterpret_cast<RtlPcToFileHeaderType *>(p_RtlPcToFileHeader);
            return STATUS_SUCCESS;
        }
    }

#pragma warning(push)
#pragma warning(disable : 28175)
    LdrDataTableEntry * module = reinterpret_cast<LdrDataTableEntry *>(driver_object->DriverSection);
#pragma warning(pop)

    g_utilp_PsLoadedModuleList = module->in_load_order_links.Flink;
    g_utilp_RtlPcToFileHeader = UtilpUnsafePcToFileHeader;
    return STATUS_SUCCESS;
}


_Use_decl_annotations_ static PVOID NTAPI UtilpUnsafePcToFileHeader(PVOID pc_value, PVOID *base_of_image) 
// A fake RtlPcToFileHeader without acquiring PsLoadedModuleSpinLock.
// Thus, it is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.
{
    if (pc_value < MmSystemRangeStart) {
        return nullptr;
    }

    LIST_ENTRY * head = g_utilp_PsLoadedModuleList;
    for (PLIST_ENTRY current = head->Flink; current != head; current = current->Flink)
    {
        LdrDataTableEntry * module = CONTAINING_RECORD(current, LdrDataTableEntry, in_load_order_links);
        void * driver_end = reinterpret_cast<void *>(reinterpret_cast<ULONG_PTR>(module->dll_base) + module->size_of_image);
        if (UtilIsInBounds(pc_value, module->dll_base, driver_end)) {
            *base_of_image = module->dll_base;
            return module->dll_base;
        }
    }

    return nullptr;
}


_Use_decl_annotations_ void *UtilPcToFileHeader(void *pc_value) 
// A wrapper of RtlPcToFileHeader
{
    void *base = nullptr;
    return g_utilp_RtlPcToFileHeader(pc_value, &base);
}


_Use_decl_annotations_ static NTSTATUS UtilpInitializePhysicalMemoryRanges()
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


_Use_decl_annotations_ static PhysicalMemoryDescriptor * UtilpBuildPhysicalMemoryRanges()
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
    if (!pm_block) {
        ExFreePoolWithTag(pm_ranges, 'hPmM');
        return nullptr;
    }
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


_Use_decl_annotations_ NTSTATUS UtilForEachProcessor(NTSTATUS (*callback_routine)(void *), void *context) 
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


_Use_decl_annotations_ NTSTATUS UtilForEachProcessorDpc(PKDEFERRED_ROUTINE deferred_routine, void *context)
// Queues a given DPC routine on all processors. Returns STATUS_SUCCESS when DPC is queued for all processors.
{
    ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++)
    {
        PROCESSOR_NUMBER processor_number = {};
        NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        PRKDPC dpc = reinterpret_cast<PRKDPC>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KDPC), TAG));
        if (!dpc) {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }
        KeInitializeDpc(dpc, deferred_routine, context);
        KeSetImportanceDpc(dpc, HighImportance);
        status = KeSetTargetProcessorDpcEx(dpc, &processor_number);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(dpc, TAG);
            return status;
        }
        KeInsertQueueDpc(dpc, nullptr, nullptr);
    }

    return STATUS_SUCCESS;
}


// memmem().
_Use_decl_annotations_ void *UtilMemMem(const void *search_base, SIZE_T search_size, const void *pattern, SIZE_T pattern_size)
{
    if (pattern_size > search_size) {
        return nullptr;
    }
    const char * base = static_cast<const char *>(search_base);
    for (SIZE_T i = 0; i <= search_size - pattern_size; i++)
    {
        if (RtlCompareMemory(pattern, &base[i], pattern_size) == pattern_size) {
            return const_cast<char *>(&base[i]);
        }
    }

    return nullptr;
}


_Use_decl_annotations_ void *GetSystemProcAddress(const wchar_t *proc_name)
// A wrapper of MmGetSystemRoutineAddress
{
    PAGED_CODE();

    UNICODE_STRING proc_name_U = {};
    RtlInitUnicodeString(&proc_name_U, proc_name);
    return MmGetSystemRoutineAddress(&proc_name_U);
}


// VA -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromVa(void *va)
{
    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
    return pa.QuadPart;
}


// VA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromVa(void *va)
{
    return UtilPfnFromPa(UtilPaFromVa(va));
}


// PA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromPa(ULONG64 pa)
{
    return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
}


// PA -> VA
_Use_decl_annotations_ void *UtilVaFromPa(ULONG64 pa)
{
    PHYSICAL_ADDRESS pa2 = {};
    pa2.QuadPart = pa;
    return MmGetVirtualForPhysical(pa2);
}


// PNF -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromPfn(PFN_NUMBER pfn)
{
    return pfn << PAGE_SHIFT;
}


// PFN -> VA
_Use_decl_annotations_ void *UtilVaFromPfn(PFN_NUMBER pfn)
{
    return UtilVaFromPa(UtilPaFromPfn(pfn));
}


_Use_decl_annotations_ void * AllocateContiguousMemory(SIZE_T number_of_bytes)
// Allocates continuous physical memory
{
    PHYSICAL_ADDRESS highest_acceptable_address = {};
    highest_acceptable_address.QuadPart = -1;

    // Allocate NX physical memory
    PHYSICAL_ADDRESS lowest_acceptable_address = {};
    PHYSICAL_ADDRESS boundary_address_multiple = {};
    return g_MmAllocateContiguousNodeMemory(number_of_bytes, lowest_acceptable_address, highest_acceptable_address, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
}


_Use_decl_annotations_ void UtilFreeContiguousMemory(void *base_address)
// Frees an address allocated by AllocateContiguousMemory()
{
    MmFreeContiguousMemory(base_address);
}


// Executes VMCALL
_Use_decl_annotations_ NTSTATUS UtilVmCall(HypercallNumber hypercall_number, void *context)
{
    __try {
        VmxStatus vmx_status = static_cast<VmxStatus>(AsmVmxCall(static_cast<ULONG>(hypercall_number), context));
        return (vmx_status == VmxStatus::kOk) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS status = GetExceptionCode();
        KdBreakPoint();
        HYPERPLATFORM_LOG_WARN_SAFE("Exception thrown (code %08x)", status);
        return status;
    }
}


_Use_decl_annotations_ void UtilDumpGpRegisters(const AllRegisters *all_regs, ULONG_PTR stack_pointer)
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


_Use_decl_annotations_ ULONG_PTR UtilVmRead(VmcsField field)
// Reads natural-width VMCS
{
    size_t field_value = 0;
    VmxStatus vmx_status = static_cast<VmxStatus>(__vmx_vmread(static_cast<size_t>(field), &field_value));
    if (vmx_status != VmxStatus::kOk) {
        HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kCriticalVmxInstructionFailure, static_cast<ULONG_PTR>(vmx_status), static_cast<ULONG_PTR>(field), 0);
    }

    return field_value;
}


_Use_decl_annotations_ ULONG64 UtilVmRead64(VmcsField field)
// Reads 64bit-width VMCS
{
    return UtilVmRead(field);
}


// Writes natural-width VMCS
_Use_decl_annotations_ VmxStatus UtilVmWrite(VmcsField field, ULONG_PTR field_value)
{
    return static_cast<VmxStatus>(__vmx_vmwrite(static_cast<size_t>(field), field_value));
}


_Use_decl_annotations_ VmxStatus UtilVmWrite64(VmcsField field, ULONG64 field_value)
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

// Executes the INVVPID instruction (type 0)
_Use_decl_annotations_ VmxStatus UtilInvvpidIndividualAddress(USHORT vpid, void *address)
{
    InvVpidDescriptor desc = {};
    desc.vpid = vpid;
    desc.linear_address = reinterpret_cast<ULONG64>(address);
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kIndividualAddressInvalidation, &desc));
}

// Executes the INVVPID instruction (type 1)
_Use_decl_annotations_ VmxStatus UtilInvvpidSingleContext(USHORT vpid)
{
    InvVpidDescriptor desc = {};
    desc.vpid = vpid;
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kSingleContextInvalidation, &desc));
}


VmxStatus UtilInvvpidAllContext()
// Executes the INVVPID instruction (type 2)
{
    InvVpidDescriptor desc = {};
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kAllContextInvalidation, &desc));
}


_Use_decl_annotations_ VmxStatus UtilInvvpidSingleContextExceptGlobal(USHORT vpid)
// Executes the INVVPID instruction (type 3)
{
    InvVpidDescriptor desc = {};
    desc.vpid = vpid;
    return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kSingleContextInvalidationExceptGlobal, &desc));
}


_Use_decl_annotations_ void UtilLoadPdptes(ULONG_PTR cr3_value)
// Loads the PDPTE registers from CR3 to VMCS
{
    SIZE_T current_cr3 = __readcr3();

    __writecr3(cr3_value);// Have to load cr3 to make UtilPfnFromVa() work properly.

    // Gets PDPTEs form CR3
    PdptrRegister pd_pointers[4] = {};
    for (int i = 0ul; i < 4; ++i)
    {
        SIZE_T pd_addr = g_utilp_pde_base + i * PAGE_SIZE;
        pd_pointers[i].fields.present = true;
        pd_pointers[i].fields.page_directory_pa = UtilPfnFromVa(reinterpret_cast<void *>(pd_addr));
    }

    __writecr3(current_cr3);
    UtilVmWrite64(VmcsField::kGuestPdptr0, pd_pointers[0].all);
    UtilVmWrite64(VmcsField::kGuestPdptr1, pd_pointers[1].all);
    UtilVmWrite64(VmcsField::kGuestPdptr2, pd_pointers[2].all);
    UtilVmWrite64(VmcsField::kGuestPdptr3, pd_pointers[3].all);
}


_Use_decl_annotations_ NTSTATUS UtilForceCopyMemory(void *destination, const void *source, SIZE_T length)
// Does RtlCopyMemory safely even if destination is a read only region
{
    PMDL mdl = IoAllocateMdl(destination, static_cast<ULONG>(length), FALSE, FALSE, nullptr);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(mdl);

#pragma warning(push)
#pragma warning(disable : 28145)
    // Following MmMapLockedPagesSpecifyCache() call causes bug check in case you are using Driver Verifier. The reason is explained as followings:
    //
    // A driver must not try to create more than one system-address-space mapping for an MDL. 
    // Additionally, because an MDL that is built by the MmBuildMdlForNonPagedPool routine is already mapped to the system
    // address space, a driver must not try to map this MDL into the system address space again by using the MmMapLockedPagesSpecifyCache routine.
    // -- MSDN
    //
    // This flag modification hacks Driver Verifier's check and prevent leading bug check.
    mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
    mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

    PVOID writable_dest = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority | MdlMappingNoExecute);
    if (!writable_dest) {
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writable_dest, source, length);
    MmUnmapLockedPages(writable_dest, mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

}  // extern "C"
