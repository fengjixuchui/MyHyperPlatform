// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements EPT functions.

#include "ept.h"
#include "asm.h"
#include "log.h"
#include "util.h"


extern "C"
{
// Followings are how 64bits of a physical address is used to locate EPT entries:
//
// EPT Page map level 4 selector           9 bits
// EPT Page directory pointer selector     9 bits
// EPT Page directory selector             9 bits
// EPT Page table selector                 9 bits
// EPT Byte within page                   12 bits

static const auto kEptpPxiShift = 39ull;// Get the highest 25 bits
static const auto kEptpPpiShift = 30ull;// Get the highest 34 bits
static const auto kEptpPdiShift = 21ull;// Get the highest 43 bits
static const auto kEptpPtiShift = 12ull;// Get the highest 52 bits

static const auto kEptpPtxMask = 0x1ffull;// Use 9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const auto kEptpNumberOfPreallocatedEntries = 50;// How many EPT entries are preallocated. When the number exceeds it, the hypervisor issues a bugcheck.
static const auto kEptpNumOfMaxVariableRangeMtrrs = 255;// Architecture defined number of variable range MTRRs
static const auto kEptpNumOfFixedRangeMtrrs = 1 + 2 + 8;// Architecture defined number of fixed range MTRRs (1 for 64k, 2 for 16k, 8 for 4k)
static const auto kEptpMtrrEntriesSize = kEptpNumOfMaxVariableRangeMtrrs + kEptpNumOfFixedRangeMtrrs;// A size of array to store all possible MTRRs

#include <pshpack1.h>
struct MtrrData {
  bool enabled;        //<! Whether this entry is valid
  bool fixedMtrr;      //<! Whether this entry manages a fixed range MTRR
  UCHAR type;          //<! Memory Type (such as WB, UC)
  bool reserverd1;     //<! Padding
  ULONG reserverd2;    //<! Padding
  ULONG64 range_base;  //<! A base address of a range managed by this entry
  ULONG64 range_end;   //<! An end address of a range managed by this entry
};
#include <poppack.h>
static_assert(sizeof(MtrrData) == 24, "Size check");

struct EptData {// EPT related data stored in ProcessorData
    EptPointer *ept_pointer;
    EptCommonEntry *ept_pml4;
    EptCommonEntry **preallocated_entries;  // An array of pre-allocated entries
    volatile long preallocated_entries_count;  // # of used pre-allocated entries
};

static memory_type EptpGetMemoryType(_In_ ULONG64 physical_address);

_When_(ept_data == nullptr, _IRQL_requires_max_(DISPATCH_LEVEL)) 
static EptCommonEntry *EptpConstructTables(_In_ EptCommonEntry *table, _In_ ULONG table_level, _In_ ULONG64 physical_address, _In_opt_ EptData *ept_data);

static void EptpDestructTables(_In_ EptCommonEntry *table, _In_ ULONG table_level);

static void EptpInitTableEntry(_In_ EptCommonEntry *Entry, _In_ ULONG table_level, _In_ ULONG64 physical_address);
static ULONG64 EptpAddressToPxeIndex(_In_ ULONG64 physical_address);
static ULONG64 EptpAddressToPpeIndex(_In_ ULONG64 physical_address);
static ULONG64 EptpAddressToPdeIndex(_In_ ULONG64 physical_address);
static ULONG64 EptpAddressToPteIndex(_In_ ULONG64 physical_address);
static bool EptpIsDeviceMemory(_In_ ULONG64 physical_address);
static EptCommonEntry *EptpGetEptPtEntry(_In_ EptCommonEntry *table, _In_ ULONG table_level, _In_ ULONG64 physical_address);
static void EptpFreeUnusedPreAllocatedEntries(_Pre_notnull_ __drv_freesMem(Mem) EptCommonEntry **preallocated_entries, _In_ long used_count);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, EptIsEptAvailable)
#pragma alloc_text(PAGE, EptInitialization)
#pragma alloc_text(PAGE, EptInitializeMtrrEntries)
#endif

static MtrrData g_eptp_mtrr_entries[kEptpMtrrEntriesSize];
static UCHAR g_eptp_mtrr_default_type;


_Use_decl_annotations_ bool EptIsEptAvailable()
// Checks if the system supports EPT technology sufficient enough
{
    PAGED_CODE();

    // Check the followings:
    // - page walk length is 4 steps
    // - extended page tables can be laid out in write-back memory
    // - INVEPT instruction with all possible types is supported
    // - INVVPID instruction with all possible types is supported
    Ia32VmxEptVpidCapMsr capability = { __readmsr(0x48C) };
    if (!capability.fields.support_page_walk_length4 ||
        !capability.fields.support_write_back_memory_type ||
        !capability.fields.support_invept ||
        !capability.fields.support_single_context_invept ||
        !capability.fields.support_all_context_invept ||
        !capability.fields.support_invvpid ||
        !capability.fields.support_individual_address_invvpid ||
        !capability.fields.support_single_context_invvpid ||
        !capability.fields.support_all_context_invvpid ||
        !capability.fields.support_single_context_retaining_globals_invvpid) 
    {
        return false;
    }

    return true;
}


_Use_decl_annotations_ ULONG64 EptGetEptPointer(EptData *ept_data)
// Returns an EPT pointer from ept_data
{
    return ept_data->ept_pointer->all;
}


_Use_decl_annotations_ void EptInitializeMtrrEntries()
// Reads and stores all MTRRs to set a correct memory type for EPT
{
    PAGED_CODE();

    int index = 0;
    
    Ia32MtrrDefaultTypeMsr default_type = { __readmsr(0x2FF) };
    g_eptp_mtrr_default_type = default_type.fields.default_mtemory_type;// Get and store the default memory type
    
    Ia32MtrrCapabilitiesMsr mtrr_capabilities = { __readmsr(0xFE) };// Read MTRR capability
    
    if (mtrr_capabilities.fields.fixed_range_supported && default_type.fields.fixed_mtrrs_enabled)// Read fixed range MTRRs if supported
    {
        static const ULONG64 k64kBase = 0x0;
        static const ULONG64 k64kManagedSize = 0x10000;
        static const ULONG64 k16kBase = 0x80000;
        static const ULONG64 k16kManagedSize = 0x4000;
        static const ULONG64 k4kBase = 0xC0000;
        static const ULONG64 k4kManagedSize = 0x1000;

        // The kIa32MtrrFix64k00000 manages 8 ranges of memory.
        // The first range starts at 0x0, and each range manages a 64k (0x10000) range.
        // For example,
        //  entry[0]:     0x0 : 0x10000 - 1
        //  entry[1]: 0x10000 : 0x20000 - 1
        //  ...
        //  entry[7]: 0x70000 : 0x80000 - 1
        ULONG64 offset = 0;
        Ia32MtrrFixedRangeMsr fixed_range = { __readmsr(0x250) };
        for (auto memory_type : fixed_range.fields.types)
        {
            // Each entry manages 64k (0x10000) length.
            ULONG64 base = k64kBase + offset;
            offset += k64kManagedSize;

            // Saves the MTRR
            g_eptp_mtrr_entries[index].enabled = true;
            g_eptp_mtrr_entries[index].fixedMtrr = true;
            g_eptp_mtrr_entries[index].type = memory_type;
            g_eptp_mtrr_entries[index].range_base = base;
            g_eptp_mtrr_entries[index].range_end = base + k64kManagedSize - 1;
            index++;
        }
        NT_ASSERT(k64kBase + offset == k16kBase);

        // kIa32MtrrFix16k80000 manages 8 ranges of memory.
        // The first range starts at 0x80000, and each range manages a 16k (0x4000) range.
        // For example,
        //  entry[0]: 0x80000 : 0x84000 - 1
        //  entry[1]: 0x88000 : 0x8C000 - 1
        //  ...
        //  entry[7]: 0x9C000 : 0xA0000 - 1
        // Also, subsequent memory ranges are managed by other MSR, kIa32MtrrFix16kA0000, which manages 8 ranges of memory starting at 0xA0000 in the same fashion.
        // For example,
        //  entry[0]: 0xA0000 : 0xA4000 - 1
        //  entry[1]: 0xA8000 : 0xAC000 - 1
        //  ...
        //  entry[7]: 0xBC000 : 0xC0000 - 1
        offset = 0;
        for (ULONG msr = static_cast<ULONG>(Msr::kIa32MtrrFix16k80000); msr <= static_cast<ULONG>(Msr::kIa32MtrrFix16kA0000); msr++)
        {
            fixed_range.all = __readmsr(msr);
            for (auto memory_type : fixed_range.fields.types)
            {
                // Each entry manages 16k (0x4000) length.
                ULONG64 base = k16kBase + offset;
                offset += k16kManagedSize;

                // Saves the MTRR
                g_eptp_mtrr_entries[index].enabled = true;
                g_eptp_mtrr_entries[index].fixedMtrr = true;
                g_eptp_mtrr_entries[index].type = memory_type;
                g_eptp_mtrr_entries[index].range_base = base;
                g_eptp_mtrr_entries[index].range_end = base + k16kManagedSize - 1;
                index++;
            }
        }
        NT_ASSERT(k16kBase + offset == k4kBase);

        // kIa32MtrrFix4kC0000 manages 8 ranges of memory.
        // The first range starts at 0xC0000, and each range manages a 4k (0x1000) range.
        // For example,
        //  entry[0]: 0xC0000 : 0xC1000 - 1
        //  entry[1]: 0xC1000 : 0xC2000 - 1
        //  ...
        //  entry[7]: 0xC7000 : 0xC8000 - 1
        // Also, subsequent memory ranges are managed by other MSRs such as kIa32MtrrFix4kC8000, kIa32MtrrFix4kD0000, and kIa32MtrrFix4kF8000.
        // Each MSR manages 8 ranges of memory in the same fashion up to 0x100000.
        offset = 0;
        for (ULONG msr = static_cast<ULONG>(Msr::kIa32MtrrFix4kC0000); msr <= static_cast<ULONG>(Msr::kIa32MtrrFix4kF8000); msr++)
        {
            fixed_range.all = __readmsr(msr);
            for (auto memory_type : fixed_range.fields.types)
            {
                // Each entry manages 4k (0x1000) length.
                ULONG64 base = k4kBase + offset;
                offset += k4kManagedSize;

                // Saves the MTRR
                g_eptp_mtrr_entries[index].enabled = true;
                g_eptp_mtrr_entries[index].fixedMtrr = true;
                g_eptp_mtrr_entries[index].type = memory_type;
                g_eptp_mtrr_entries[index].range_base = base;
                g_eptp_mtrr_entries[index].range_end = base + k4kManagedSize - 1;
                index++;
            }
        }
        NT_ASSERT(k4kBase + offset == 0x100000);
    }
    
    for (ULONG i = 0; i < mtrr_capabilities.fields.variable_range_count; i++)// Read all variable range MTRRs
    {
        // Read MTRR mask and check if it is in use
        ULONG phy_mask = static_cast<ULONG>(Msr::kIa32MtrrPhysMaskN) + i * 2;
        Ia32MtrrPhysMaskMsr mtrr_mask = { __readmsr(phy_mask) };
        if (!mtrr_mask.fields.valid) {
            continue;
        }
        
        ULONG length;
        BitScanForward64(&length, mtrr_mask.fields.phys_mask * PAGE_SIZE);// Get a length this MTRR manages

        // Read MTRR base and calculate a range this MTRR manages
        ULONG phy_base = static_cast<ULONG>(Msr::kIa32MtrrPhysBaseN) + i * 2;
        Ia32MtrrPhysBaseMsr mtrr_base = { __readmsr(phy_base) };
        ULONG64 base = mtrr_base.fields.phys_base * PAGE_SIZE;
        ULONG64 end = base + (1ull << length) - 1;

        // Save it
        g_eptp_mtrr_entries[index].enabled = true;
        g_eptp_mtrr_entries[index].fixedMtrr = false;
        g_eptp_mtrr_entries[index].type = mtrr_base.fields.type;
        g_eptp_mtrr_entries[index].range_base = base;
        g_eptp_mtrr_entries[index].range_end = end;
        index++;
    }
}


_Use_decl_annotations_ static memory_type EptpGetMemoryType(ULONG64 physical_address)
// Returns a memory type based on MTRRs
{
    UCHAR result_type = MAXUCHAR;// Indicate that MTRR is not defined (as a default)
    
    for (const auto mtrr_entry : g_eptp_mtrr_entries)// Looks for MTRR that includes the specified physical_address
    {
        if (!mtrr_entry.enabled) {
            break;// Reached out the end of stored MTRRs
        }

        if (!UtilIsInBounds(physical_address, mtrr_entry.range_base, mtrr_entry.range_end)) {
            continue;// This MTRR does not describe a memory type of the physical_address
        }
        
        if (mtrr_entry.fixedMtrr) {// See: MTRR Precedences
            result_type = mtrr_entry.type;// If a fixed MTRR describes a memory type, it is priority
            break;
        }

        if (mtrr_entry.type == static_cast<UCHAR>(memory_type::kUncacheable)) {// If a memory type is UC, it is priority.
            result_type = mtrr_entry.type;// Do not continue to search as UC has the highest priority
            break;
        }

        if (result_type == static_cast<UCHAR>(memory_type::kWriteThrough) || mtrr_entry.type == static_cast<UCHAR>(memory_type::kWriteThrough)) {
            if (result_type == static_cast<UCHAR>(memory_type::kWriteBack)) {
                // If two or more MTRRs describes an over-wrapped memory region, and one is WT and the other one is WB, use WT.
                // However, look for other MTRRs, as the other MTRR specifies the memory address as UC, which is priority.
                result_type = static_cast<UCHAR>(memory_type::kWriteThrough);
                continue;
            }
        }

        // Otherwise, processor behavior is undefined.
        result_type = mtrr_entry.type;// We just use the last MTRR describes the memory address.
    }
    
    if (result_type == MAXUCHAR) {// Use the default MTRR if no MTRR entry is found
        result_type = g_eptp_mtrr_default_type;
    }

    return static_cast<memory_type>(result_type);
}


_Use_decl_annotations_ static EptCommonEntry *EptpAllocateEptEntryFromPool()
// Return a new EPT entry either by creating new one
{
    static const SIZE_T kAllocSize = 512 * sizeof(EptCommonEntry);
    static_assert(kAllocSize == PAGE_SIZE, "Size check");

    EptCommonEntry * entry = reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(NonPagedPoolNx, kAllocSize, TAG));
    ASSERT(entry);
    RtlZeroMemory(entry, kAllocSize);
    return entry;
}


_Use_decl_annotations_ static EptCommonEntry * EptpAllocateEptEntryFromPreAllocated(EptData *ept_data)
// Return a new EPT entry from pre-allocated ones.
{
    LONG count = InterlockedIncrement(&ept_data->preallocated_entries_count);
    ASSERT(count <= kEptpNumberOfPreallocatedEntries);

    return ept_data->preallocated_entries[count - 1];
}


_Use_decl_annotations_ static EptCommonEntry *EptpAllocateEptEntry(EptData *ept_data)
// Return a new EPT entry either by creating new one or from pre-allocated ones
{
    if (ept_data) {
        return EptpAllocateEptEntryFromPreAllocated(ept_data);
    } else {
        return EptpAllocateEptEntryFromPool();
    }
}


_Use_decl_annotations_ EptData *EptInitialization() 
// Builds EPT, allocates pre-allocated entires, initializes and returns EptData
{
    PAGED_CODE();

    static const ULONG64 kEptPageWalkLevel = 4ul;
    
    EptData * ept_data = reinterpret_cast<EptData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EptData), TAG));// Allocate ept_data
    ASSERT(ept_data);
    RtlZeroMemory(ept_data, sizeof(EptData));
    
    EptPointer * ept_poiner = reinterpret_cast<EptPointer *>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, TAG));// Allocate EptPointer
    ASSERT(ept_poiner);
    RtlZeroMemory(ept_poiner, PAGE_SIZE);

    // Allocate EPT_PML4 and initialize EptPointer
    EptCommonEntry * ept_pml4 = reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, TAG));
    ASSERT(ept_pml4);
    RtlZeroMemory(ept_pml4, PAGE_SIZE);
    ept_poiner->fields.memory_type = static_cast<ULONG64>(EptpGetMemoryType(UtilPaFromVa(ept_pml4)));
    ept_poiner->fields.page_walk_length = kEptPageWalkLevel - 1;
    ept_poiner->fields.pml4_address = UtilPfnFromPa(UtilPaFromVa(ept_pml4));

    // Initialize all EPT entries for all physical memory pages
    for (PFN_COUNT run_index = 0ul; run_index < g_utilp_physical_memory_ranges->number_of_runs; ++run_index)
    {
        const PhysicalMemoryRun * run = &g_utilp_physical_memory_ranges->run[run_index];
        const ULONG_PTR base_addr = run->base_page * PAGE_SIZE;
        for (ULONG_PTR page_index = 0ull; page_index < run->page_count; ++page_index)
        {
            const ULONG_PTR indexed_addr = base_addr + page_index * PAGE_SIZE;
            const EptCommonEntry * ept_pt_entry = EptpConstructTables(ept_pml4, 4, indexed_addr, nullptr);
            if (!ept_pt_entry) {
                EptpDestructTables(ept_pml4, 4);
                ExFreePoolWithTag(ept_poiner, TAG);
                ExFreePoolWithTag(ept_data, TAG);
                return nullptr;
            }
        }
    }

    // Initialize an EPT entry for APIC_BASE. It is required to allocated it now for some reasons, or else, system hangs.
    const Ia32ApicBaseMsr apic_msr = { __readmsr(0x01B) };
    if (!EptpConstructTables(ept_pml4, 4, apic_msr.fields.apic_base * PAGE_SIZE, nullptr)) {
        EptpDestructTables(ept_pml4, 4);
        ExFreePoolWithTag(ept_poiner, TAG);
        ExFreePoolWithTag(ept_data, TAG);
        return nullptr;
    }

    // Allocate preallocated_entries
    const SIZE_T preallocated_entries_size = sizeof(EptCommonEntry *) * kEptpNumberOfPreallocatedEntries;
    EptCommonEntry ** preallocated_entries = reinterpret_cast<EptCommonEntry **>(ExAllocatePoolWithTag(NonPagedPoolNx, preallocated_entries_size, TAG));
    ASSERT(preallocated_entries);
    RtlZeroMemory(preallocated_entries, preallocated_entries_size);

    // And fill preallocated_entries with newly created entries
    for (SIZE_T i = 0ul; i < kEptpNumberOfPreallocatedEntries; ++i)
    {
        EptCommonEntry * ept_entry = EptpAllocateEptEntry(nullptr);
        ASSERT (ept_entry);
        preallocated_entries[i] = ept_entry;
    }

    // Initialization completed
    ept_data->ept_pointer = ept_poiner;
    ept_data->ept_pml4 = ept_pml4;
    ept_data->preallocated_entries = preallocated_entries;
    ept_data->preallocated_entries_count = 0;
    return ept_data;
}


_Use_decl_annotations_ static EptCommonEntry *EptpConstructTables(EptCommonEntry *table, ULONG table_level, ULONG64 physical_address, EptData *ept_data)
// Allocate and initialize all EPT entries associated with the physical_address
{
    switch (table_level)
    {
    case 4:// table == PML4 (512 GB)
    {
        ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
        EptCommonEntry * ept_pml4_entry = &table[pxe_index];
        if (!ept_pml4_entry->all) {
            EptCommonEntry * ept_pdpt = EptpAllocateEptEntry(ept_data);
            if (!ept_pdpt) {
                return nullptr;
            }
            EptpInitTableEntry(ept_pml4_entry, table_level, UtilPaFromVa(ept_pdpt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pml4_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 3:// table == PDPT (1 GB)
    {
        ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
        EptCommonEntry * ept_pdpt_entry = &table[ppe_index];
        if (!ept_pdpt_entry->all) {
            EptCommonEntry * ept_pdt = EptpAllocateEptEntry(ept_data);
            if (!ept_pdt) {
                return nullptr;
            }
            EptpInitTableEntry(ept_pdpt_entry, table_level, UtilPaFromVa(ept_pdt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 2:// table == PDT (2 MB)
    {
        ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
        EptCommonEntry * ept_pdt_entry = &table[pde_index];
        if (!ept_pdt_entry->all) {
            EptCommonEntry * ept_pt = EptpAllocateEptEntry(ept_data);
            if (!ept_pt) {
                return nullptr;
            }
            EptpInitTableEntry(ept_pdt_entry, table_level, UtilPaFromVa(ept_pt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdt_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 1:// table == PT (4 KB)
    {
        ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
        EptCommonEntry * ept_pt_entry = &table[pte_index];
        NT_ASSERT(!ept_pt_entry->all);
        EptpInitTableEntry(ept_pt_entry, table_level, physical_address);
        return ept_pt_entry;
    }
    default:
        KdBreakPoint();
        return nullptr;
    }
}


_Use_decl_annotations_ static void EptpInitTableEntry(EptCommonEntry *entry, ULONG table_level, ULONG64 physical_address)
// Initialize an EPT entry with a "pass through" attribute
{
    entry->fields.read_access = true;
    entry->fields.write_access = true;
    entry->fields.execute_access = true;
    entry->fields.physial_address = UtilPfnFromPa(physical_address);
    if (table_level == 1) {
        entry->fields.memory_type = static_cast<ULONG64>(EptpGetMemoryType(physical_address));
    }
}


_Use_decl_annotations_ static ULONG64 EptpAddressToPxeIndex(ULONG64 physical_address)
// Return an address of PXE
{
    return (physical_address >> kEptpPxiShift) & kEptpPtxMask;
}


_Use_decl_annotations_ static ULONG64 EptpAddressToPpeIndex(ULONG64 physical_address)
// Return an address of PPE
{
    return (physical_address >> kEptpPpiShift) & kEptpPtxMask;
}


_Use_decl_annotations_ static ULONG64 EptpAddressToPdeIndex(ULONG64 physical_address)
// Return an address of PDE
{
    return (physical_address >> kEptpPdiShift) & kEptpPtxMask;
}


_Use_decl_annotations_ static ULONG64 EptpAddressToPteIndex(ULONG64 physical_address)
// Return an address of PTE
{
    return (physical_address >> kEptpPtiShift) & kEptpPtxMask;
}


_Use_decl_annotations_ void EptHandleEptViolation(EptData *ept_data)
// Deal with EPT violation VM-exit.
{
    const EptViolationQualification exit_qualification = { UtilVmRead(VmcsField::kExitQualification) };
    ULONG64 fault_pa = UtilVmRead64(VmcsField::kGuestPhysicalAddress);

    if (exit_qualification.fields.ept_readable || exit_qualification.fields.ept_writeable || exit_qualification.fields.ept_executable) {
        KdBreakPoint();
        return;
    }

    EptCommonEntry * ept_entry = EptGetEptPtEntry(ept_data, fault_pa);
    if (ept_entry && ept_entry->all) {
        KdBreakPoint();
        return;
    }

    // EPT entry miss. It should be device memory.
    NT_VERIFY(EptpIsDeviceMemory(fault_pa));//debug°æ±¾ÌØÓÐ¡£
    EptpConstructTables(ept_data->ept_pml4, 4, fault_pa, ept_data);

    UtilInveptGlobal();
}


_Use_decl_annotations_ static bool EptpIsDeviceMemory(ULONG64 physical_address)
// Returns if the physical_address is device memory (which could not have a corresponding PFN entry)
{
    for (PFN_COUNT i = 0ul; i < g_utilp_physical_memory_ranges->number_of_runs; ++i)
    {
        const PhysicalMemoryRun * current_run = &g_utilp_physical_memory_ranges->run[i];
        ULONG64 base_addr = static_cast<ULONG64>(current_run->base_page) * PAGE_SIZE;
        ULONG64 endAddr = base_addr + current_run->page_count * PAGE_SIZE - 1;
        if (UtilIsInBounds(physical_address, base_addr, endAddr)) {
            return false;
        }
    }

    return true;
}


_Use_decl_annotations_ EptCommonEntry *EptGetEptPtEntry(EptData *ept_data, ULONG64 physical_address)
// Returns an EPT entry corresponds to the physical_address
{
    return EptpGetEptPtEntry(ept_data->ept_pml4, 4, physical_address);
}


_Use_decl_annotations_ static EptCommonEntry *EptpGetEptPtEntry(EptCommonEntry *table, ULONG table_level, ULONG64 physical_address)
// Returns an EPT entry corresponds to the physical_address
{
    if (!table) {
        return nullptr;
    }

    switch (table_level)
    {
    case 4:// table == PML4
    {
        ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
        EptCommonEntry * ept_pml4_entry = &table[pxe_index];
        if (!ept_pml4_entry->all) {
            return nullptr;
        }
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pml4_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 3:// table == PDPT
    {
        ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
        EptCommonEntry * ept_pdpt_entry = &table[ppe_index];
        if (!ept_pdpt_entry->all) {
            return nullptr;
        }
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 2:// table == PDT
    {
        ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
        EptCommonEntry * ept_pdt_entry = &table[pde_index];
        if (!ept_pdt_entry->all) {
            return nullptr;
        }
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdt_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 1:// table == PT
    {
        ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
        EptCommonEntry * ept_pt_entry = &table[pte_index];
        return ept_pt_entry;
    }
    default:
        KdBreakPoint();
        return nullptr;
    }
}


_Use_decl_annotations_ void EptTermination(EptData *ept_data)
// Frees all EPT stuff
{
    EptpFreeUnusedPreAllocatedEntries(ept_data->preallocated_entries, ept_data->preallocated_entries_count);
    EptpDestructTables(ept_data->ept_pml4, 4);
    ExFreePoolWithTag(ept_data->ept_pointer, TAG);
    ExFreePoolWithTag(ept_data, TAG);
}


_Use_decl_annotations_ static void EptpFreeUnusedPreAllocatedEntries(EptCommonEntry **preallocated_entries, long used_count)
// Frees all unused pre-allocated EPT entries. Other used entries should be freed with EptpDestructTables().
{
    for (SIZE_T i = used_count; i < kEptpNumberOfPreallocatedEntries; ++i)
    {
        if (!preallocated_entries[i]) {
            break;
        }
#pragma warning(push)
#pragma warning(disable : 6001)
        ExFreePoolWithTag(preallocated_entries[i], TAG);
#pragma warning(pop)
    }

    ExFreePoolWithTag(preallocated_entries, TAG);
}


_Use_decl_annotations_ static void EptpDestructTables(EptCommonEntry *table, ULONG table_level)
// Frees all used EPT entries by walking through whole EPT
{
    for (int i = 0ul; i < 512; ++i)
    {
        EptCommonEntry entry = table[i];
        if (entry.fields.physial_address)
        {
            EptCommonEntry * sub_table = reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(entry.fields.physial_address));

            switch (table_level)
            {
            case 4:  // table == PML4, sub_table == PDPT
            case 3:  // table == PDPT, sub_table == PDT
                EptpDestructTables(sub_table, table_level - 1);
                break;
            case 2:  // table == PDT, sub_table == PT
                ExFreePoolWithTag(sub_table, TAG);
                break;
            default:
                KdBreakPoint();
                break;
            }
        }
    }

    ExFreePoolWithTag(table, TAG);
}

}  // extern "C"
