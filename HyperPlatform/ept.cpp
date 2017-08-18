// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#include "ept.h"
#include "asm.h"
#include "log.h"
#include "util.h"


extern "C"
{
const auto kEptpNumberOfPreallocatedEntries = 50;// How many EPT entries are preallocated. When the number exceeds it, the hypervisor issues a bugcheck.
const auto kEptpNumOfMaxVariableRangeMtrrs = 255;// Architecture defined number of variable range MTRRs
const auto kEptpNumOfFixedRangeMtrrs = 1 + 2 + 8;// Architecture defined number of fixed range MTRRs (1 for 64k, 2 for 16k, 8 for 4k)
const auto kEptpMtrrEntriesSize = kEptpNumOfMaxVariableRangeMtrrs + kEptpNumOfFixedRangeMtrrs;// A size of array to store all possible MTRRs

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, EptIsEptAvailable)
#pragma alloc_text(PAGE, EptInitialization)
#pragma alloc_text(PAGE, EptInitializeMtrrEntries)
#endif

MtrrData g_eptp_mtrr_entries[kEptpMtrrEntriesSize];
UCHAR g_eptp_mtrr_default_type;


static ULONG64 EptpAddressToPxeIndex(ULONG64 physical_address)// Return an address of PXE
{
    return (physical_address >> 39ull) & 0x1ffull;
}


static ULONG64 EptpAddressToPpeIndex(ULONG64 physical_address)// Return an address of PPE
{
    return (physical_address >> 30ull) & 0x1ffull;
}


static ULONG64 EptpAddressToPdeIndex(ULONG64 physical_address)// Return an address of PDE
{
    return (physical_address >> 21ull) & 0x1ffull;
}


static ULONG64 EptpAddressToPteIndex(ULONG64 physical_address)// Return an address of PTE
{
    return (physical_address >> 12ull) & 0x1ffull;
}


static memory_type EptpGetMemoryType(ULONG64 physical_address)// Returns a memory type based on MTRRs
{
    UCHAR result_type = MAXUCHAR;// Indicate that MTRR is not defined (as a default)
    
    for (MtrrData mtrr_entry : g_eptp_mtrr_entries)// Looks for MTRR that includes the specified physical_address
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


static EptCommonEntry *EptpAllocateEptEntry(EptData *ept_data)// Return a new EPT entry either by creating new one or from pre-allocated ones
{
    if (ept_data) {// Return a new EPT entry from pre-allocated ones.
        LONG count = InterlockedIncrement(&ept_data->preallocated_entries_count); ASSERT(count <= kEptpNumberOfPreallocatedEntries);
        return ept_data->preallocated_entries[count - 1];
    } else {// Return a new EPT entry either by creating new one
        const SIZE_T kAllocSize = 512 * sizeof(EptCommonEntry);
        static_assert(kAllocSize == PAGE_SIZE, "Size check");

        EptCommonEntry * entry = reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(NonPagedPoolNx, kAllocSize, TAG)); ASSERT(entry);
        RtlZeroMemory(entry, kAllocSize);
        return entry;
    }
}


static void EptpInitTableEntry(EptCommonEntry *entry, ULONG table_level, ULONG64 physical_address)// Initialize an EPT entry with a "pass through" attribute
{
    entry->fields.read_access = true;
    entry->fields.write_access = true;
    entry->fields.execute_access = true;
    entry->fields.physial_address = UtilPfnFromPa(physical_address);
    if (table_level == 1) {
        entry->fields.memory_type = static_cast<ULONG64>(EptpGetMemoryType(physical_address));
    }
}


static EptCommonEntry *EptpConstructTables(EptCommonEntry *table, ULONG table_level, ULONG64 physical_address, EptData *ept_data)
// Allocate and initialize all EPT entries associated with the physical_address
{
    switch (table_level)
    {
    case 4:// table == PML4 (512 GB)
    {
        ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
        EptCommonEntry * ept_pml4_entry = &table[pxe_index];
        if (!ept_pml4_entry->all) {
            EptCommonEntry * ept_pdpt = EptpAllocateEptEntry(ept_data); ASSERT(ept_pdpt);
            EptpInitTableEntry(ept_pml4_entry, table_level, UtilPaFromVa(ept_pdpt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pml4_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 3:// table == PDPT (1 GB)
    {
        ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
        EptCommonEntry * ept_pdpt_entry = &table[ppe_index];
        if (!ept_pdpt_entry->all) {
            EptCommonEntry * ept_pdt = EptpAllocateEptEntry(ept_data); ASSERT(ept_pdt);
            EptpInitTableEntry(ept_pdpt_entry, table_level, UtilPaFromVa(ept_pdt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 2:// table == PDT (2 MB)
    {
        ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
        EptCommonEntry * ept_pdt_entry = &table[pde_index];
        if (!ept_pdt_entry->all) {
            EptCommonEntry * ept_pt = EptpAllocateEptEntry(ept_data); ASSERT(ept_pt);
            EptpInitTableEntry(ept_pdt_entry, table_level, UtilPaFromVa(ept_pt));
        }
        return EptpConstructTables(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdt_entry->fields.physial_address)), table_level - 1, physical_address, ept_data);
    }
    case 1:// table == PT (4 KB)
    {
        ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
        EptCommonEntry * ept_pt_entry = &table[pte_index]; NT_ASSERT(!ept_pt_entry->all);
        EptpInitTableEntry(ept_pt_entry, table_level, physical_address);
        return ept_pt_entry;
    }
    default:
        KdBreakPoint();
        return nullptr;
    }
}


static bool EptpIsDeviceMemory(ULONG64 physical_address)// Returns if the physical_address is device memory (which could not have a corresponding PFN entry)
{
    for (PFN_COUNT i = 0ul; i < g_utilp_physical_memory_ranges->number_of_runs; ++i)
    {
        PhysicalMemoryRun * current_run = &g_utilp_physical_memory_ranges->run[i];
        ULONG64 base_addr = static_cast<ULONG64>(current_run->base_page) * PAGE_SIZE;
        ULONG64 endAddr = base_addr + current_run->page_count * PAGE_SIZE - 1;
        if (UtilIsInBounds(physical_address, base_addr, endAddr)) {
            return false;
        }
    }

    return true;
}


static EptCommonEntry *EptpGetEptPtEntry(EptCommonEntry *table, ULONG table_level, ULONG64 physical_address)// Returns an EPT entry corresponds to the physical_address
{
    if (!table) {//有这个，下面的三个断言可去掉。
        return nullptr;
    }

    switch (table_level)
    {
    case 4:// table == PML4
    {
        EptCommonEntry * ept_pml4_entry = &table[EptpAddressToPxeIndex(physical_address)]; //ASSERT(ept_pml4_entry->all);
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pml4_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 3:// table == PDPT
    {
        EptCommonEntry * ept_pdpt_entry = &table[EptpAddressToPpeIndex(physical_address)]; //ASSERT(ept_pdpt_entry->all);
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 2:// table == PDT
    {
        EptCommonEntry * ept_pdt_entry = &table[EptpAddressToPdeIndex(physical_address)]; //ASSERT(ept_pdt_entry->all);
        return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept_pdt_entry->fields.physial_address)), table_level - 1, physical_address);
    }
    case 1:// table == PT
    {
        EptCommonEntry * ept_pt_entry = &table[EptpAddressToPteIndex(physical_address)];
        return ept_pt_entry;
    }
    default:
        KdBreakPoint();
        return nullptr;
    }
}


static void EptpFreeUnusedPreAllocatedEntries(EptCommonEntry **preallocated_entries, long used_count)
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


static void EptpDestructTables(EptCommonEntry *table, ULONG table_level)// Frees all used EPT entries by walking through whole EPT
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


//////////////////////////////////////////////////////////////////////////////////////////////////


bool EptIsEptAvailable()// Checks if the system supports EPT technology sufficient enough
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


ULONG64 EptGetEptPointer(EptData *ept_data)// Returns an EPT pointer from ept_data
{
    return ept_data->ept_pointer->all;
}


void EptInitializeMtrrEntries()// Reads and stores all MTRRs to set a correct memory type for EPT
{
    PAGED_CODE();

    int index = 0;

    Ia32MtrrCapabilitiesMsr mtrr_capabilities = { __readmsr(0xFE) };//IA32_MTRRCAP Register; Read MTRR capability

    Ia32MtrrDefaultTypeMsr default_type = { __readmsr(0x2FF) };// IA32_MTRR_DEF_TYPE
    g_eptp_mtrr_default_type = default_type.fields.type;// Get and store the default memory type

    if (mtrr_capabilities.fields.MTRRs && default_type.fields.FE)// Read fixed range MTRRs if supported
    {
        // The kIa32MtrrFix64k00000 manages 8 ranges of memory.
        // The first range starts at 0x0, and each range manages a 64k (0x10000) range.
        ULONG64 offset = 0;
        Ia32MtrrFixedRangeMsr fixed_range = { __readmsr(0x250) };//IA32_MTRR_FIX64K_00000 详细的见：11.11.2.2   Fixed Range MTRRs
        for (UCHAR memory_type : fixed_range.fields.types)
        {
            g_eptp_mtrr_entries[index].enabled = true;
            g_eptp_mtrr_entries[index].fixedMtrr = true;
            g_eptp_mtrr_entries[index].type = memory_type;
            g_eptp_mtrr_entries[index].range_base = offset;
            g_eptp_mtrr_entries[index].range_end = g_eptp_mtrr_entries[index].range_base + 0x10000 - 1;

            index++;
            offset += 0x10000;// Each entry manages 64k (0x10000) length.
        }
        NT_ASSERT(offset == 0x80000); ASSERT(8 == index);

        // kIa32MtrrFix16k80000 manages 8 ranges of memory.
        // The first range starts at 0x80000, and each range manages a 16k (0x4000) range.
        // Also, subsequent memory ranges are managed by other MSR, kIa32MtrrFix16kA0000, which manages 8 ranges of memory starting at 0xA0000 in the same fashion.
        offset = 0;
        for (ULONG msr = static_cast<ULONG>(Msr::kIa32MtrrFix16k80000); msr <= static_cast<ULONG>(Msr::kIa32MtrrFix16kA0000); msr++)
        {
            fixed_range.all = __readmsr(msr);
            for (UCHAR memory_type : fixed_range.fields.types)
            {
                g_eptp_mtrr_entries[index].enabled = true;
                g_eptp_mtrr_entries[index].fixedMtrr = true;
                g_eptp_mtrr_entries[index].type = memory_type;
                g_eptp_mtrr_entries[index].range_base = 0x80000 + offset;
                g_eptp_mtrr_entries[index].range_end = g_eptp_mtrr_entries[index].range_base + 0x4000 - 1;

                index++;
                offset += 0x4000;// Each entry manages 16k (0x4000) length.
            }
        }
        NT_ASSERT(0x80000 + offset == 0xC0000);

        // kIa32MtrrFix4kC0000 manages 8 ranges of memory.
        // The first range starts at 0xC0000, and each range manages a 4k (0x1000) range.
        // Also, subsequent memory ranges are managed by other MSRs such as kIa32MtrrFix4kC8000, kIa32MtrrFix4kD0000, and kIa32MtrrFix4kF8000.
        // Each MSR manages 8 ranges of memory in the same fashion up to 0x100000.
        offset = 0;
        for (ULONG msr = static_cast<ULONG>(Msr::kIa32MtrrFix4kC0000); msr <= static_cast<ULONG>(Msr::kIa32MtrrFix4kF8000); msr++)
        {
            fixed_range.all = __readmsr(msr);
            for (UCHAR memory_type : fixed_range.fields.types)
            {
                g_eptp_mtrr_entries[index].enabled = true;
                g_eptp_mtrr_entries[index].fixedMtrr = true;
                g_eptp_mtrr_entries[index].type = memory_type;
                g_eptp_mtrr_entries[index].range_base = 0xC0000 + offset;
                g_eptp_mtrr_entries[index].range_end = g_eptp_mtrr_entries[index].range_base + 0x1000 - 1;

                index++;
                offset += 0x1000;// Each entry manages 4k (0x1000) length.
            }
        }
        NT_ASSERT(0xC0000 + offset == 0x100000);
    }

    for (ULONG i = 0; i < mtrr_capabilities.fields.VCNT; i++)// Read all variable range MTRRs
    {
        Ia32MtrrPhysMaskMsr mtrr_mask = { __readmsr(static_cast<ULONG>(Msr::kIa32MtrrPhysMaskN) + i * 2) };// Read MTRR mask and check if it is in use
        if (!mtrr_mask.fields.valid) {
            continue;
        }

        ULONG length;
        BitScanForward64(&length, mtrr_mask.fields.phys_mask * PAGE_SIZE);// Get a length this MTRR manages

        Ia32MtrrPhysBaseMsr mtrr_base = { __readmsr(static_cast<ULONG>(Msr::kIa32MtrrPhysBaseN) + i * 2) };// Read MTRR base and calculate a range this MTRR manages

        g_eptp_mtrr_entries[index].enabled = true;
        g_eptp_mtrr_entries[index].fixedMtrr = false;
        g_eptp_mtrr_entries[index].type = mtrr_base.fields.type;
        g_eptp_mtrr_entries[index].range_base = mtrr_base.fields.phys_base * PAGE_SIZE;
        g_eptp_mtrr_entries[index].range_end = g_eptp_mtrr_entries[index].range_base + (1ull << length) - 1;
        index++;
    }
}


void EptHandleEptViolation(EptData *ept_data)// Deal with EPT violation VM-exit.
{
    EptViolationQualification exit_qualification = { UtilVmRead(VmcsField::kExitQualification) };
    ULONG64 fault_pa = UtilVmRead(VmcsField::kGuestPhysicalAddress);

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
    NT_VERIFY(EptpIsDeviceMemory(fault_pa));//debug版本特有。
    EptpConstructTables(ept_data->ept_pml4, 4, fault_pa, ept_data);

    UtilInveptGlobal();
}


EptCommonEntry *EptGetEptPtEntry(EptData *ept_data, ULONG64 physical_address)// Returns an EPT entry corresponds to the physical_address
{
    return EptpGetEptPtEntry(ept_data->ept_pml4, 4, physical_address);
}


void EptTermination(EptData *ept_data)// Frees all EPT stuff
{
    EptpFreeUnusedPreAllocatedEntries(ept_data->preallocated_entries, ept_data->preallocated_entries_count);
    EptpDestructTables(ept_data->ept_pml4, 4);
    ExFreePoolWithTag(ept_data->ept_pointer, TAG);
    ExFreePoolWithTag(ept_data, TAG);
}


EptData *EptInitialization()// Builds EPT, allocates pre-allocated entires, initializes and returns EptData
{
    PAGED_CODE();

    EptData * ept_data = reinterpret_cast<EptData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EptData), TAG)); ASSERT(ept_data);
    RtlZeroMemory(ept_data, sizeof(EptData));

    EptPointer * ept_poiner = reinterpret_cast<EptPointer *>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, TAG)); ASSERT(ept_poiner);
    RtlZeroMemory(ept_poiner, PAGE_SIZE);

    // Allocate EPT_PML4 and initialize EptPointer
    EptCommonEntry * ept_pml4 = reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, TAG)); ASSERT(ept_pml4);
    RtlZeroMemory(ept_pml4, PAGE_SIZE);
    ept_poiner->fields.memory_type = static_cast<ULONG64>(EptpGetMemoryType(UtilPaFromVa(ept_pml4)));
    ept_poiner->fields.page_walk_length = 3;
    ept_poiner->fields.pml4_address = UtilPfnFromPa(UtilPaFromVa(ept_pml4));

    // Initialize all EPT entries for all physical memory pages
    for (PFN_COUNT run_index = 0ul; run_index < g_utilp_physical_memory_ranges->number_of_runs; ++run_index)
    {
        PhysicalMemoryRun * run = &g_utilp_physical_memory_ranges->run[run_index];
        for (ULONG_PTR page_index = 0ull; page_index < run->page_count; ++page_index)
        {
            EptpConstructTables(ept_pml4, 4, run->base_page * PAGE_SIZE + page_index * PAGE_SIZE, nullptr);
        }
    }

    // Initialize an EPT entry for APIC_BASE. It is required to allocated it now for some reasons, or else, system hangs.
    Ia32ApicBaseMsr apic_msr = { __readmsr(0x01B) };
    EptpConstructTables(ept_pml4, 4, apic_msr.fields.apic_base * PAGE_SIZE, nullptr);
    
    SIZE_T preallocated_entries_size = sizeof(EptCommonEntry *) * kEptpNumberOfPreallocatedEntries;
    EptCommonEntry ** preallocated_entries = reinterpret_cast<EptCommonEntry **>(ExAllocatePoolWithTag(NonPagedPoolNx, preallocated_entries_size, TAG)); ASSERT(preallocated_entries);
    RtlZeroMemory(preallocated_entries, preallocated_entries_size);
    for (SIZE_T i = 0ul; i < kEptpNumberOfPreallocatedEntries; ++i)
    {
        preallocated_entries[i] = EptpAllocateEptEntry(nullptr); ASSERT(preallocated_entries[i]);
    }

    ept_data->ept_pointer = ept_poiner;
    ept_data->ept_pml4 = ept_pml4;
    ept_data->preallocated_entries = preallocated_entries;
    ept_data->preallocated_entries_count = 0;
    return ept_data;
}

}
