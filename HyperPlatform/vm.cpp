// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements VMM initialization functions.

#include <limits.h>
#include <intrin.h>

#include "vm.h"
#include "asm.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#include "vmm.h"

extern "C"
{
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpIsVmxAvailable();
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmpSetLockBitCallback(_In_opt_ void *context);
_IRQL_requires_max_(PASSIVE_LEVEL) static SharedProcessorData *InitializeSharedData();
_IRQL_requires_max_(PASSIVE_LEVEL) static void *BuildMsrBitmap();
_IRQL_requires_max_(PASSIVE_LEVEL) static UCHAR *BuildIoBitmaps();
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmpStartVm(_In_opt_ void *context);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpInitializeVm(_In_ ULONG_PTR guest_stack_pointer, _In_ ULONG_PTR guest_instruction_pointer, _In_opt_ void *context);
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpEnterVmxMode(_Inout_ ProcessorData *processor_data);
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpInitializeVmcs(_Inout_ ProcessorData *processor_data);
_IRQL_requires_max_(PASSIVE_LEVEL) 
static bool VmpSetupVmcs(_In_ const ProcessorData *processor_data, _In_ ULONG_PTR guest_stack_pointer, _In_ ULONG_PTR guest_instruction_pointer, _In_ ULONG_PTR vmm_stack_pointer);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpLaunchVm();
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG VmpGetSegmentAccessRight(_In_ USHORT segment_selector);
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR VmpGetSegmentBase(_In_ ULONG_PTR gdt_base, _In_ USHORT segment_selector);
_IRQL_requires_max_(PASSIVE_LEVEL) static SegmentDescriptor *VmpGetSegmentDescriptor(_In_ ULONG_PTR descriptor_table_base, _In_ USHORT segment_selector);
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR VmpGetSegmentBaseByDescriptor(_In_ const SegmentDescriptor *segment_descriptor);
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG VmpAdjustControlValue(_In_ Msr msr, _In_ ULONG requested_value);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmpStopVm(_In_opt_ void *context);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpFreeProcessorData(_In_opt_ ProcessorData *processor_data);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpFreeSharedData(_In_ ProcessorData *processor_data);
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpIsHyperPlatformInstalled();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, VmInitialization)
#pragma alloc_text(PAGE, VmTermination)
#pragma alloc_text(PAGE, VmpIsVmxAvailable)
#pragma alloc_text(PAGE, VmpSetLockBitCallback)
#pragma alloc_text(PAGE, InitializeSharedData)
#pragma alloc_text(PAGE, BuildMsrBitmap)
#pragma alloc_text(PAGE, BuildIoBitmaps)
#pragma alloc_text(PAGE, VmpStartVm)
#pragma alloc_text(PAGE, VmpInitializeVm)
#pragma alloc_text(PAGE, VmpEnterVmxMode)
#pragma alloc_text(PAGE, VmpInitializeVmcs)
#pragma alloc_text(PAGE, VmpSetupVmcs)
#pragma alloc_text(PAGE, VmpLaunchVm)
#pragma alloc_text(PAGE, VmpGetSegmentAccessRight)
#pragma alloc_text(PAGE, VmpGetSegmentBase)
#pragma alloc_text(PAGE, VmpGetSegmentDescriptor)
#pragma alloc_text(PAGE, VmpGetSegmentBaseByDescriptor)
#pragma alloc_text(PAGE, VmpAdjustControlValue)
#pragma alloc_text(PAGE, VmpStopVm)
#pragma alloc_text(PAGE, VmpFreeProcessorData)
#pragma alloc_text(PAGE, VmpFreeSharedData)
#pragma alloc_text(PAGE, VmpIsHyperPlatformInstalled)
#pragma alloc_text(PAGE, VmHotplugCallback)
#endif


_Use_decl_annotations_ NTSTATUS VmInitialization()
// Checks if a VMM can be installed, and so, installs it
{
    PAGED_CODE();

    if (VmpIsHyperPlatformInstalled()) {
        return STATUS_CANCELLED;
    }

    if (!VmpIsVmxAvailable()) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    static SharedProcessorData * shared_data = InitializeSharedData();
    if (!shared_data) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    EptInitializeMtrrEntries();// Read and store all MTRRs to set a correct memory type for EPT

    NTSTATUS status = UtilForEachProcessor(VmpStartVm, shared_data);// Virtualize all processors
    if (!NT_SUCCESS(status)) {
        UtilForEachProcessor(VmpStopVm, nullptr);
        return status;
    }

    return status;
}


_Use_decl_annotations_ static bool VmpIsVmxAvailable()
// Checks if the system supports virtualization
{
    PAGED_CODE();

    // See: DISCOVERING SUPPORT FOR VMX
    // If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
    int cpu_info[4] = {};
    __cpuid(cpu_info, 1);
    const CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
    if (!cpu_features.fields.vmx) {
        LOG_ERROR("VMX features are not supported.");
        return false;
    }

    // See: BASIC VMX INFORMATION
    // The first processors to support VMX operation use the write-back type.
    const Ia32VmxBasicMsr vmx_basic_msr = { __readmsr(0x480) };
    if (static_cast<memory_type>(vmx_basic_msr.fields.memory_type) != memory_type::kWriteBack) {
        LOG_ERROR("Write-back cache type is not supported.");
        return false;
    }

    // See: ENABLING AND ENTERING VMX OPERATION
    Ia32FeatureControlMsr vmx_feature_control = { __readmsr(0x03A) };
    if (!vmx_feature_control.fields.lock) {
        LOG_INFO("The lock bit is clear. Attempting to set 1.");
        NTSTATUS status = UtilForEachProcessor(VmpSetLockBitCallback, nullptr);
        if (!NT_SUCCESS(status)) {
            return false;
        }
    }
    if (!vmx_feature_control.fields.enable_vmxon) {
        LOG_ERROR("VMX features are not enabled.");
        return false;
    }

    if (!EptIsEptAvailable()) {
        LOG_ERROR("EPT features are not fully supported.");
        return false;
    }

    return true;
}


_Use_decl_annotations_ static NTSTATUS VmpSetLockBitCallback(void *context)
// Sets 1 to the lock bit of the IA32_FEATURE_CONTROL MSR
{
    UNREFERENCED_PARAMETER(context);
    PAGED_CODE();

    Ia32FeatureControlMsr vmx_feature_control = { __readmsr(0x03A) };
    if (vmx_feature_control.fields.lock) {
        return STATUS_SUCCESS;
    }
    vmx_feature_control.fields.lock = true;
    __writemsr(0x03A, vmx_feature_control.all);
    vmx_feature_control.all = __readmsr(0x03A);
    if (!vmx_feature_control.fields.lock) {
        LOG_ERROR("The lock bit is still clear.");
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_ static SharedProcessorData * InitializeSharedData()
// Initialize shared processor data
{
    PAGED_CODE();

    SharedProcessorData * shared_data = reinterpret_cast<SharedProcessorData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(SharedProcessorData), TAG));
    ASSERT(shared_data);
    RtlZeroMemory(shared_data, sizeof(SharedProcessorData));

    shared_data->msr_bitmap = BuildMsrBitmap();// Setup MSR bitmap
    if (!shared_data->msr_bitmap) {
        ExFreePoolWithTag(shared_data, TAG);
        return nullptr;
    }

    UCHAR * io_bitmaps = BuildIoBitmaps();// Setup IO bitmaps
    if (!io_bitmaps) {
        ExFreePoolWithTag(shared_data->msr_bitmap, TAG);
        ExFreePoolWithTag(shared_data, TAG);
        return nullptr;
    }

    shared_data->io_bitmap_a = io_bitmaps;
    shared_data->io_bitmap_b = io_bitmaps + PAGE_SIZE;

    return shared_data;
}


_Use_decl_annotations_ static void * BuildMsrBitmap()// Build MSR bitmap
{
    PAGED_CODE();

    void * msr_bitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, TAG);
    ASSERT(msr_bitmap);
    RtlZeroMemory(msr_bitmap, PAGE_SIZE);

    // Activate VM-exit for RDMSR against all MSRs
    UCHAR * bitmap_read_low = reinterpret_cast<UCHAR *>(msr_bitmap);
    UCHAR * bitmap_read_high = bitmap_read_low + 1024;
    RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
    RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff
    
    RTL_BITMAP bitmap_read_low_header = {};
    RtlInitializeBitMap(&bitmap_read_low_header, reinterpret_cast<PULONG>(bitmap_read_low), 1024 * 8);
    RtlClearBits(&bitmap_read_low_header, 0xe7, 2);// Ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)

    // Checks MSRs that cause #GP from 0 to 0xfff, and ignore all of them
    for (ULONG msr = 0ul; msr < 0x1000; ++msr)
    {
        __try {
            __readmsr(msr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlClearBits(&bitmap_read_low_header, msr, 1);
        }
    }
    
    RTL_BITMAP bitmap_read_high_header = {};
    RtlInitializeBitMap(&bitmap_read_high_header, reinterpret_cast<PULONG>(bitmap_read_high), 1024 * CHAR_BIT);
    RtlClearBits(&bitmap_read_high_header, 0x101, 2);// Ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)

    return msr_bitmap;
}


_Use_decl_annotations_ static UCHAR * BuildIoBitmaps()// Build IO bitmaps
{
    PAGED_CODE();

    UCHAR * io_bitmaps = reinterpret_cast<UCHAR *>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE * 2, TAG));// Allocate two IO bitmaps as one contiguous 4K+4K page
    ASSERT(io_bitmaps);

    UCHAR * io_bitmap_a = io_bitmaps;              // for    0x0 - 0x7fff
    UCHAR * io_bitmap_b = io_bitmaps + PAGE_SIZE;  // for 0x8000 - 0xffff
    RtlFillMemory(io_bitmap_a, PAGE_SIZE, 0);
    RtlFillMemory(io_bitmap_b, PAGE_SIZE, 0);

    // Activate VM-exit for IO port 0x10 - 0x2010 as an example
    RTL_BITMAP bitmap_a_header = {};
    RtlInitializeBitMap(&bitmap_a_header, reinterpret_cast<PULONG>(io_bitmap_a), PAGE_SIZE * CHAR_BIT);

    RTL_BITMAP bitmap_b_header = {};
    RtlInitializeBitMap(&bitmap_b_header, reinterpret_cast<PULONG>(io_bitmap_b), PAGE_SIZE * CHAR_BIT);

    return io_bitmaps;
}


_Use_decl_annotations_ static NTSTATUS VmpStartVm(void *context)// Virtualize the current processor
{
    PAGED_CODE();

    bool ok = AsmInitializeVm(VmpInitializeVm, context);
    NT_ASSERT(VmpIsHyperPlatformInstalled() == ok);
    if (!ok) 
    {
        LOG_INFO("Initializing VMX for the processor %d fail.", KeGetCurrentProcessorNumberEx(nullptr));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_ static void VmpInitializeVm(ULONG_PTR guest_stack_pointer, ULONG_PTR guest_instruction_pointer, void *context) 
// Allocates structures for virtualization, initializes VMCS and virtualizes the current processor
{
    PAGED_CODE();

    SharedProcessorData * shared_data = reinterpret_cast<SharedProcessorData *>(context);
    if (!shared_data) {
        return;
    }
    
    ProcessorData * processor_data = reinterpret_cast<ProcessorData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ProcessorData), TAG));// Allocate related structures
    ASSERT(processor_data);
    RtlZeroMemory(processor_data, sizeof(ProcessorData));
    processor_data->shared_data = shared_data;
    InterlockedIncrement(&processor_data->shared_data->reference_count);
    
    processor_data->ept_data = EptInitialization();// Set up EPT
    if (!processor_data->ept_data) {
        goto ReturnFalse;
    }
    
    processor_data->vmm_stack_limit = AllocateContiguousMemory(KERNEL_STACK_SIZE);// Allocate other processor data fields
    if (!processor_data->vmm_stack_limit) {
        goto ReturnFalse;
    }
    RtlZeroMemory(processor_data->vmm_stack_limit, KERNEL_STACK_SIZE);

    processor_data->vmcs_region = reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(NonPagedPoolNx, kVmxMaxVmcsSize, TAG));
    ASSERT(processor_data->vmcs_region);
    RtlZeroMemory(processor_data->vmcs_region, kVmxMaxVmcsSize);

    processor_data->vmxon_region = reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(NonPagedPoolNx, kVmxMaxVmcsSize, TAG));
    ASSERT(processor_data->vmxon_region);
    RtlZeroMemory(processor_data->vmxon_region, kVmxMaxVmcsSize);

    // Initialize stack memory for VMM like this:
    //
    // (High)
    // +------------------+  <- vmm_stack_region_base      (eg, AED37000)
    // | processor_data   |  <- vmm_stack_data             (eg, AED36FFC)
    // +------------------+
    // | MAXULONG_PTR     |  <- vmm_stack_base (initial SP)(eg, AED36FF8)
    // +------------------+    v
    // |                  |    v
    // | (VMM Stack)      |    v (grow)
    // |                  |    v
    // +------------------+  <- vmm_stack_limit            (eg, AED34000)
    // (Low)
    ULONG_PTR vmm_stack_region_base = reinterpret_cast<ULONG_PTR>(processor_data->vmm_stack_limit) + KERNEL_STACK_SIZE;
    ULONG_PTR vmm_stack_data = vmm_stack_region_base - sizeof(void *);
    ULONG_PTR vmm_stack_base = vmm_stack_data - sizeof(void *);
    *reinterpret_cast<ULONG_PTR *>(vmm_stack_base) = MAXULONG_PTR;
    *reinterpret_cast<ProcessorData **>(vmm_stack_data) = processor_data;

    // Set up VMCS
    if (!VmpEnterVmxMode(processor_data)) {
        goto ReturnFalse;
    }
    if (!VmpInitializeVmcs(processor_data)) {
        goto ReturnFalseWithVmxOff;
    }
    if (!VmpSetupVmcs(processor_data, guest_stack_pointer, guest_instruction_pointer, vmm_stack_base)) {
        goto ReturnFalseWithVmxOff;
    }

    VmpLaunchVm();// Do virtualize the processor

  // Here is not be executed with successful vmlaunch.
  // Instead, the context jumps to an address specified by guest_instruction_pointer.

ReturnFalseWithVmxOff:;
    __vmx_off();

ReturnFalse:;
    VmpFreeProcessorData(processor_data);
}


_Use_decl_annotations_ static bool VmpEnterVmxMode(ProcessorData *processor_data)
// See: VMM SETUP & TEAR DOWN
{
    PAGED_CODE();

    // Apply FIXED bits
    // See: VMX-FIXED BITS IN CR0

    //        IA32_VMX_CRx_FIXED0 IA32_VMX_CRx_FIXED1 Meaning
    // Values 1                   *                   bit of CRx is fixed to 1
    // Values 0                   1                   bit of CRx is flexible
    // Values *                   0                   bit of CRx is fixed to 0
    const Cr0 cr0_fixed0 = { __readmsr(0x486) };
    const Cr0 cr0_fixed1 = { __readmsr(0x487) };
    Cr0 cr0 = { __readcr0() };
    Cr0 cr0_original = cr0;
    cr0.all &= cr0_fixed1.all;
    cr0.all |= cr0_fixed0.all;
    __writecr0(cr0.all);

    // See: VMX-FIXED BITS IN CR4
    const Cr4 cr4_fixed0 = { __readmsr(0x488) };
    const Cr4 cr4_fixed1 = { __readmsr(0x489) };
    Cr4 cr4 = { __readcr4() };
    Cr4 cr4_original = cr4;
    cr4.all &= cr4_fixed1.all;
    cr4.all |= cr4_fixed0.all;
    __writecr4(cr4.all);

    // Write a VMCS revision identifier
    const Ia32VmxBasicMsr vmx_basic_msr = { __readmsr(0x480) };
    processor_data->vmxon_region->revision_identifier = vmx_basic_msr.fields.revision_identifier;

    ULONG64 vmxon_region_pa = UtilPaFromVa(processor_data->vmxon_region);
    if (__vmx_on(&vmxon_region_pa)) {
        return false;
    }

    // See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use of the INVEPT Instruction
    UtilInveptGlobal();
    UtilInvvpidAllContext();
    return true;
}


_Use_decl_annotations_ static bool VmpInitializeVmcs(ProcessorData *processor_data)
// See: VMM SETUP & TEAR DOWN
{
    PAGED_CODE();

    // Write a VMCS revision identifier
    const Ia32VmxBasicMsr vmx_basic_msr = { __readmsr(0x480) };
    processor_data->vmcs_region->revision_identifier = vmx_basic_msr.fields.revision_identifier;

    SIZE_T vmcs_region_pa = UtilPaFromVa(processor_data->vmcs_region);
    if (__vmx_vmclear(&vmcs_region_pa)) {
        return false;
    }
    if (__vmx_vmptrld(&vmcs_region_pa)) {
        return false;
    }

    return true;// The launch state of current VMCS is "clear"
}


_Use_decl_annotations_ static bool VmpSetupVmcs(const ProcessorData *processor_data, ULONG_PTR guest_stack_pointer, ULONG_PTR guest_instruction_pointer, ULONG_PTR vmm_stack_pointer)
// See: PREPARATION AND LAUNCHING A VIRTUAL MACHINE
{
    PAGED_CODE();

    Gdtr gdtr = {};
    __sgdt(&gdtr);

    Idtr idtr = {};
    __sidt(&idtr);

    // See: Algorithms for Determining VMX Capabilities
    bool use_true_msrs = Ia32VmxBasicMsr{ __readmsr(0x480) }.fields.vmx_capability_hint;

    VmxVmEntryControls vm_entryctl_requested = {};
    vm_entryctl_requested.fields.load_debug_controls = 1;
    vm_entryctl_requested.fields.ia32e_mode_guest = 1;
    VmxVmEntryControls vm_entryctl = { VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls, vm_entryctl_requested.all) };

    VmxVmExitControls vm_exitctl_requested = {};
    vm_exitctl_requested.fields.host_address_space_size = 1;
    vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = 1;
    VmxVmExitControls vm_exitctl = { VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls, vm_exitctl_requested.all) };

    VmxPinBasedControls vm_pinctl_requested = {};
    VmxPinBasedControls vm_pinctl = { VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls : Msr::kIa32VmxPinbasedCtls, vm_pinctl_requested.all) };

    VmxProcessorBasedControls vm_procctl_requested = {};
    vm_procctl_requested.fields.cr3_load_exiting = true;
    vm_procctl_requested.fields.mov_dr_exiting = true;
    vm_procctl_requested.fields.use_io_bitmaps = true;
    vm_procctl_requested.fields.use_msr_bitmaps = true;
    vm_procctl_requested.fields.activate_secondary_control = true;
    VmxProcessorBasedControls vm_procctl = { VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls : Msr::kIa32VmxProcBasedCtls, vm_procctl_requested.all) };

    VmxSecondaryProcessorBasedControls vm_procctl2_requested = {};
    vm_procctl2_requested.fields.enable_ept = true;
    vm_procctl2_requested.fields.descriptor_table_exiting = true;
    vm_procctl2_requested.fields.enable_rdtscp = true;  // for Win10
    vm_procctl2_requested.fields.enable_vpid = true;
    vm_procctl2_requested.fields.enable_xsaves_xstors = true;  // for Win10
    VmxSecondaryProcessorBasedControls vm_procctl2 = { VmpAdjustControlValue(Msr::kIa32VmxProcBasedCtls2, vm_procctl2_requested.all) };

    // NOTE: Comment in any of those as needed
    ULONG_PTR exception_bitmap =
        // 1 << InterruptionVector::kBreakpointException |
        // 1 << InterruptionVector::kGeneralProtectionException |
        // 1 << InterruptionVector::kPageFaultException |
        0;

    // Set up CR0 and CR4 bitmaps
    // - Where a bit is     masked, the shadow bit appears
    // - Where a bit is not masked, the actual bit appears
    // VM-exit occurs when a guest modifies any of those fields
    Cr0 cr0_mask = {};
    Cr0 cr0_shadow = { __readcr0() };

    Cr4 cr4_mask = {};
    Cr4 cr4_shadow = { __readcr4() };
    // For example, when we want to hide CR4.VMXE from the guest, comment in below
    // cr4_mask.fields.vmxe = true;
    // cr4_shadow.fields.vmxe = false;
    
    VmxStatus error = VmxStatus::kOk;// clang-format off
    
    error |= UtilVmWrite(VmcsField::kVirtualProcessorId, KeGetCurrentProcessorNumberEx(nullptr) + 1);/* 16-Bit Control Field */

    /* 16-Bit Guest-State Fields */
    error |= UtilVmWrite(VmcsField::kGuestEsSelector, AsmReadES());
    error |= UtilVmWrite(VmcsField::kGuestCsSelector, AsmReadCS());
    error |= UtilVmWrite(VmcsField::kGuestSsSelector, AsmReadSS());
    error |= UtilVmWrite(VmcsField::kGuestDsSelector, AsmReadDS());
    error |= UtilVmWrite(VmcsField::kGuestFsSelector, AsmReadFS());
    error |= UtilVmWrite(VmcsField::kGuestGsSelector, AsmReadGS());
    error |= UtilVmWrite(VmcsField::kGuestLdtrSelector, AsmReadLDTR());
    error |= UtilVmWrite(VmcsField::kGuestTrSelector, AsmReadTR());

    /* 16-Bit Host-State Fields */
    // RPL and TI have to be 0
    error |= UtilVmWrite(VmcsField::kHostEsSelector, AsmReadES() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostCsSelector, AsmReadCS() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostSsSelector, AsmReadSS() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostDsSelector, AsmReadDS() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostFsSelector, AsmReadFS() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostGsSelector, AsmReadGS() & 0xf8);
    error |= UtilVmWrite(VmcsField::kHostTrSelector, AsmReadTR() & 0xf8);

    /* 64-Bit Control Fields */
    error |= UtilVmWrite64(VmcsField::kIoBitmapA, UtilPaFromVa(processor_data->shared_data->io_bitmap_a));
    error |= UtilVmWrite64(VmcsField::kIoBitmapB, UtilPaFromVa(processor_data->shared_data->io_bitmap_b));
    error |= UtilVmWrite64(VmcsField::kMsrBitmap, UtilPaFromVa(processor_data->shared_data->msr_bitmap));
    error |= UtilVmWrite64(VmcsField::kEptPointer, EptGetEptPointer(processor_data->ept_data));

    /* 64-Bit Guest-State Fields */
    error |= UtilVmWrite64(VmcsField::kVmcsLinkPointer, MAXULONG64);
    error |= UtilVmWrite64(VmcsField::kGuestIa32Debugctl, __readmsr(0x1D9));

    /* 32-Bit Control Fields */
    error |= UtilVmWrite(VmcsField::kPinBasedVmExecControl, vm_pinctl.all);
    error |= UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
    error |= UtilVmWrite(VmcsField::kExceptionBitmap, exception_bitmap);
    error |= UtilVmWrite(VmcsField::kVmExitControls, vm_exitctl.all);
    error |= UtilVmWrite(VmcsField::kVmEntryControls, vm_entryctl.all);
    error |= UtilVmWrite(VmcsField::kSecondaryVmExecControl, vm_procctl2.all);

    /* 32-Bit Guest-State Fields */
    error |= UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
    error |= UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
    error |= UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
    error |= UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
    error |= UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
    error |= UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
    error |= UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
    error |= UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
    error |= UtilVmWrite(VmcsField::kGuestGdtrLimit, gdtr.limit);
    error |= UtilVmWrite(VmcsField::kGuestIdtrLimit, idtr.limit);
    error |= UtilVmWrite(VmcsField::kGuestEsArBytes, VmpGetSegmentAccessRight(AsmReadES()));
    error |= UtilVmWrite(VmcsField::kGuestCsArBytes, VmpGetSegmentAccessRight(AsmReadCS()));
    error |= UtilVmWrite(VmcsField::kGuestSsArBytes, VmpGetSegmentAccessRight(AsmReadSS()));
    error |= UtilVmWrite(VmcsField::kGuestDsArBytes, VmpGetSegmentAccessRight(AsmReadDS()));
    error |= UtilVmWrite(VmcsField::kGuestFsArBytes, VmpGetSegmentAccessRight(AsmReadFS()));
    error |= UtilVmWrite(VmcsField::kGuestGsArBytes, VmpGetSegmentAccessRight(AsmReadGS()));
    error |= UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmpGetSegmentAccessRight(AsmReadLDTR()));
    error |= UtilVmWrite(VmcsField::kGuestTrArBytes, VmpGetSegmentAccessRight(AsmReadTR()));
    error |= UtilVmWrite(VmcsField::kGuestSysenterCs, __readmsr(0x174));
    
    error |= UtilVmWrite(VmcsField::kHostIa32SysenterCs, __readmsr(0x174));/* 32-Bit Host-State Field */

    /* Natural-Width Control Fields */
    error |= UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);
    error |= UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all);
    error |= UtilVmWrite(VmcsField::kCr0ReadShadow, cr0_shadow.all);
    error |= UtilVmWrite(VmcsField::kCr4ReadShadow, cr4_shadow.all);

    /* Natural-Width Guest-State Fields */
    error |= UtilVmWrite(VmcsField::kGuestCr0, __readcr0());
    error |= UtilVmWrite(VmcsField::kGuestCr3, __readcr3());
    error |= UtilVmWrite(VmcsField::kGuestCr4, __readcr4());
    error |= UtilVmWrite(VmcsField::kGuestEsBase, 0);
    error |= UtilVmWrite(VmcsField::kGuestCsBase, 0);
    error |= UtilVmWrite(VmcsField::kGuestSsBase, 0);
    error |= UtilVmWrite(VmcsField::kGuestDsBase, 0);
    error |= UtilVmWrite(VmcsField::kGuestFsBase, __readmsr(0xC0000100));
    error |= UtilVmWrite(VmcsField::kGuestGsBase, __readmsr(0xC0000101));
    error |= UtilVmWrite(VmcsField::kGuestLdtrBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
    error |= UtilVmWrite(VmcsField::kGuestTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
    error |= UtilVmWrite(VmcsField::kGuestGdtrBase, gdtr.base);
    error |= UtilVmWrite(VmcsField::kGuestIdtrBase, idtr.base);
    error |= UtilVmWrite(VmcsField::kGuestDr7, __readdr(7));
    error |= UtilVmWrite(VmcsField::kGuestRsp, guest_stack_pointer);
    error |= UtilVmWrite(VmcsField::kGuestRip, guest_instruction_pointer);
    error |= UtilVmWrite(VmcsField::kGuestRflags, __readeflags());
    error |= UtilVmWrite(VmcsField::kGuestSysenterEsp, __readmsr(0x175));
    error |= UtilVmWrite(VmcsField::kGuestSysenterEip, __readmsr(0x176));

    /* Natural-Width Host-State Fields */
    error |= UtilVmWrite(VmcsField::kHostCr0, __readcr0());
    error |= UtilVmWrite(VmcsField::kHostCr3, __readcr3());
    error |= UtilVmWrite(VmcsField::kHostCr4, __readcr4());
    error |= UtilVmWrite(VmcsField::kHostFsBase, __readmsr(0xC0000100));
    error |= UtilVmWrite(VmcsField::kHostGsBase, __readmsr(0xC0000101));
    error |= UtilVmWrite(VmcsField::kHostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
    error |= UtilVmWrite(VmcsField::kHostGdtrBase, gdtr.base);
    error |= UtilVmWrite(VmcsField::kHostIdtrBase, idtr.base);
    error |= UtilVmWrite(VmcsField::kHostIa32SysenterEsp, __readmsr(0x175));
    error |= UtilVmWrite(VmcsField::kHostIa32SysenterEip, __readmsr(0x176));
    error |= UtilVmWrite(VmcsField::kHostRsp, vmm_stack_pointer);
    error |= UtilVmWrite(VmcsField::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));
    // clang-format on

    VmxStatus vmx_status = static_cast<VmxStatus>(error);
    return vmx_status == VmxStatus::kOk;
}


_Use_decl_annotations_ static void VmpLaunchVm() // Executes vmlaunch
{
    PAGED_CODE();

    ULONG_PTR error_code = UtilVmRead(VmcsField::kVmInstructionError);
    if (error_code) {
        LOG_WARN("VM_INSTRUCTION_ERROR = %Iu", error_code);
    }

    VmxStatus vmx_status = static_cast<VmxStatus>(__vmx_vmlaunch());

    // Here should not executed with successful vmlaunch. Instead, the context jumps to an address specified by GUEST_RIP.
    if (vmx_status == VmxStatus::kErrorWithStatus) {
        error_code = UtilVmRead(VmcsField::kVmInstructionError);
        LOG_ERROR("VM_INSTRUCTION_ERROR = %Iu", error_code);
    }
}


_Use_decl_annotations_ static ULONG VmpGetSegmentAccessRight(USHORT segment_selector)
// Returns access right of the segment specified by the SegmentSelector for VMX
{
    PAGED_CODE();

    VmxRegmentDescriptorAccessRight access_right = {};
    const SegmentSelector ss = { segment_selector };
    if (segment_selector) {
        ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
        native_access_right >>= 8;
        access_right.all = static_cast<ULONG>(native_access_right);
        access_right.fields.reserved1 = 0;
        access_right.fields.reserved2 = 0;
        access_right.fields.unusable = false;
    } else {
        access_right.fields.unusable = true;
    }

    return access_right.all;
}


_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBase(ULONG_PTR gdt_base, USHORT segment_selector)
// Returns a base address of the segment specified by SegmentSelector
{
    PAGED_CODE();

    const SegmentSelector ss = { segment_selector };
    if (!ss.all) {
        return 0;
    }

    if (ss.fields.ti) {
        SegmentDescriptor * local_segment_descriptor = VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
        ULONG_PTR ldt_base = VmpGetSegmentBaseByDescriptor(local_segment_descriptor);
        SegmentDescriptor * segment_descriptor = VmpGetSegmentDescriptor(ldt_base, segment_selector);
        return VmpGetSegmentBaseByDescriptor(segment_descriptor);
    } else {
        SegmentDescriptor * segment_descriptor = VmpGetSegmentDescriptor(gdt_base, segment_selector);
        return VmpGetSegmentBaseByDescriptor(segment_descriptor);
    }
}


_Use_decl_annotations_ static SegmentDescriptor *VmpGetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector)
// Returns the segment descriptor corresponds to the SegmentSelector
{
    PAGED_CODE();

    const SegmentSelector ss = { segment_selector };
    return reinterpret_cast<SegmentDescriptor *>(descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}


_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBaseByDescriptor(const SegmentDescriptor *segment_descriptor)
// Returns a base address of segment_descriptor
{
    PAGED_CODE();

    // Calculate a 32bit base address
    SIZE_T base_high = segment_descriptor->fields.base_high << (6 * 4);
    SIZE_T base_middle = segment_descriptor->fields.base_mid << (4 * 4);
    SIZE_T base_low = segment_descriptor->fields.base_low;
    SIZE_T base = (base_high | base_middle | base_low) & MAXULONG;
    
    if (!segment_descriptor->fields.system) {// Get upper 32bit of the base address if needed
        const SegmentDesctiptorX64 * desc64 = reinterpret_cast<const SegmentDesctiptorX64 *>(segment_descriptor);
        ULONG64 base_upper32 = desc64->base_upper32;
        base |= (base_upper32 << 32);
    }

    return base;
}


_Use_decl_annotations_ static ULONG VmpAdjustControlValue(Msr msr, ULONG requested_value)
// Adjust the requested control value with consulting a value of related MSR
{
    PAGED_CODE();

    LARGE_INTEGER msr_value = {};
    msr_value.QuadPart = __readmsr((ULONG)msr);

    ULONG adjusted_value = requested_value;
    adjusted_value &= msr_value.HighPart;// bit == 0 in high word ==> must be zero
    adjusted_value |= msr_value.LowPart;// bit == 1 in low word  ==> must be one
    return adjusted_value;
}


_Use_decl_annotations_ void VmTermination()// Terminates VM
{
    PAGED_CODE();

    NTSTATUS status = UtilForEachProcessor(VmpStopVm, nullptr);
    if (NT_SUCCESS(status)) {
        LOG_INFO("The VMM has been uninstalled.");
    } else {
        LOG_WARN("The VMM has not been uninstalled (%08x).", status);
    }

    NT_ASSERT(!VmpIsHyperPlatformInstalled());
}


_Use_decl_annotations_ static NTSTATUS VmpStopVm(void *context)
// Stops virtualization through a hypercall and frees all related memory
{
    UNREFERENCED_PARAMETER(context);
    PAGED_CODE();
    
    ProcessorData *processor_data = nullptr;
    NTSTATUS status = UtilVmCall(HypercallNumber::kTerminateVmm, &processor_data);// Stop virtualization and get an address of the management structure
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Cr4 cr4 = { __readcr4() };
    cr4.fields.vmxe = false;
    __writecr4(cr4.all);// Clear CR4.VMXE, as there is no reason to leave the bit after vmxoff

    VmpFreeProcessorData(processor_data);
    return STATUS_SUCCESS;
}


_Use_decl_annotations_ static void VmpFreeProcessorData(ProcessorData *processor_data)// Frees all related memory
{
    PAGED_CODE();

    if (!processor_data) {
        return;
    }
    if (processor_data->vmm_stack_limit) {
        UtilFreeContiguousMemory(processor_data->vmm_stack_limit);
    }
    if (processor_data->vmcs_region) {
        ExFreePoolWithTag(processor_data->vmcs_region, TAG);
    }
    if (processor_data->vmxon_region) {
        ExFreePoolWithTag(processor_data->vmxon_region, TAG);
    }
    if (processor_data->ept_data) {
        EptTermination(processor_data->ept_data);
    }

    VmpFreeSharedData(processor_data);

    ExFreePoolWithTag(processor_data, TAG);
}


_Use_decl_annotations_ static void VmpFreeSharedData(ProcessorData *processor_data)
// Decrement reference count of shared data and free it if no reference
{
    PAGED_CODE();

    if (!processor_data->shared_data) {
        return;
    }

    if (InterlockedDecrement(&processor_data->shared_data->reference_count) != 0) {
        return;
    }

    if (processor_data->shared_data->io_bitmap_a) {
        ExFreePoolWithTag(processor_data->shared_data->io_bitmap_a, TAG);
    }
    if (processor_data->shared_data->msr_bitmap) {
        ExFreePoolWithTag(processor_data->shared_data->msr_bitmap, TAG);
    }
    ExFreePoolWithTag(processor_data->shared_data, TAG);
}


_Use_decl_annotations_ static bool VmpIsHyperPlatformInstalled()
// Tests if HyperPlatform is already installed
{
    PAGED_CODE();

    int cpu_info[4] = {};
    __cpuid(cpu_info, 1);
    const CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
    if (!cpu_features.fields.not_used) {
        return false;
    }

    __cpuid(cpu_info, kHyperVCpuidInterface);
    return cpu_info[0] == 'PpyH';
}


_Use_decl_annotations_ NTSTATUS VmHotplugCallback(const PROCESSOR_NUMBER &proc_num)
// Virtualizes the specified processor
{
    PAGED_CODE();

    // Switch to the processor 0 to get SharedProcessorData
    GROUP_AFFINITY affinity = {};
    GROUP_AFFINITY previous_affinity = {};
    KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);
    SharedProcessorData *shared_data = nullptr;
    NTSTATUS status = UtilVmCall(HypercallNumber::kGetSharedProcessorData, &shared_data);
    KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!shared_data) {
        return STATUS_UNSUCCESSFUL;
    }

    // Switch to the newly added processor to virtualize it
    affinity.Group = proc_num.Group;
    affinity.Mask = 1ull << proc_num.Number;
    KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);
    status = VmpStartVm(shared_data);
    KeRevertToUserGroupAffinityThread(&previous_affinity);
    return status;
}

}  // extern "C"
