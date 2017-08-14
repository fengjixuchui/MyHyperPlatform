// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements VMM functions.

#include <intrin.h>

#include "vmm.h"
#include "asm.h"
#include "ept.h"
#include "log.h"
#include "util.h"


extern "C"
{
bool __stdcall VmmVmExitHandler(_Inout_ VmmInitialStack *stack);
DECLSPEC_NORETURN void __stdcall VmmVmxFailureHandler(_Inout_ AllRegisters *all_regs);
static void VmmpHandleVmExit(_Inout_ GuestContext *guest_context);
DECLSPEC_NORETURN static void VmmpHandleTripleFault(_Inout_ GuestContext *guest_context);
DECLSPEC_NORETURN static void VmmpHandleUnexpectedExit(_Inout_ GuestContext *guest_context);
static void VmmpHandleMonitorTrap(_Inout_ GuestContext *guest_context);
static void VmmpHandleException(_Inout_ GuestContext *guest_context);
static void VmmpHandleCpuid(_Inout_ GuestContext *guest_context);
static void VmmpHandleRdtsc(_Inout_ GuestContext *guest_context);
static void VmmpHandleRdtscp(_Inout_ GuestContext *guest_context);
static void VmmpHandleXsetbv(_Inout_ GuestContext *guest_context);
static void VmmpHandleMsrReadAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleMsrWriteAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleMsrAccess(_Inout_ GuestContext *guest_context, _In_ bool read_access);
static void VmmpHandleGdtrOrIdtrAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleLdtrOrTrAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleDrAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleIoPort(_Inout_ GuestContext *guest_context);
static void VmmpHandleCrAccess(_Inout_ GuestContext *guest_context);
static void VmmpHandleVmx(_Inout_ GuestContext *guest_context);
static void VmmpHandleVmCall(_Inout_ GuestContext *guest_context);
static void VmmpHandleInvalidateInternalCaches(_Inout_ GuestContext *guest_context);
static void VmmpHandleInvalidateTlbEntry(_Inout_ GuestContext *guest_context);
static void VmmpHandleEptViolation(_Inout_ GuestContext *guest_context);
static void VmmpHandleEptMisconfig(_Inout_ GuestContext *guest_context);
static ULONG_PTR *VmmpSelectRegister(_In_ ULONG index, _In_ GuestContext *guest_context);
static void VmmpDumpGuestState();
static void VmmpAdjustGuestInstructionPointer(_In_ GuestContext *guest_context);
static void VmmpIoWrapper(_In_ bool to_memory, _In_ bool is_string, _In_ SIZE_T size_of_access, _In_ unsigned short port, _Inout_ void *address, _In_ unsigned long count);
static void VmmpIndicateSuccessfulVmcall(_In_ GuestContext *guest_context);
static void VmmpIndicateUnsuccessfulVmcall(_In_ GuestContext *guest_context);
static void VmmpHandleVmCallTermination(_In_ GuestContext *guest_context, _Inout_ void *context);
static UCHAR VmmpGetGuestCpl();
static void VmmpInjectInterruption(_In_ InterruptionType interruption_type, _In_ InterruptionVector vector, _In_ bool deliver_error_code, _In_ ULONG32 error_code);


#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ bool __stdcall VmmVmExitHandler(VmmInitialStack *stack)
// A high level VMX handler called from AsmVmExitHandler().
// Return true for vmresume, or return false for vmxoff.
{
    // Save guest's context and raise IRQL as quick as possible
    KIRQL guest_irql = KeGetCurrentIrql();
    ULONG64 guest_cr8 = __readcr8();
    if (guest_irql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }
    NT_ASSERT(stack->reserved == MAXULONG_PTR);

    // Capture the current guest state
    GuestContext guest_context = { stack, UtilVmRead(VmcsField::kGuestRflags), UtilVmRead(VmcsField::kGuestRip), guest_cr8, guest_irql, true };
    guest_context.gp_regs->sp = UtilVmRead(VmcsField::kGuestRsp);
    VmmpHandleVmExit(&guest_context);// Dispatch the current VM-exit event

    if (!guest_context.vm_continue) {// See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use of the INVEPT Instruction
        UtilInveptGlobal();
        UtilInvvpidAllContext();
    }

    if (guest_context.irql < DISPATCH_LEVEL) {// Restore guest's context
        KeLowerIrql(guest_context.irql);
    }

     __writecr8(guest_context.cr8);

    return guest_context.vm_continue;
}
#pragma warning(pop)


_Use_decl_annotations_ static void VmmpHandleVmExit(GuestContext *guest_context)
// Dispatches VM-exit to a corresponding handler
{
    const VmExitInformation exit_reason = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };

    switch (exit_reason.fields.reason)
    {
    case VmxExitReason::kExceptionOrNmi:
        VmmpHandleException(guest_context);
        break;
    case VmxExitReason::kTripleFault:
        VmmpHandleTripleFault(guest_context);
        break;
    case VmxExitReason::kCpuid:
        VmmpHandleCpuid(guest_context);
        break;
    case VmxExitReason::kInvd:
        VmmpHandleInvalidateInternalCaches(guest_context);
        break;
    case VmxExitReason::kInvlpg:
        VmmpHandleInvalidateTlbEntry(guest_context);
        break;
    case VmxExitReason::kRdtsc:
        VmmpHandleRdtsc(guest_context);
        break;
    case VmxExitReason::kCrAccess:
        VmmpHandleCrAccess(guest_context);
        break;
    case VmxExitReason::kDrAccess:
        VmmpHandleDrAccess(guest_context);
        break;
    case VmxExitReason::kIoInstruction:
        VmmpHandleIoPort(guest_context);
        break;
    case VmxExitReason::kMsrRead:
        VmmpHandleMsrReadAccess(guest_context);
        break;
    case VmxExitReason::kMsrWrite:
        VmmpHandleMsrWriteAccess(guest_context);
        break;
    case VmxExitReason::kMonitorTrapFlag:
        VmmpHandleMonitorTrap(guest_context);
        break;
    case VmxExitReason::kGdtrOrIdtrAccess:
        VmmpHandleGdtrOrIdtrAccess(guest_context);
        break;
    case VmxExitReason::kLdtrOrTrAccess:
        VmmpHandleLdtrOrTrAccess(guest_context);
        break;
    case VmxExitReason::kEptViolation:
        VmmpHandleEptViolation(guest_context);
        break;
    case VmxExitReason::kEptMisconfig:
        VmmpHandleEptMisconfig(guest_context);
        break;
    case VmxExitReason::kVmcall:
        VmmpHandleVmCall(guest_context);
        break;
    case VmxExitReason::kVmclear:
    case VmxExitReason::kVmlaunch:
    case VmxExitReason::kVmptrld:
    case VmxExitReason::kVmptrst:
    case VmxExitReason::kVmread:
    case VmxExitReason::kVmresume:
    case VmxExitReason::kVmwrite:
    case VmxExitReason::kVmoff:
    case VmxExitReason::kVmon:
        VmmpHandleVmx(guest_context);
        break;
    case VmxExitReason::kRdtscp:
        VmmpHandleRdtscp(guest_context);
        break;
    case VmxExitReason::kXsetbv:
        VmmpHandleXsetbv(guest_context);
        break;
    default:
        VmmpHandleUnexpectedExit(guest_context);
        break;
    }
}


// Triple fault VM-exit. Fatal error.
_Use_decl_annotations_ static void VmmpHandleTripleFault(GuestContext *guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);

    VmmpDumpGuestState();
    __debugbreak();
}


// Unexpected VM-exit. Fatal error.
_Use_decl_annotations_ static void VmmpHandleUnexpectedExit(GuestContext *guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);

    VmmpDumpGuestState();
    ULONG_PTR qualification = UtilVmRead(VmcsField::kExitQualification);
    __debugbreak();
}


// MTF VM-exit
_Use_decl_annotations_ static void VmmpHandleMonitorTrap(GuestContext *guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);

    VmmpDumpGuestState();
    __debugbreak();
}


// Interrupt
_Use_decl_annotations_ static void VmmpHandleException(GuestContext *guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);

    VmExitInterruptionInformationField exception = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo)) };
    InterruptionType interruption_type = static_cast<InterruptionType>(exception.fields.interruption_type);
    InterruptionVector vector = static_cast<InterruptionVector>(exception.fields.vector);

    if (interruption_type == InterruptionType::kHardwareException) {// Hardware exception
        if (vector == InterruptionVector::kPageFaultException) {// #PF
            PageFaultErrorCode fault_code = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode)) };
            ULONG_PTR fault_address = UtilVmRead(VmcsField::kExitQualification);

            VmmpInjectInterruption(interruption_type, vector, true, fault_code.all);
            AsmWriteCR2(fault_address);
        } else if (vector == InterruptionVector::kGeneralProtectionException) {// # GP
            ULONG32 error_code = static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode));

            VmmpInjectInterruption(interruption_type, vector, true, error_code);
        } else {
            __debugbreak();
        }
    } else if (interruption_type == InterruptionType::kSoftwareException) {// Software exception
        if (vector == InterruptionVector::kBreakpointException) {// #BP
            VmmpInjectInterruption(interruption_type, vector, false, 0);
            UtilVmWrite(VmcsField::kVmEntryInstructionLen, 1);
        } else {
            __debugbreak();
        }
    } else {
        __debugbreak();
    }
}


// CPUID
_Use_decl_annotations_ static void VmmpHandleCpuid(GuestContext *guest_context)
{
    unsigned int cpu_info[4] = {};
    int function_id = static_cast<int>(guest_context->gp_regs->ax);
    int sub_function_id = static_cast<int>(guest_context->gp_regs->cx);

    __cpuidex(reinterpret_cast<int *>(cpu_info), function_id, sub_function_id);

    if (function_id == 1) {// Present existence of a hypervisor using the HypervisorPresent bit
        CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
        cpu_features.fields.not_used = true;
        cpu_info[2] = static_cast<int>(cpu_features.all);
    } else if (function_id == kHyperVCpuidInterface) {
        cpu_info[0] = 'PpyH';// Leave signature of HyperPlatform onto EAX
    }

    guest_context->gp_regs->ax = cpu_info[0];
    guest_context->gp_regs->bx = cpu_info[1];
    guest_context->gp_regs->cx = cpu_info[2];
    guest_context->gp_regs->dx = cpu_info[3];
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// RDTSC
_Use_decl_annotations_ static void VmmpHandleRdtsc(GuestContext *guest_context)
{
    ULARGE_INTEGER tsc = {};
    tsc.QuadPart = __rdtsc();
    guest_context->gp_regs->dx = tsc.HighPart;
    guest_context->gp_regs->ax = tsc.LowPart;
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// RDTSCP
_Use_decl_annotations_ static void VmmpHandleRdtscp(GuestContext *guest_context)
{
    unsigned int tsc_aux = 0;
    ULARGE_INTEGER tsc = {};
    tsc.QuadPart = __rdtscp(&tsc_aux);
    guest_context->gp_regs->dx = tsc.HighPart;
    guest_context->gp_regs->ax = tsc.LowPart;
    guest_context->gp_regs->cx = tsc_aux;
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// XSETBV. It is executed at the time of system resuming
_Use_decl_annotations_ static void VmmpHandleXsetbv(GuestContext *guest_context)
{
    ULARGE_INTEGER value = {};
    value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
    value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
    _xsetbv(static_cast<ULONG>(guest_context->gp_regs->cx), value.QuadPart);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// RDMSR
_Use_decl_annotations_ static void VmmpHandleMsrReadAccess(GuestContext *guest_context)
{
    VmmpHandleMsrAccess(guest_context, true);
}


// WRMSR
_Use_decl_annotations_ static void VmmpHandleMsrWriteAccess(GuestContext *guest_context)
{
    VmmpHandleMsrAccess(guest_context, false);
}


// RDMSR and WRMSR
_Use_decl_annotations_ static void VmmpHandleMsrAccess(GuestContext *guest_context, bool read_access)
{
    Msr msr = static_cast<Msr>(guest_context->gp_regs->cx);// Apply it for VMCS instead of a real MSR if a specified MSR is either of them.

    bool transfer_to_vmcs = false;
    VmcsField vmcs_field = {};
    switch (msr)
    {
    case Msr::kIa32SysenterCs:
        vmcs_field = VmcsField::kGuestSysenterCs;
        transfer_to_vmcs = true;
        break;
    case Msr::kIa32SysenterEsp:
        vmcs_field = VmcsField::kGuestSysenterEsp;
        transfer_to_vmcs = true;
        break;
    case Msr::kIa32SysenterEip:
        vmcs_field = VmcsField::kGuestSysenterEip;
        transfer_to_vmcs = true;
        break;
    case Msr::kIa32Debugctl:
        vmcs_field = VmcsField::kGuestIa32Debugctl;
        transfer_to_vmcs = true;
        break;
    case Msr::kIa32GsBase:
        vmcs_field = VmcsField::kGuestGsBase;
        transfer_to_vmcs = true;
        break;
    case Msr::kIa32FsBase:
        vmcs_field = VmcsField::kGuestFsBase;
        transfer_to_vmcs = true;
        break;
    default:
        break;
    }

    const auto is_64bit_vmcs = UtilIsInBounds(vmcs_field, VmcsField::kIoBitmapA, VmcsField::kHostIa32PerfGlobalCtrlHigh);

    LARGE_INTEGER msr_value = {};
    if (read_access) {
        if (transfer_to_vmcs) {
            if (is_64bit_vmcs) {
                msr_value.QuadPart = UtilVmRead64(vmcs_field);
            } else {
                msr_value.QuadPart = UtilVmRead(vmcs_field);
            }
        } else {
            msr_value.QuadPart = __readmsr((ULONG)msr);
        }
        guest_context->gp_regs->ax = msr_value.LowPart;
        guest_context->gp_regs->dx = msr_value.HighPart;
    } else {
        msr_value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
        msr_value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
        if (transfer_to_vmcs) {
            if (is_64bit_vmcs) {
                UtilVmWrite64(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
            } else {
                UtilVmWrite(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
            }
        } else {
            __writemsr((ULONG)msr, msr_value.QuadPart);
        }
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}


// LIDT, SIDT, LGDT and SGDT
_Use_decl_annotations_ static void VmmpHandleGdtrOrIdtrAccess(GuestContext *guest_context)
{
    const GdtrOrIdtrInstInformation exit_qualification = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo)) };
    ULONG_PTR displacement = UtilVmRead(VmcsField::kExitQualification);// Calculate an address to be used for the instruction

    // Base
    ULONG_PTR base_value = 0;
    if (!exit_qualification.fields.base_register_invalid) {
        ULONG_PTR * register_used = VmmpSelectRegister(exit_qualification.fields.base_register, guest_context);
        base_value = *register_used;
    }

    // Index
    ULONG_PTR index_value = 0;
    if (!exit_qualification.fields.index_register_invalid) {
        ULONG_PTR * register_used = VmmpSelectRegister(exit_qualification.fields.index_register, guest_context);
        index_value = *register_used;
        switch (static_cast<Scaling>(exit_qualification.fields.scalling))
        {
        case Scaling::kNoScaling:
            index_value = index_value;
            break;
        case Scaling::kScaleBy2:
            index_value = index_value * 2;
            break;
        case Scaling::kScaleBy4:
            index_value = index_value * 4;
            break;
        case Scaling::kScaleBy8:
            index_value = index_value * 8;
            break;
        default:
            break;
        }
    }

    ULONG_PTR operation_address = base_value + index_value + displacement;
    if (static_cast<AddressSize>(exit_qualification.fields.address_size) == AddressSize::k32bit) {
        operation_address &= MAXULONG;
    }

    // Update CR3 with that of the guest since below code is going to access memory.
    ULONG_PTR guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    ULONG_PTR vmm_cr3 = __readcr3();
    __writecr3(guest_cr3);

    // Emulate the instruction
    Idtr * descriptor_table_reg = reinterpret_cast<Idtr *>(operation_address);
    switch (static_cast<GdtrOrIdtrInstructionIdentity>(exit_qualification.fields.instruction_identity))
    {
    case GdtrOrIdtrInstructionIdentity::kSgdt:
        descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestGdtrBase);
        descriptor_table_reg->limit = static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestGdtrLimit));
        break;
    case GdtrOrIdtrInstructionIdentity::kSidt:
        descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestIdtrBase);
        descriptor_table_reg->limit = static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestIdtrLimit));
        break;
    case GdtrOrIdtrInstructionIdentity::kLgdt:
        UtilVmWrite(VmcsField::kGuestGdtrBase, descriptor_table_reg->base);
        UtilVmWrite(VmcsField::kGuestGdtrLimit, descriptor_table_reg->limit);
        break;
    case GdtrOrIdtrInstructionIdentity::kLidt:
        UtilVmWrite(VmcsField::kGuestIdtrBase, descriptor_table_reg->base);
        UtilVmWrite(VmcsField::kGuestIdtrLimit, descriptor_table_reg->limit);
        break;
    }

    __writecr3(vmm_cr3);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// LLDT, LTR, SLDT, and STR
_Use_decl_annotations_ static void VmmpHandleLdtrOrTrAccess(GuestContext *guest_context)
{
    const LdtrOrTrInstInformation exit_qualification = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo)) };
    ULONG_PTR displacement = UtilVmRead(VmcsField::kExitQualification);// Calculate an address or a register to be used for the instruction
    ULONG_PTR operation_address = 0;

    if (exit_qualification.fields.register_access) {// Register
        ULONG_PTR * register_used = VmmpSelectRegister(exit_qualification.fields.register1, guest_context);
        operation_address = reinterpret_cast<ULONG_PTR>(register_used);
    } else {// Base
        ULONG_PTR base_value = 0;
        if (!exit_qualification.fields.base_register_invalid) {
            ULONG_PTR *register_used = VmmpSelectRegister(exit_qualification.fields.base_register, guest_context);
            base_value = *register_used;
        }

        // Index
        ULONG_PTR index_value = 0;
        if (!exit_qualification.fields.index_register_invalid) {
            ULONG_PTR * register_used = VmmpSelectRegister(exit_qualification.fields.index_register, guest_context);
            index_value = *register_used;
            switch (static_cast<Scaling>(exit_qualification.fields.scalling))
            {
            case Scaling::kNoScaling:
                index_value = index_value;
                break;
            case Scaling::kScaleBy2:
                index_value = index_value * 2;
                break;
            case Scaling::kScaleBy4:
                index_value = index_value * 4;
                break;
            case Scaling::kScaleBy8:
                index_value = index_value * 8;
                break;
            default:
                break;
            }
        }

        operation_address = base_value + index_value + displacement;
        if (static_cast<AddressSize>(exit_qualification.fields.address_size) == AddressSize::k32bit) {
            operation_address &= MAXULONG;
        }
    }

    // Update CR3 with that of the guest since below code is going to access memory.
    ULONG_PTR guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    ULONG_PTR vmm_cr3 = __readcr3();
    __writecr3(guest_cr3);

    // Emulate the instruction
    USHORT * selector = reinterpret_cast<USHORT *>(operation_address);
    switch (static_cast<LdtrOrTrInstructionIdentity>(exit_qualification.fields.instruction_identity))
    {
    case LdtrOrTrInstructionIdentity::kSldt:
        *selector = static_cast<USHORT>(UtilVmRead(VmcsField::kGuestLdtrSelector));
        break;
    case LdtrOrTrInstructionIdentity::kStr:
        *selector = static_cast<USHORT>(UtilVmRead(VmcsField::kGuestTrSelector));
        break;
    case LdtrOrTrInstructionIdentity::kLldt:
        UtilVmWrite(VmcsField::kGuestLdtrSelector, *selector);
        break;
    case LdtrOrTrInstructionIdentity::kLtr:
        UtilVmWrite(VmcsField::kGuestTrSelector, *selector);
        break;
    }

    __writecr3(vmm_cr3);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// MOV to / from DRx
_Use_decl_annotations_ static void VmmpHandleDrAccess(GuestContext *guest_context)
{
    MovDrQualification exit_qualification = { UtilVmRead(VmcsField::kExitQualification) };
    ULONG_PTR * register_used = VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

    // Emulate the instruction
    switch (static_cast<MovDrDirection>(exit_qualification.fields.direction))
    {
    case MovDrDirection::kMoveToDr:
      // clang-format off
        switch (exit_qualification.fields.debugl_register)
        {
        case 0:
            __writedr(0, *register_used);
            break;
        case 1:
            __writedr(1, *register_used);
            break;
        case 2:
            __writedr(2, *register_used);
            break;
        case 3:
            __writedr(3, *register_used);
            break;
        case 4:
            __writedr(4, *register_used);
            break;
        case 5:
            __writedr(5, *register_used);
            break;
        case 6:
            __writedr(6, *register_used);
            break;
        case 7:
            UtilVmWrite(VmcsField::kGuestDr7, *register_used);
            break;
        default:
            break;
        }
        // clang-format on
        break;
    case MovDrDirection::kMoveFromDr:
      // clang-format off
        switch (exit_qualification.fields.debugl_register)
        {
        case 0:
            *register_used = __readdr(0);
            break;
        case 1:
            *register_used = __readdr(1);
            break;
        case 2:
            *register_used = __readdr(2);
            break;
        case 3:
            *register_used = __readdr(3);
            break;
        case 4:
            *register_used = __readdr(4);
            break;
        case 5:
            *register_used = __readdr(5);
            break;
        case 6:
            *register_used = __readdr(6);
            break;
        case 7:
            *register_used = UtilVmRead(VmcsField::kGuestDr7);
            break;
        default:
            break;
        }
        // clang-format on
        break;
    default:
        __debugbreak();
        break;
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}


// IN, INS, OUT, OUTS
_Use_decl_annotations_ static void VmmpHandleIoPort(GuestContext *guest_context)
{
    const IoInstQualification exit_qualification = { UtilVmRead(VmcsField::kExitQualification) };
    bool is_in = exit_qualification.fields.direction == 1;  // to memory?
    bool is_string = exit_qualification.fields.string_instruction == 1;
    bool is_rep = exit_qualification.fields.rep_prefixed == 1;
    USHORT port = static_cast<USHORT>(exit_qualification.fields.port_number);
    void * string_address = reinterpret_cast<void *>((is_in) ? guest_context->gp_regs->di : guest_context->gp_regs->si);
    unsigned long count = static_cast<unsigned long>((is_rep) ? guest_context->gp_regs->cx : 1);
    void * address = (is_string) ? string_address : &guest_context->gp_regs->ax;
    SIZE_T size_of_access = 0;
    const char *suffix = "";

    switch (static_cast<IoInstSizeOfAccess>(exit_qualification.fields.size_of_access))
    {
    case IoInstSizeOfAccess::k1Byte:
        size_of_access = 1;
        suffix = "B";
        break;
    case IoInstSizeOfAccess::k2Byte:
        size_of_access = 2;
        suffix = "W";
        break;
    case IoInstSizeOfAccess::k4Byte:
        size_of_access = 4;
        suffix = "D";
        break;
    }

    LOG_DEBUG_SAFE("GuestIp= %016Ix, Port= %04x, %s%s%s", guest_context->ip, port, (is_in ? "IN" : "OUT"), (is_string ? "S" : ""), (is_string ? suffix : ""));

    VmmpIoWrapper(is_in, is_string, size_of_access, port, address, count);

    // Update RCX, RDI and RSI accordingly.
    // Note that this code can handle only the REP prefix.
    if (is_string) {
        auto update_count = (is_rep) ? guest_context->gp_regs->cx : 1;
        auto update_size = update_count * size_of_access;
        auto update_register = (is_in) ? &guest_context->gp_regs->di : &guest_context->gp_regs->si;

        if (guest_context->flag_reg.fields.df) {
            *update_register = *update_register - update_size;
        } else {
            *update_register = *update_register + update_size;
        }

        if (is_rep) {
            guest_context->gp_regs->cx = 0;
        }
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}


// Perform IO instruction according with parameters
_Use_decl_annotations_ static void VmmpIoWrapper(bool to_memory, bool is_string, SIZE_T size_of_access, unsigned short port, void *address, unsigned long count)
{
    NT_ASSERT(size_of_access == 1 || size_of_access == 2 || size_of_access == 4);

    // Update CR3 with that of the guest since below code is going to access memory.
    auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    auto vmm_cr3 = __readcr3();
    __writecr3(guest_cr3);

    // clang-format off
    if (to_memory) {
        if (is_string) {// INS
            switch (size_of_access)
            {
            case 1:
                __inbytestring(port, reinterpret_cast<UCHAR*>(address), count);
                break;
            case 2:
                __inwordstring(port, reinterpret_cast<USHORT*>(address), count);
                break;
            case 4:
                __indwordstring(port, reinterpret_cast<ULONG*>(address), count);
                break;
            }
        } else {// IN
            switch (size_of_access)
            {
            case 1:
                *reinterpret_cast<UCHAR*>(address) = __inbyte(port);
                break;
            case 2:
                *reinterpret_cast<USHORT*>(address) = __inword(port);
                break;
            case 4:
                *reinterpret_cast<ULONG*>(address) = __indword(port);
                break;
            }
        }
    } else {
        if (is_string) {// OUTS
            switch (size_of_access)
            {
            case 1:
                __outbytestring(port, reinterpret_cast<UCHAR*>(address), count);
                break;
            case 2:
                __outwordstring(port, reinterpret_cast<USHORT*>(address), count);
                break;
            case 4:
                __outdwordstring(port, reinterpret_cast<ULONG*>(address), count);
                break;
            }
        } else {// OUT
            switch (size_of_access)
            {
            case 1:
                __outbyte(port, *reinterpret_cast<UCHAR*>(address));
                break;
            case 2:
                __outword(port, *reinterpret_cast<USHORT*>(address));
                break;
            case 4:
                __outdword(port, *reinterpret_cast<ULONG*>(address));
                break;
            }
        }
    }
    // clang-format on

    __writecr3(vmm_cr3);
}


// MOV to / from CRx
_Use_decl_annotations_ static void VmmpHandleCrAccess(GuestContext *guest_context)
{
    MovCrQualification exit_qualification = { UtilVmRead(VmcsField::kExitQualification) };
    auto register_used = VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

    switch (static_cast<MovCrAccessType>(exit_qualification.fields.access_type)) 
    {
    case MovCrAccessType::kMoveToCr:
        switch (exit_qualification.fields.control_register)
        {
        case 0:// CR0 <- Reg
        {
            Cr0 cr0_fixed0 = { __readmsr(0x486) };
            Cr0 cr0_fixed1 = { __readmsr(0x487) };
            Cr0 cr0 = { *register_used };
            cr0.all &= cr0_fixed1.all;
            cr0.all |= cr0_fixed0.all;
            UtilVmWrite(VmcsField::kGuestCr0, cr0.all);
            UtilVmWrite(VmcsField::kCr0ReadShadow, cr0.all);
            break;
        }
        case 3:// CR3 <- Reg
            UtilInvvpidSingleContextExceptGlobal(static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1));
            UtilVmWrite(VmcsField::kGuestCr3, *register_used);
            break;
        case 4:// CR4 <- Reg
        {
            UtilInvvpidAllContext();
            Cr4 cr4_fixed0 = { __readmsr(0x488) };
            Cr4 cr4_fixed1 = { __readmsr(0x489) };
            Cr4 cr4 = { *register_used };
            cr4.all &= cr4_fixed1.all;
            cr4.all |= cr4_fixed0.all;
            UtilVmWrite(VmcsField::kGuestCr4, cr4.all);
            UtilVmWrite(VmcsField::kCr4ReadShadow, cr4.all);
            break;
        }
        case 8:// CR8 <- Reg
            guest_context->cr8 = *register_used;
            break;
        default:
            __debugbreak();
            break;
        }
        break;
    case MovCrAccessType::kMoveFromCr:
        switch (exit_qualification.fields.control_register)
        {
        case 3:// Reg <- CR3
            *register_used = UtilVmRead(VmcsField::kGuestCr3);
            break;
        case 8:// Reg <- CR8
            *register_used = guest_context->cr8;
            break;
        default:
            __debugbreak();
            break;
        }
        break;

      // Unimplemented
    case MovCrAccessType::kClts:
    case MovCrAccessType::kLmsw:
    default:
        KdBreakPoint();
        break;
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}


_Use_decl_annotations_ static void VmmpHandleVmx(GuestContext *guest_context)
// VMX instructions except for VMCALL
{
    // See: CONVENTIONS
    guest_context->flag_reg.fields.cf = true;  // Error without status
    guest_context->flag_reg.fields.pf = false;
    guest_context->flag_reg.fields.af = false;
    guest_context->flag_reg.fields.zf = false;  // Error without status
    guest_context->flag_reg.fields.sf = false;
    guest_context->flag_reg.fields.of = false;
    UtilVmWrite(VmcsField::kGuestRflags, guest_context->flag_reg.all);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// VMCALL
_Use_decl_annotations_ static void VmmpHandleVmCall(GuestContext *guest_context)
{
    // VMCALL convention for HyperPlatform:
    //  ecx: hyper-call number (always 32bit)
    //  edx: arbitrary context parameter (pointer size)
    // Any unsuccessful VMCALL will inject #UD into a guest
    auto hypercall_number = static_cast<HypercallNumber>(guest_context->gp_regs->cx);
    auto context = reinterpret_cast<void *>(guest_context->gp_regs->dx);

    switch (hypercall_number)
    {
    case HypercallNumber::kTerminateVmm:// Unloading requested. This VMCALL is allowed to execute only from CPL=0
        if (VmmpGetGuestCpl() == 0) {
            VmmpHandleVmCallTermination(guest_context, context);
        } else {
            VmmpIndicateUnsuccessfulVmcall(guest_context);
        }
        break;
    case HypercallNumber::kPingVmm:// Sample VMCALL handler
        VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    case HypercallNumber::kGetSharedProcessorData:
        *reinterpret_cast<void **>(context) = guest_context->stack->processor_data->shared_data;
        VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    default:// Unsupported hypercall
        VmmpIndicateUnsuccessfulVmcall(guest_context);
    }
}


// INVD
_Use_decl_annotations_ static void VmmpHandleInvalidateInternalCaches(GuestContext *guest_context)
{
    AsmInvalidateInternalCaches();
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// INVLPG
_Use_decl_annotations_ static void VmmpHandleInvalidateTlbEntry(GuestContext *guest_context)
{
    auto invalidate_address = reinterpret_cast<void *>(UtilVmRead(VmcsField::kExitQualification));
    __invlpg(invalidate_address);
    UtilInvvpidIndividualAddress(static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1), invalidate_address);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


_Use_decl_annotations_ static void VmmpHandleEptViolation(GuestContext *guest_context)
// EXIT_REASON_EPT_VIOLATION
{
    auto processor_data = guest_context->stack->processor_data;
    EptHandleEptViolation(processor_data->ept_data);
}


_Use_decl_annotations_ static void VmmpHandleEptMisconfig(GuestContext *guest_context)
// EXIT_REASON_EPT_MISCONFIG
{
    UNREFERENCED_PARAMETER(guest_context);

    ULONG_PTR fault_address = UtilVmRead(VmcsField::kGuestPhysicalAddress);
    EptCommonEntry * ept_pt_entry = EptGetEptPtEntry(guest_context->stack->processor_data->ept_data, fault_address);
    __debugbreak();
}


_Use_decl_annotations_ static ULONG_PTR *VmmpSelectRegister(ULONG index, GuestContext *guest_context)
// Selects a register to be used based on the index
{
    ULONG_PTR *register_used = nullptr;
    // clang-format off
    switch (index) 
    {
    case 0:
        register_used = &guest_context->gp_regs->ax;
        break;
    case 1:
        register_used = &guest_context->gp_regs->cx;
        break;
    case 2:
        register_used = &guest_context->gp_regs->dx;
        break;
    case 3:
        register_used = &guest_context->gp_regs->bx;
        break;
    case 4:
        register_used = &guest_context->gp_regs->sp;
        break;
    case 5:
        register_used = &guest_context->gp_regs->bp;
        break;
    case 6:
        register_used = &guest_context->gp_regs->si;
        break;
    case 7:
        register_used = &guest_context->gp_regs->di;
        break;
    case 8:
        register_used = &guest_context->gp_regs->r8;
        break;
    case 9:
        register_used = &guest_context->gp_regs->r9;
        break;
    case 10:
        register_used = &guest_context->gp_regs->r10;
        break;
    case 11:
        register_used = &guest_context->gp_regs->r11;
        break;
    case 12:
        register_used = &guest_context->gp_regs->r12;
        break;
    case 13:
        register_used = &guest_context->gp_regs->r13;
        break;
    case 14:
        register_used = &guest_context->gp_regs->r14;
        break;
    case 15:
        register_used = &guest_context->gp_regs->r15;
        break;
    default:
        KdBreakPoint();
        break;
    }

    return register_used;// clang-format on
}


static void VmmpDumpGuestState() 
// Dumps guest state VMCS fields
{
  // clang-format off
    LOG_DEBUG_SAFE("Guest EsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestEsSelector));
    LOG_DEBUG_SAFE("Guest CsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestCsSelector));
    LOG_DEBUG_SAFE("Guest SsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestSsSelector));
    LOG_DEBUG_SAFE("Guest DsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestDsSelector));
    LOG_DEBUG_SAFE("Guest FsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestFsSelector));
    LOG_DEBUG_SAFE("Guest GsSelector   = %016Ix", UtilVmRead(VmcsField::kGuestGsSelector));
    LOG_DEBUG_SAFE("Guest LdtrSelector = %016Ix", UtilVmRead(VmcsField::kGuestLdtrSelector));
    LOG_DEBUG_SAFE("Guest TrSelector   = %016Ix", UtilVmRead(VmcsField::kGuestTrSelector));

    LOG_DEBUG_SAFE("Guest Ia32Debugctl = %016llx", UtilVmRead64(VmcsField::kGuestIa32Debugctl));

    LOG_DEBUG_SAFE("Guest EsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestEsLimit));
    LOG_DEBUG_SAFE("Guest CsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestCsLimit));
    LOG_DEBUG_SAFE("Guest SsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestSsLimit));
    LOG_DEBUG_SAFE("Guest DsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestDsLimit));
    LOG_DEBUG_SAFE("Guest FsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestFsLimit));
    LOG_DEBUG_SAFE("Guest GsLimit      = %016Ix", UtilVmRead(VmcsField::kGuestGsLimit));
    LOG_DEBUG_SAFE("Guest LdtrLimit    = %016Ix", UtilVmRead(VmcsField::kGuestLdtrLimit));
    LOG_DEBUG_SAFE("Guest TrLimit      = %016Ix", UtilVmRead(VmcsField::kGuestTrLimit));
    LOG_DEBUG_SAFE("Guest GdtrLimit    = %016Ix", UtilVmRead(VmcsField::kGuestGdtrLimit));
    LOG_DEBUG_SAFE("Guest IdtrLimit    = %016Ix", UtilVmRead(VmcsField::kGuestIdtrLimit));
    LOG_DEBUG_SAFE("Guest EsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestEsArBytes));
    LOG_DEBUG_SAFE("Guest CsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestCsArBytes));
    LOG_DEBUG_SAFE("Guest SsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestSsArBytes));
    LOG_DEBUG_SAFE("Guest DsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestDsArBytes));
    LOG_DEBUG_SAFE("Guest FsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestFsArBytes));
    LOG_DEBUG_SAFE("Guest GsArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestGsArBytes));
    LOG_DEBUG_SAFE("Guest LdtrArBytes  = %016Ix", UtilVmRead(VmcsField::kGuestLdtrArBytes));
    LOG_DEBUG_SAFE("Guest TrArBytes    = %016Ix", UtilVmRead(VmcsField::kGuestTrArBytes));
    LOG_DEBUG_SAFE("Guest SysenterCs   = %016Ix", UtilVmRead(VmcsField::kGuestSysenterCs));

    LOG_DEBUG_SAFE("Guest Cr0          = %016Ix", UtilVmRead(VmcsField::kGuestCr0));
    LOG_DEBUG_SAFE("Guest Cr3          = %016Ix", UtilVmRead(VmcsField::kGuestCr3));
    LOG_DEBUG_SAFE("Guest Cr4          = %016Ix", UtilVmRead(VmcsField::kGuestCr4));

    LOG_DEBUG_SAFE("Guest EsBase       = %016Ix", UtilVmRead(VmcsField::kGuestEsBase));
    LOG_DEBUG_SAFE("Guest CsBase       = %016Ix", UtilVmRead(VmcsField::kGuestCsBase));
    LOG_DEBUG_SAFE("Guest SsBase       = %016Ix", UtilVmRead(VmcsField::kGuestSsBase));
    LOG_DEBUG_SAFE("Guest DsBase       = %016Ix", UtilVmRead(VmcsField::kGuestDsBase));
    LOG_DEBUG_SAFE("Guest FsBase       = %016Ix", UtilVmRead(VmcsField::kGuestFsBase));
    LOG_DEBUG_SAFE("Guest GsBase       = %016Ix", UtilVmRead(VmcsField::kGuestGsBase));

    LOG_DEBUG_SAFE("Guest LdtrBase     = %016Ix", UtilVmRead(VmcsField::kGuestLdtrBase));
    LOG_DEBUG_SAFE("Guest TrBase       = %016Ix", UtilVmRead(VmcsField::kGuestTrBase));
    LOG_DEBUG_SAFE("Guest GdtrBase     = %016Ix", UtilVmRead(VmcsField::kGuestGdtrBase));
    LOG_DEBUG_SAFE("Guest IdtrBase     = %016Ix", UtilVmRead(VmcsField::kGuestIdtrBase));
    LOG_DEBUG_SAFE("Guest Dr7          = %016Ix", UtilVmRead(VmcsField::kGuestDr7));
    LOG_DEBUG_SAFE("Guest Rsp          = %016Ix", UtilVmRead(VmcsField::kGuestRsp));
    LOG_DEBUG_SAFE("Guest Rip          = %016Ix", UtilVmRead(VmcsField::kGuestRip));
    LOG_DEBUG_SAFE("Guest Rflags       = %016Ix", UtilVmRead(VmcsField::kGuestRflags));
    LOG_DEBUG_SAFE("Guest SysenterEsp  = %016Ix", UtilVmRead(VmcsField::kGuestSysenterEsp));
    LOG_DEBUG_SAFE("Guest SysenterEip  = %016Ix", UtilVmRead(VmcsField::kGuestSysenterEip));
  // clang-format on
}


_Use_decl_annotations_ static void VmmpAdjustGuestInstructionPointer(GuestContext *guest_context)
// Advances guest's IP to the next instruction
{
    ULONG_PTR exit_inst_length = UtilVmRead(VmcsField::kVmExitInstructionLen);
    UtilVmWrite(VmcsField::kGuestRip, guest_context->ip + exit_inst_length);
    
    if (guest_context->flag_reg.fields.tf) {// Inject #DB if TF is set
        VmmpInjectInterruption(InterruptionType::kHardwareException, InterruptionVector::kDebugException, false, 0);
        UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);
    }
}


_Use_decl_annotations_ void __stdcall VmmVmxFailureHandler(AllRegisters *all_regs)
// Handle VMRESUME or VMXOFF failure. Fatal error.
{
    //ULONG_PTR guest_ip = UtilVmRead(VmcsField::kGuestRip);
    // See: VM-Instruction Error Numbers
    ULONG_PTR vmx_error = (all_regs->flags.fields.zf) ? UtilVmRead(VmcsField::kVmInstructionError) : 0;
    __debugbreak();
}


_Use_decl_annotations_ static void VmmpIndicateSuccessfulVmcall(GuestContext *guest_context)
// Indicates successful VMCALL
{
    // See: CONVENTIONS
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.pf = false;
    guest_context->flag_reg.fields.af = false;
    guest_context->flag_reg.fields.zf = false;
    guest_context->flag_reg.fields.sf = false;
    guest_context->flag_reg.fields.of = false;
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.zf = false;
    UtilVmWrite(VmcsField::kGuestRflags, guest_context->flag_reg.all);
    VmmpAdjustGuestInstructionPointer(guest_context);
}


// Indicates unsuccessful VMCALL
_Use_decl_annotations_ static void VmmpIndicateUnsuccessfulVmcall(GuestContext *guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);

    VmmpInjectInterruption(InterruptionType::kHardwareException, InterruptionVector::kInvalidOpcodeException, false, 0);
    UtilVmWrite(VmcsField::kVmEntryInstructionLen, 3);  // VMCALL is 3 bytes
}


_Use_decl_annotations_ static void VmmpHandleVmCallTermination(GuestContext *guest_context, void *context)
// Handles an unloading request
{
  // The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
  // It is not correct value but fine to ignore since vmresume loads correct values from VMCS.
  // But here, we are going to skip vmresume and simply return to where VMCALL is executed.
  // It results in keeping those broken values and ends up with bug check 109, so we should fix them manually.
    ULONG_PTR gdt_limit = UtilVmRead(VmcsField::kGuestGdtrLimit);
    ULONG_PTR gdt_base = UtilVmRead(VmcsField::kGuestGdtrBase);
    ULONG_PTR idt_limit = UtilVmRead(VmcsField::kGuestIdtrLimit);
    ULONG_PTR idt_base = UtilVmRead(VmcsField::kGuestIdtrBase);
    Gdtr gdtr = { static_cast<USHORT>(gdt_limit), gdt_base };
    Idtr idtr = { static_cast<USHORT>(idt_limit), idt_base };
    __lgdt(&gdtr);
    __lidt(&idtr);

    // Store an address of the management structure to the context parameter
    ProcessorData ** result_ptr = reinterpret_cast<ProcessorData **>(context);
    *result_ptr = guest_context->stack->processor_data;

    // Set rip to the next instruction of VMCALL
    ULONG_PTR exit_instruction_length = UtilVmRead(VmcsField::kVmExitInstructionLen);
    ULONG_PTR return_address = guest_context->ip + exit_instruction_length;

    // Since the flag register is overwritten after VMXOFF, we should manually indicates that VMCALL was successful by clearing those flags.
    // See: CONVENTIONS
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.pf = false;
    guest_context->flag_reg.fields.af = false;
    guest_context->flag_reg.fields.zf = false;
    guest_context->flag_reg.fields.sf = false;
    guest_context->flag_reg.fields.of = false;
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.zf = false;

    // Set registers used after VMXOFF to recover the context.
    // Volatile registers must be used because those changes are reflected to the guest's context after VMXOFF.
    guest_context->gp_regs->cx = return_address;
    guest_context->gp_regs->dx = guest_context->gp_regs->sp;
    guest_context->gp_regs->ax = guest_context->flag_reg.all;
    guest_context->vm_continue = false;
}


static UCHAR VmmpGetGuestCpl()
// Returns guest's CPL
{
    VmxRegmentDescriptorAccessRight ar = { static_cast<unsigned int>(UtilVmRead(VmcsField::kGuestSsArBytes)) };
    return ar.fields.dpl;
}


// Injects interruption to a guest
_Use_decl_annotations_ static void VmmpInjectInterruption(InterruptionType interruption_type, InterruptionVector vector, bool deliver_error_code, ULONG32 error_code)
{
    VmEntryInterruptionInformationField inject = {};
    inject.fields.valid = true;
    inject.fields.interruption_type = static_cast<ULONG32>(interruption_type);
    inject.fields.vector = static_cast<ULONG32>(vector);
    inject.fields.deliver_error_code = deliver_error_code;
    UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);

    if (deliver_error_code) {
        UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, error_code);
    }
}

}  // extern "C"
