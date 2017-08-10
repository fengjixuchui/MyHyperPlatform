// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to assembly functions.

#pragma once

#include "ia32_type.h"

extern "C"
{
/// A wrapper for vm_initialization_routine.
/// @param vm_initialization_routine  A function pointer for entering VMX-mode
/// @param context  A context parameter for vm_initialization_routine
/// @return true if vm_initialization_routine was successfully executed
bool __stdcall AsmInitializeVm(_In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR, _In_opt_ void *), _In_opt_ void *context);

void __stdcall AsmVmmEntryPoint();/// An entry point of VMM where gets called whenever VM-exit occurred.

/// Executes VMCALL with the given hypercall number and a context.
/// @param hypercall_number   A hypercall number
/// @param context  A context parameter for VMCALL
/// @return Equivalent to #VmxStatus
unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number, _In_opt_ void *context);

/// Writes to GDT
/// @param gdtr   A value to write
void __stdcall AsmWriteGDT(_In_ const Gdtr *gdtr);

/// Reads SGDT
/// @param gdtr   A pointer to read GDTR
void __stdcall AsmReadGDT(_Out_ Gdtr *gdtr);

/// Reads SLDT
/// @return LDT
USHORT __stdcall AsmReadLDTR();

/// Reads STR
/// @return TR
USHORT __stdcall AsmReadTR();

/// Reads ES
/// @return ES
USHORT __stdcall AsmReadES();

/// Reads CS
/// @return CS
USHORT __stdcall AsmReadCS();

/// Reads SS
/// @return SS
USHORT __stdcall AsmReadSS();

/// Reads DS
/// @return DS
USHORT __stdcall AsmReadDS();

/// Reads FS
/// @return FS
USHORT __stdcall AsmReadFS();

/// Reads GS
/// @return GS
USHORT __stdcall AsmReadGS();

/// Loads access rights byte
/// @param segment_selector   A value to get access rights byte
/// @return An access rights byte
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

/// Invalidates internal caches
void __stdcall AsmInvalidateInternalCaches();

/// Writes to CR2
/// @param cr2_value  A value to write
void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);

/// Invalidates translations derived from EPT
/// @param invept_type  A type of invalidation
/// @param invept_descriptor  A reference to EPTP to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvept(_In_ InvEptType invept_type, _In_ const InvEptDescriptor *invept_descriptor);

/// Invalidate translations based on VPID
/// @param invvpid_type  A type of invalidation
/// @param invvpid_descriptor  A description of translations to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvvpid(_In_ InvVpidType invvpid_type, _In_ const InvVpidDescriptor *invvpid_descriptor);


/// Writes to GDT
/// @param gdtr   A value to write
inline void __sgdt(_Out_ void *gdtr)
{
    AsmReadGDT(static_cast<Gdtr *>(gdtr));
}

/// Reads SGDT
/// @param gdtr   A pointer to read GDTR
inline void __lgdt(_In_ void *gdtr)
{ 
    AsmWriteGDT(static_cast<Gdtr *>(gdtr));
}

}  // extern "C"
