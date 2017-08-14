// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to VMM functions.

#pragma once

#include <fltKernel.h>

#include "ia32_type.h"

struct SharedProcessorData {/// Represents VMM related data shared across all processors
  volatile long reference_count;  //!< Number of processors sharing this data
  void* msr_bitmap;               //!< Bitmap to activate MSR I/O VM-exit
  void* io_bitmap_a;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
  void* io_bitmap_b;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
};

struct ProcessorData {/// Represents VMM related data associated with each processor
  SharedProcessorData* shared_data;         //!< Shared data
  void* vmm_stack_limit;                    //!< A head of VA for VMM stack
  struct VmControlStructure* vmxon_region;  //!< VA of a VMXON region
  struct VmControlStructure* vmcs_region;   //!< VA of a VMCS region
  struct EptData* ept_data;                 //!< A pointer to EPT related data
};

#pragma warning(disable:4189) // 局部变量已初始化但不引用

extern "C"
{
    // Represents raw structure of stack of VMM when VmmVmExitHandler() is called
    struct VmmInitialStack {
        GpRegistersX64 gp_regs;
        ULONG_PTR reserved;
        ProcessorData *processor_data;
    };
}

// Things need to be read and written by each VM-exit handler
struct GuestContext {
    union {
        VmmInitialStack *stack;
        GpRegistersX64 *gp_regs;
    };
    FlagRegister flag_reg;
    ULONG_PTR ip;
    ULONG_PTR cr8;
    KIRQL irql;
    bool vm_continue;
};
static_assert(sizeof(GuestContext) == 40, "Size check");
