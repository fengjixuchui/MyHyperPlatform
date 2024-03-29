// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to VMM initialization functions

#pragma once

#include <fltKernel.h>

extern "C"
{
/// Virtualizes all processors
/// Initializes a VMCS region and virtualizes (ie, enters the VMX non-root operation mode) for each processor.
/// Returns non STATUS_SUCCESS value if any of processors failed to do so. In that case, this function de-virtualize already virtualized processors.
NTSTATUS VmInitialization();

void VmTermination();/// De-virtualize all processors

/// Virtualizes the specified processor
/// @param proc_num   A processor number to virtualize
/// The processor 0 must have already been virtualized, or it fails.
NTSTATUS VmHotplugCallback(const PROCESSOR_NUMBER& proc_num);
}
