// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares and implements common things across the project

/// @mainpage
/// @section whats About
/// These pages serve as a programmer's reference manual for HyperPlatform and were automatically generated from the source using Doxygen.
///
/// For compilation and installation of HyperPlatform, see the HyperPlatform project page.
/// For more general information about development using HyperPlatform, see User's Documents in the project page.
/// @li https://github.com/tandasat/HyperPlatform
///
/// Some of good places to start are the files page that provides a brief description of each files,
/// the DriverEntry() function where is an entry point of HyperPlatform, and the VmmVmExitHandler() function, a high-level entry point of VM-exit handlers.
///
/// @subsection links External Document
/// This document often refers to the Intel 64 and IA-32 Architectures Software Developer Manuals (Intel SDM). Any descriptions like
/// "See: CONTROL REGISTERS" implies that details are explained in a page or a table titled as "CONTROL REGISTERS" in the Intel SDM.
/// @li
/// http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
///
/// @copyright Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#pragma once

#include <fltKernel.h>

// C30030: Calling a memory allocating function and passing a parameter that indicates executable memory
// Disable C30030 since POOL_NX_OPTIN + ExInitializeDriverRuntime is in place.
// This warning is false positive and can be seen when Target Platform Version equals to 10.0.14393.0.
#pragma prefast(disable : 30030)

/// Enable or disable performance monitoring globally
/// Enables #HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE() which measures an elapsed time of the scope when set to non 0.
/// Enabling it introduces negative performance impact.
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1

static const ULONG TAG = 'PpyH';/// A pool tag
