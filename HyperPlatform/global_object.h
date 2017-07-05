// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to global object functions.

#pragma once

#include <fltKernel.h>

extern "C"
{
/// Calls all constructors and register all destructor
/// @return STATUS_SUCCESS on success
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS GlobalObjectInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void GlobalObjectTermination();/// Calls all destructors
}
