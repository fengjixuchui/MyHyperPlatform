// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// @brief Declares interfaces to hot-plug functions.

#pragma once

#include <fltKernel.h>

extern "C"
{
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HotplugCallbackInitialization();
_IRQL_requires_max_(PASSIVE_LEVEL) void HotplugCallbackTermination();
}
