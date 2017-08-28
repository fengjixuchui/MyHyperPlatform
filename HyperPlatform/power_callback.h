// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// @brief Declares interfaces to power functions.

#pragma once

#include <fltKernel.h>

extern "C"
{
    NTSTATUS PowerCallbackInitialization();
    void PowerCallbackTermination();
}
