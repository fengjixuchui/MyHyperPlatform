// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to performance measurement functions.

#pragma once

#include "perf_counter.h"

extern "C"
{
    _IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS PerfInitialization();/// Makes #HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE() ready for use
    _IRQL_requires_max_(PASSIVE_LEVEL) void PerfTermination();/// Ends performance monitoring and outputs its results
    
    extern PerfCollector* g_performance_collector;/// Stores all performance data collected by #HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE().
}
