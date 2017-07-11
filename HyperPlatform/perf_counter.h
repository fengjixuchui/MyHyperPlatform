// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to performance measurement primitives.
///
/// @warning
/// All exposed interfaces but #HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME are meant to be for internal use only. Also, the macro is only used by a wrapper code.
///
/// @see performance.h

#pragma once

#include <fltKernel.h>


/// Responsible for collecting and saving data supplied by PerfCounter.
class PerfCollector
{
public:
    using InitialOutputRoutine = void(_In_opt_ void* output_context);/// A function type for printing out a header line of results
    using FinalOutputRoutine = void(_In_opt_ void* output_context);/// A function type for printing out a footer line of results

    /// A function type for printing out results
    using OutputRoutine = void(_In_ const char* location_name, _In_ ULONG64 total_execution_count, _In_ ULONG64 total_elapsed_time, _In_opt_ void* output_context);

    using LockRoutine = void(_In_opt_ void* lock_context);/// A function type for acquiring and releasing a lock

    /// Constructor; call this only once before any other code in this module runs
    /// @param output_routine   A function pointer for printing out results
    /// @param initial_output_routine A function pointer for printing a header line of results
    /// @param final_output_routine   A function pointer for printing a footer line of results
    /// @param lock_enter_routine   A function pointer for acquiring a lock
    /// @param lock_leave_routine   A function pointer for releasing a lock
    /// @param lock_context   An arbitrary parameter for \a lock_enter_routine and \a lock_leave_routine
    /// @param output_context   An arbitrary parameter for \a output_routine, \a initial_output_routine and \a final_output_routine.
    void Initialize(
        _In_ OutputRoutine* output_routine,
        _In_opt_ InitialOutputRoutine* initial_output_routine = NoOutputRoutine,
        _In_opt_ FinalOutputRoutine* final_output_routine = NoOutputRoutine,
        _In_opt_ LockRoutine* lock_enter_routine = NoLockRoutine,
        _In_opt_ LockRoutine* lock_leave_routine = NoLockRoutine,
        _In_opt_ void* lock_context = nullptr,
        _In_opt_ void* output_context = nullptr)
    {
        initial_output_routine_ = initial_output_routine;
        final_output_routine_ = final_output_routine;
        output_routine_ = output_routine;
        lock_enter_routine_ = lock_enter_routine;
        lock_leave_routine_ = lock_leave_routine;
        lock_context_ = lock_context;
        output_context_ = output_context;
        memset(data_, 0, sizeof(data_));
    }

    /// Destructor; prints out accumulated performance results.
    void Terminate()
    {
        if (data_[0].key) {
            initial_output_routine_(output_context_);
        }

        for (ULONG i = 0ul; i < kMaxNumberOfDataEntries; i++)
        {
            if (data_[i].key == nullptr) {
                break;
            }

            output_routine_(data_[i].key, data_[i].total_execution_count, data_[i].total_elapsed_time, output_context_);
        }

        if (data_[0].key) {
            final_output_routine_(output_context_);
        }
    }

    /// Saves performance data taken by PerfCounter.
    bool AddData(_In_ const char* location_name, _In_ ULONG64 elapsed_time)
    {
        ScopedLock lock(lock_enter_routine_, lock_leave_routine_, lock_context_);

        ULONG data_index = GetPerfDataIndex(location_name);
        if (data_index == kInvalidDataIndex) {
            return false;
        }

        data_[data_index].total_execution_count++;
        data_[data_index].total_elapsed_time += elapsed_time;
        return true;
    }

private:
    static const ULONG kInvalidDataIndex = MAXULONG;
    static const ULONG kMaxNumberOfDataEntries = 200;

    /// Represents performance data for each location
    struct PerfDataEntry {
        const char* key;                //!< Identifies a subject matter location
        ULONG64 total_execution_count;  //!< How many times executed
        ULONG64 total_elapsed_time;     //!< An accumulated elapsed time
    };

    /// Scoped lock
    class ScopedLock
    {
    public:
        /// Acquires a lock using \a lock_routine.
        /// @param lock_routine  A function pointer for acquiring a lock
        /// @param leave_routine A function pointer for releasing a lock
        /// @param lock_context  An arbitrary parameter for \a lock_enter_routine and \a lock_leave_routine
        ScopedLock(_In_ LockRoutine* lock_routine, _In_ LockRoutine* leave_routine, _In_opt_ void* lock_context)
            : lock_routine_(lock_routine), leave_routine_(leave_routine), lock_context_(lock_context)
        {
            lock_routine_(lock_context_);
        }

        /// Releases a lock using ScopedLock::leave_routine_.
        ~ScopedLock()
        {
            leave_routine_(lock_context_);
        }

    private:
        LockRoutine* lock_routine_;
        LockRoutine* leave_routine_;
        void* lock_context_;
    };

    /// Default empty output routine
    /// @param output_context   Ignored
    static void NoOutputRoutine(_In_opt_ void* output_context) {
        UNREFERENCED_PARAMETER(output_context);
    }

    /// Default empty lock and release routine
    /// @param lock_context   Ignored
    static void NoLockRoutine(_In_opt_ void* lock_context) {
        UNREFERENCED_PARAMETER(lock_context);
    }

    /// Returns an index of data corresponds to the location_name.
    /// @param key   A location to get an index of corresponding data entry
    /// @return   An index of data or kInvalidDataIndex
    /// It adds a new entry when the key is not found in existing entries.
    /// Returns kInvalidDataIndex if a corresponding entry is not found and there is no room to add a new entry.
    ULONG GetPerfDataIndex(_In_ const char* key)
    {
        if (!key) {
            return false;
        }

        for (ULONG i = 0ul; i < kMaxNumberOfDataEntries; i++)
        {
            if (data_[i].key == key) {
                return i;
            }

            if (data_[i].key == nullptr) {
                data_[i].key = key;
                return i;
            }
        }

        return kInvalidDataIndex;
    }

    InitialOutputRoutine* initial_output_routine_;
    FinalOutputRoutine* final_output_routine_;
    OutputRoutine* output_routine_;
    LockRoutine* lock_enter_routine_;
    LockRoutine* lock_leave_routine_;
    void* lock_context_;
    void* output_context_;
    PerfDataEntry data_[kMaxNumberOfDataEntries];
};
