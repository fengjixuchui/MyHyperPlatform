// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Declares interfaces to logging functions.

#pragma once

#include <fltKernel.h>

static const ULONG TAG = 'PpyH';/// A pool tag

extern "C"
{
    struct LogBufferInfo {
        volatile char *log_buffer_head;// A pointer to buffer currently used. It is either log_buffer1 or log_buffer2.
        volatile char *log_buffer_tail;// A pointer to where the next log should be written.

        char *log_buffer1;
        char *log_buffer2;

        SIZE_T log_max_usage;// Holds the biggest buffer usage to determine a necessary buffer size.

        HANDLE log_file_handle;
        KSPIN_LOCK spin_lock;
        ERESOURCE resource;
        bool resource_initialized;
        volatile bool buffer_flush_thread_should_be_alive;
        volatile bool buffer_flush_thread_started;
        HANDLE buffer_flush_thread_handle;
        wchar_t log_file_path[200];
    };

    /// Logs a message as respective severity
    /// @param format   A format string
    /// @return STATUS_SUCCESS on success
    ///
    /// Debug prints or buffers a log message with information about current execution context such as time, PID and TID as respective severity.
    /// Here are some guide lines to decide which level is appropriate:
    ///  @li DEBUG: info for only developers.
    ///  @li INFO: info for all users.
    ///  @li WARN: info may require some attention but does not prevent the program working properly.
    ///  @li ERROR: info about issues may stop the program working properly.
    ///
    /// A message should not exceed 512 bytes after all string construction is done; otherwise this macro fails to log and returns non STATUS_SUCCESS.
#define LOG_INFO(format, ...)   LogpPrint(kLogpLevelInfo, __FUNCTION__, (format), __VA_ARGS__)
#define LOG_WARN(format, ...)   LogpPrint(kLogpLevelWarn, __FUNCTION__, (format), __VA_ARGS__)
#define LOG_ERROR(format, ...)  LogpPrint(kLogpLevelError, __FUNCTION__, (format), __VA_ARGS__)

/// Buffers a message as respective severity
/// @param format   A format string
/// @return STATUS_SUCCESS on success
///
/// Buffers the log to buffer and neither calls DbgPrint() nor writes to a file.
/// It is strongly recommended to use it when a status of a system is not expectable in order to avoid system instability.
#define LOG_DEBUG_SAFE(format, ...) LogpPrint(kLogpLevelDebug | kLogpLevelOptSafe, __FUNCTION__, (format), __VA_ARGS__)

    static const auto kLogpLevelOptSafe = 0x1ul;/// Save this log to buffer and not try to write to a log file.

    static const auto kLogpLevelDebug = 0x10ul;  //!< Bit mask for DEBUG level logs
    static const auto kLogpLevelInfo = 0x20ul;   //!< Bit mask for INFO level logs
    static const auto kLogpLevelWarn = 0x40ul;   //!< Bit mask for WARN level logs
    static const auto kLogpLevelError = 0x80ul;  //!< Bit mask for ERROR level logs

    static const auto kLogPutLevelDebug = kLogpLevelError | kLogpLevelWarn | kLogpLevelInfo | kLogpLevelDebug;/// For LogInitialization(). Enables all levels of logs
    static const auto kLogPutLevelInfo = kLogpLevelError | kLogpLevelWarn | kLogpLevelInfo;/// For LogInitialization(). Enables ERROR, WARN and INFO levels of logs
    static const auto kLogPutLevelWarn = kLogpLevelError | kLogpLevelWarn;/// For LogInitialization(). Enables ERROR and WARN levels of logs
    static const auto kLogPutLevelError = kLogpLevelError;/// For LogInitialization(). Enables an ERROR level of logs
    static const auto kLogPutLevelDisable = 0x00ul;/// For LogInitialization(). Disables all levels of logs
    static const auto kLogOptDisableTime = 0x100ul;/// For LogInitialization(). Do not log a current time
    static const auto kLogOptDisableFunctionName = 0x200ul;/// For LogInitialization(). Do not log a current function name
    static const auto kLogOptDisableProcessorNumber = 0x400ul;/// For LogInitialization(). Do not log a current processor number
    static const auto kLogOptDisableDbgPrint = 0x800ul;/// For LogInitialization(). Do not log to debug buffer

    /// Initializes the log system.
    /// @param flag   A OR-ed flag to control a log level and options
    /// @param file_path  A log file path
    /// @return STATUS_SUCCESS on success, STATUS_REINITIALIZATION_NEEDED when re-initialization with LogRegisterReinitialization() is required, or else on failure.
    ///
    /// Allocates internal log buffers, initializes related resources, starts a log flush thread and creates a log file if requested.
    /// This function returns STATUS_REINITIALIZATION_NEEDED if a file-system is not initialized yet.
    /// In that case, a driver must call LogRegisterReinitialization() for completing initialization.
    ///
    /// \a flag is a OR-ed value of kLogPutLevel* and kLogOpt*. For example, kLogPutLevelDebug | kLogOptDisableFunctionName.
    NTSTATUS LogInitialization(_In_ ULONG flag, _In_opt_ const wchar_t *file_path);

    /// Registers re-initialization.
    /// @param driver_object  A driver object being loaded
    ///
    /// A driver must call this function, or call LogTermination() and return non STATUS_SUCCESS from DriverEntry() if LogInitialization() returned
    /// STATUS_REINITIALIZATION_NEEDED. If this function is called, DriverEntry() must return STATUS_SUCCESS.
    void LogRegisterReinitialization(_In_ PDRIVER_OBJECT driver_object);

    void LogTermination();/// Terminates the log system. Should be called from a DriverUnload routine.

    /// Logs a message; use HYPERPLATFORM_LOG_*() macros instead.
    /// @param level   Severity of a message
    /// @param function_name   A name of a function called this function
    /// @param format   A format string
    /// @return STATUS_SUCCESS on success
    /// @see LOG_DEBUG_SAFE
    NTSTATUS LogpPrint(_In_ ULONG level, _In_z_ const char *function_name, _In_z_ _Printf_format_string_ const char *format, ...);
}
