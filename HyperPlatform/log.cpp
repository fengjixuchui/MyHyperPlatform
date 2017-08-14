// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements logging functions.

#include "log.h"
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

#pragma prefast(disable : 30030)// See common.h for details

extern "C"
{
// A size for log buffer in NonPagedPoolNx. Two buffers are allocated with this size.
// Exceeded logs are ignored silently. Make it bigger if a buffered log size often reach this size.
static const auto kLogpBufferSizeInPages = 16ul;

static const auto kLogpBufferSize = PAGE_SIZE * kLogpBufferSizeInPages;// An actual log buffer size in bytes.
static const auto kLogpBufferUsableSize = kLogpBufferSize - 1;// A size that is usable for logging. Minus one because the last byte is kept for \0.
static const auto kLogpLogFlushIntervalMsec = 50;// An interval to flush buffered log entries into a log file.

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogpInitializeBufferInfo(_In_ const wchar_t *log_file_path, _Inout_ LogBufferInfo *info);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogpInitializeLogFile(_Inout_ LogBufferInfo *info);
static DRIVER_REINITIALIZE LogpReinitializationRoutine;
_IRQL_requires_max_(PASSIVE_LEVEL) static void LogpFinalizeBufferInfo(_In_ LogBufferInfo *info);
static NTSTATUS LogpMakePrefix(_In_ ULONG level, _In_z_ const char *function_name, _In_z_ const char *log_message, _Out_ char *log_buffer, _In_ SIZE_T log_buffer_length);
static const char *LogpFindBaseFunctionName(_In_z_ const char *function_name);
static NTSTATUS LogpPut(_In_z_ char *message, _In_ ULONG attribute);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogpFlushLogBuffer(_Inout_ LogBufferInfo *info);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogpWriteMessageToFile(_In_z_ const char *message, _In_ const LogBufferInfo &info);
static NTSTATUS LogpBufferMessage(_In_z_ const char *message, _Inout_ LogBufferInfo *info);
static void LogpDoDbgPrint(_In_z_ char *message);
static bool LogpIsLogFileEnabled(_In_ const LogBufferInfo &info);
static bool LogpIsLogFileActivated(_In_ const LogBufferInfo &info);
static bool LogpIsLogNeeded(_In_ ULONG level);
static bool LogpIsDbgPrintNeeded();
static KSTART_ROUTINE LogpBufferFlushThreadRoutine;
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogpSleep(_In_ LONG millisecond);
static void LogpSetPrintedBit(_In_z_ char *message, _In_ bool on);
static bool LogpIsPrinted(_In_z_ char *message);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, LogInitialization)
#pragma alloc_text(INIT, LogpInitializeBufferInfo)
#pragma alloc_text(PAGE, LogpInitializeLogFile)
#pragma alloc_text(INIT, LogRegisterReinitialization)
#pragma alloc_text(PAGE, LogpReinitializationRoutine)
#pragma alloc_text(PAGE, LogTermination)
#pragma alloc_text(PAGE, LogpFinalizeBufferInfo)
#pragma alloc_text(PAGE, LogpBufferFlushThreadRoutine)
#pragma alloc_text(PAGE, LogpSleep)
#endif

static auto g_logp_debug_flag = kLogPutLevelDisable;
static LogBufferInfo g_logp_log_buffer_info = {};


_Use_decl_annotations_ NTSTATUS LogInitialization(ULONG flag, const wchar_t *log_file_path)
{
    PAGED_CODE();

    g_logp_debug_flag = flag;

    bool need_reinitialization = false;
    if (log_file_path)// Initialize a log file if a log file path is specified.
    {
        NTSTATUS status = LogpInitializeBufferInfo(log_file_path, &g_logp_log_buffer_info);
        if (status == STATUS_REINITIALIZATION_NEEDED) {
            need_reinitialization = true;
        } else if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return (need_reinitialization ? STATUS_REINITIALIZATION_NEEDED : STATUS_SUCCESS);
}


_Use_decl_annotations_ static NTSTATUS LogpInitializeBufferInfo(const wchar_t *log_file_path, LogBufferInfo *info)
// Initialize a log file related code such as a flushing thread.
{
    PAGED_CODE();
    NT_ASSERT(log_file_path);
    NT_ASSERT(info);

    KeInitializeSpinLock(&info->spin_lock);

    NTSTATUS status = RtlStringCchCopyW(info->log_file_path, RTL_NUMBER_OF_FIELD(LogBufferInfo, log_file_path), log_file_path);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ExInitializeResourceLite(&info->resource);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    info->resource_initialized = true;
    
    info->log_buffer1 = reinterpret_cast<char *>(ExAllocatePoolWithTag(NonPagedPoolNx, kLogpBufferSize, TAG));// Allocate two log buffers on NonPagedPoolNx.
    ASSERT(info->log_buffer1);

    info->log_buffer2 = reinterpret_cast<char *>(ExAllocatePoolWithTag(NonPagedPoolNx, kLogpBufferSize, TAG));
    ASSERT(info->log_buffer2);

    // Initialize these buffers
    RtlFillMemory(info->log_buffer1, kLogpBufferSize, 0xff);  // for diagnostic
    info->log_buffer1[0] = '\0';
    info->log_buffer1[kLogpBufferSize - 1] = '\0';  // at the end

    RtlFillMemory(info->log_buffer2, kLogpBufferSize, 0xff);  // for diagnostic
    info->log_buffer2[0] = '\0';
    info->log_buffer2[kLogpBufferSize - 1] = '\0';  // at the end

    // Buffer should be used is log_buffer1, and location should be written logs is the head of the buffer.
    info->log_buffer_head = info->log_buffer1;
    info->log_buffer_tail = info->log_buffer1;

    status = LogpInitializeLogFile(info);
    if (status == STATUS_OBJECT_PATH_NOT_FOUND) {
        LOG_INFO("The log file needs to be activated later.");
        status = STATUS_REINITIALIZATION_NEEDED;
    } else if (!NT_SUCCESS(status)) {
        LogpFinalizeBufferInfo(info);
    }

    return status;
}


_Use_decl_annotations_ static NTSTATUS LogpInitializeLogFile(LogBufferInfo *info) 
// Initializes a log file and starts a log buffer thread.
{
    PAGED_CODE();

    if (info->log_file_handle) {
        return STATUS_SUCCESS;
    }

    // Initialize a log file
    UNICODE_STRING log_file_path_u = {};
    RtlInitUnicodeString(&log_file_path_u, info->log_file_path);
    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &log_file_path_u, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io_status = {};
    NTSTATUS status = ZwCreateFile(
        &info->log_file_handle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &oa,
        &io_status,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr,
        0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Initialize a log buffer flush thread.
    info->buffer_flush_thread_should_be_alive = true;
    status = PsCreateSystemThread(&info->buffer_flush_thread_handle, GENERIC_ALL, nullptr, nullptr, nullptr, LogpBufferFlushThreadRoutine, info);
    if (!NT_SUCCESS(status)) {
        ZwClose(info->log_file_handle);
        info->log_file_handle = nullptr;
        info->buffer_flush_thread_should_be_alive = false;
        return status;
    }

    // Wait until the thread has started
    while (!info->buffer_flush_thread_started)
    {
        LogpSleep(100);
    }

    return status;
}


_Use_decl_annotations_ void LogRegisterReinitialization(PDRIVER_OBJECT driver_object)
// Registers LogpReinitializationRoutine() for re-initialization.
{
    PAGED_CODE();
    IoRegisterBootDriverReinitialization(driver_object, LogpReinitializationRoutine, &g_logp_log_buffer_info);
    LOG_INFO("The log file will be activated later.");
}


_Use_decl_annotations_ VOID static LogpReinitializationRoutine(_DRIVER_OBJECT *driver_object, PVOID context, ULONG count)
// Initializes a log file at the re-initialization phase.
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(count);
    NT_ASSERT(context);

    LogBufferInfo * info = reinterpret_cast<LogBufferInfo *>(context);
    NTSTATUS status = LogpInitializeLogFile(info);
    NT_ASSERT(NT_SUCCESS(status));
    if (NT_SUCCESS(status)) {
        LOG_INFO("The log file has been activated.");
    }
}


_Use_decl_annotations_ void LogTermination()
// Terminates the log functions.
{
    PAGED_CODE();

    g_logp_debug_flag = kLogPutLevelDisable;
    LogpFinalizeBufferInfo(&g_logp_log_buffer_info);
}


_Use_decl_annotations_ static void LogpFinalizeBufferInfo(LogBufferInfo *info)
// Terminates a log file related code.
{
    PAGED_CODE();
    NT_ASSERT(info);

    // Closing the log buffer flush thread.
    if (info->buffer_flush_thread_handle) {
        info->buffer_flush_thread_should_be_alive = false;
        NTSTATUS status = ZwWaitForSingleObject(info->buffer_flush_thread_handle, FALSE, nullptr);
        ASSERT(NT_SUCCESS(status));
        ZwClose(info->buffer_flush_thread_handle);
        info->buffer_flush_thread_handle = nullptr;
    }

    // Cleaning up other things.
    if (info->log_file_handle) {
        ZwClose(info->log_file_handle);
        info->log_file_handle = nullptr;
    }
    if (info->log_buffer2) {
        ExFreePoolWithTag(info->log_buffer2, TAG);
        info->log_buffer2 = nullptr;
    }
    if (info->log_buffer1) {
        ExFreePoolWithTag(info->log_buffer1, TAG);
        info->log_buffer1 = nullptr;
    }

    if (info->resource_initialized) {
        ExDeleteResourceLite(&info->resource);
        info->resource_initialized = false;
    }
}


_Use_decl_annotations_ NTSTATUS LogpPrint(ULONG level, const char *function_name, const char *format, ...)
// Actual implementation of logging API.
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!LogpIsLogNeeded(level)) {
        return status;
    }

    va_list args;
    va_start(args, format);
    char log_message[412];
    status = RtlStringCchVPrintfA(log_message, RTL_NUMBER_OF(log_message), format, args);
    va_end(args);
    if (!NT_SUCCESS(status)) {
        __debugbreak();
        return status;
    }
    if (log_message[0] == '\0') {
        __debugbreak();
        return STATUS_INVALID_PARAMETER;
    }

    ULONG pure_level = level & 0xf0;
    ULONG attribute = level & 0x0f;

    // A single entry of log should not exceed 512 bytes. See Reading and Filtering Debugging Messages in MSDN for details.
    char message[512];
    static_assert(RTL_NUMBER_OF(message) <= 512, "One log message should not exceed 512 bytes.");
    status = LogpMakePrefix(pure_level, function_name, log_message, message, RTL_NUMBER_OF(message));
    if (!NT_SUCCESS(status)) {
        __debugbreak();
        return status;
    }

    status = LogpPut(message, attribute);
    ASSERT(NT_SUCCESS(status));
    return status;
}


_Use_decl_annotations_ static NTSTATUS LogpMakePrefix(ULONG level, const char *function_name, const char *log_message, char *log_buffer, SIZE_T log_buffer_length)
// Concatenates meta information such as the current time and a process ID to user given log message.
{
    char const *level_string = nullptr;
    switch (level)
    {
    case kLogpLevelDebug:
        level_string = "DBG\t";
        break;
    case kLogpLevelInfo:
        level_string = "INF\t";
        break;
    case kLogpLevelWarn:
        level_string = "WRN\t";
        break;
    case kLogpLevelError:
        level_string = "ERR\t";
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;

    char time_buffer[20] = {};
    if ((g_logp_debug_flag & kLogOptDisableTime) == 0) {
        TIME_FIELDS time_fields;
        LARGE_INTEGER system_time, local_time;

        KeQuerySystemTime(&system_time);// Want the current time.
        ExSystemTimeToLocalTime(&system_time, &local_time);
        RtlTimeToTimeFields(&local_time, &time_fields);
        status = RtlStringCchPrintfA(time_buffer, RTL_NUMBER_OF(time_buffer), "%02u:%02u:%02u.%03u\t", time_fields.Hour, time_fields.Minute, time_fields.Second, time_fields.Milliseconds);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    
    char function_name_buffer[50] = {};// Want the function name
    if ((g_logp_debug_flag & kLogOptDisableFunctionName) == 0) {
        const char * base_function_name = LogpFindBaseFunctionName(function_name);
        status = RtlStringCchPrintfA(function_name_buffer, RTL_NUMBER_OF(function_name_buffer), "%-40s\t", base_function_name);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    
    char processro_number[10] = {};// Want the processor number
    if ((g_logp_debug_flag & kLogOptDisableProcessorNumber) == 0) {
        status = RtlStringCchPrintfA(processro_number, RTL_NUMBER_OF(processro_number), "#%lu\t", KeGetCurrentProcessorNumberEx(nullptr));
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    // It uses PsGetProcessId(PsGetCurrentProcess()) instead of PsGetCurrentThreadProcessId() because the later sometimes returns unwanted value, for example:
    //  PID == 4 but its image name != ntoskrnl.exe
    // The author is guessing that it is related to attaching processes but not quite sure. The former way works as expected.
    status = RtlStringCchPrintfA(log_buffer, log_buffer_length, "%s%s%s%5Iu\t%5Iu\t%-15s\t%s%s\r\n",
        time_buffer,
        level_string,
        processro_number,
        reinterpret_cast<ULONG_PTR>(PsGetProcessId(PsGetCurrentProcess())),
        reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()),
        PsGetProcessImageFileName(PsGetCurrentProcess()),
        function_name_buffer,
        log_message);
    return status;
}


_Use_decl_annotations_ static const char *LogpFindBaseFunctionName(const char *function_name)
// Returns the function's base name, for example,
// NamespaceName::ClassName::MethodName will be returned as MethodName.
{
    if (!function_name) {
        return nullptr;
    }

    const char * ptr = function_name;
    const char * name = function_name;

    while (*(ptr++))
    {
        if (*ptr == ':') {
            name = ptr + 1;
        }
    }

    return name;
}


_Use_decl_annotations_ static NTSTATUS LogpPut(char *message, ULONG attribute)
// Logs the entry according to attribute and the thread condition.
{
    NTSTATUS status = STATUS_SUCCESS;

    bool do_DbgPrint = ((attribute & kLogpLevelOptSafe) == 0 && KeGetCurrentIrql() < CLOCK_LEVEL);

    // Log the entry to a file or buffer.
    LogBufferInfo &info = g_logp_log_buffer_info;
    if (LogpIsLogFileEnabled(info)) {// Can it log it to a file now?
        if (((attribute & kLogpLevelOptSafe) == 0) && KeGetCurrentIrql() == PASSIVE_LEVEL && LogpIsLogFileActivated(info)) {
#pragma warning(push)
#pragma warning(disable : 28123)
            if (!KeAreAllApcsDisabled()) {// Yes, it can. Do it.
                LogpFlushLogBuffer(&info);
                status = LogpWriteMessageToFile(message, info);
            }
#pragma warning(pop)
        } else {// No, it cannot. Set the printed bit if needed, and then buffer it.
            if (do_DbgPrint) {
                LogpSetPrintedBit(message, true);
            }
            status = LogpBufferMessage(message, &info);
            LogpSetPrintedBit(message, false);
        }
    }
    
    if (do_DbgPrint) {// Can it safely be printed?
        LogpDoDbgPrint(message);
    }

    return status;
}


_Use_decl_annotations_ static NTSTATUS LogpFlushLogBuffer(LogBufferInfo *info)
// Switches the current log buffer, saves the contents of old buffer to the log file, and prints them out as necessary.
// This function does not flush the log file, so code should call LogpWriteMessageToFile() or ZwFlushBuffersFile() later.
{
    NT_ASSERT(info);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    NTSTATUS status = STATUS_SUCCESS;
    
    ExEnterCriticalRegionAndAcquireResourceExclusive(&info->resource);// Enter a critical section and acquire a reader lock for info in order to write a log file safely.
    
    KLOCK_QUEUE_HANDLE lock_handle = {};
    KeAcquireInStackQueuedSpinLock(&info->spin_lock, &lock_handle);// Acquire a spin lock for info.log_buffer(s) in order to switch its head safely.
    char * old_log_buffer = const_cast<char *>(info->log_buffer_head);
    if (old_log_buffer[0]) {
        info->log_buffer_head = (old_log_buffer == info->log_buffer1) ? info->log_buffer2 : info->log_buffer1;
        info->log_buffer_head[0] = '\0';
        info->log_buffer_tail = info->log_buffer_head;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    // Write all log entries in old log buffer.
    IO_STATUS_BLOCK io_status = {};
    for (char * current_log_entry = old_log_buffer; current_log_entry[0]; )
    {
        // Check the printed bit and clear it
        bool printed_out = LogpIsPrinted(current_log_entry);
        LogpSetPrintedBit(current_log_entry, false);

        size_t current_log_entry_length = strlen(current_log_entry);
        status = ZwWriteFile(info->log_file_handle, nullptr, nullptr, nullptr, &io_status, current_log_entry, static_cast<ULONG>(current_log_entry_length), nullptr, nullptr);
        ASSERT (NT_SUCCESS(status));
        
        if (!printed_out) {// Print it out if requested and the message is not already printed out
            LogpDoDbgPrint(current_log_entry);
        }

        current_log_entry += current_log_entry_length + 1;
    }
    old_log_buffer[0] = '\0';

    ExReleaseResourceAndLeaveCriticalRegion(&info->resource);
    return status;
}


_Use_decl_annotations_ static NTSTATUS LogpWriteMessageToFile(const char *message, const LogBufferInfo &info)
// Logs the current log entry to and flush the log file.
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    IO_STATUS_BLOCK io_status = {};
    NTSTATUS status = ZwWriteFile(info.log_file_handle, nullptr, nullptr, nullptr, &io_status, const_cast<char *>(message), static_cast<ULONG>(strlen(message)), nullptr, nullptr);
    ASSERT (NT_SUCCESS(status));
    status = ZwFlushBuffersFile(info.log_file_handle, &io_status);
    return status;
}


_Use_decl_annotations_ static NTSTATUS LogpBufferMessage(const char *message, LogBufferInfo *info) 
// Buffer the log entry to the log buffer.
{
    NT_ASSERT(info);

    // Acquire a spin lock to add the log safely.
    KLOCK_QUEUE_HANDLE lock_handle = {};
    KIRQL old_irql = KeGetCurrentIrql();
    if (old_irql < DISPATCH_LEVEL) {
        KeAcquireInStackQueuedSpinLock(&info->spin_lock, &lock_handle);
    } else {
        KeAcquireInStackQueuedSpinLockAtDpcLevel(&info->spin_lock, &lock_handle);
    }
    NT_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

    // Copy the current log to the buffer.
    SIZE_T used_buffer_size = info->log_buffer_tail - info->log_buffer_head;
    NTSTATUS status = RtlStringCchCopyA(const_cast<char *>(info->log_buffer_tail), kLogpBufferUsableSize - used_buffer_size, message);
    if (NT_SUCCESS(status)) {// Update info.log_max_usage if necessary.
        SIZE_T message_length = strlen(message) + 1;
        info->log_buffer_tail += message_length;
        used_buffer_size += message_length;
        if (used_buffer_size > info->log_max_usage) {
            info->log_max_usage = used_buffer_size;  // Update
        }
    } else {
        info->log_max_usage = kLogpBufferSize;  // Indicates overflow
    }
    *info->log_buffer_tail = '\0';

    if (old_irql < DISPATCH_LEVEL) {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
    } else {
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
    }

    return status;
}


_Use_decl_annotations_ static void LogpDoDbgPrint(char *message)
// Calls DbgPrintEx() while converting \r\n to \n\0
{
    if (!LogpIsDbgPrintNeeded()) {
        return;
    }
    SIZE_T location_of_cr = strlen(message) - 2;
    message[location_of_cr] = '\n';
    message[location_of_cr + 1] = '\0';
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", message);
}


_Use_decl_annotations_ static bool LogpIsLogFileEnabled(const LogBufferInfo &info) 
// Returns true when a log file is enabled.
{
    if (info.log_buffer1) {
        NT_ASSERT(info.log_buffer2);
        NT_ASSERT(info.log_buffer_head);
        NT_ASSERT(info.log_buffer_tail);
        return true;
    }

    NT_ASSERT(!info.log_buffer2);
    NT_ASSERT(!info.log_buffer_head);
    NT_ASSERT(!info.log_buffer_tail);
    return false;
}


_Use_decl_annotations_ static bool LogpIsLogFileActivated(const LogBufferInfo &info)
// Returns true when a log file is opened.
{
    if (info.buffer_flush_thread_should_be_alive) {
        NT_ASSERT(info.buffer_flush_thread_handle);
        NT_ASSERT(info.log_file_handle);
        return true;
    }

    NT_ASSERT(!info.buffer_flush_thread_handle);
    NT_ASSERT(!info.log_file_handle);
    return false;
}


_Use_decl_annotations_ static bool LogpIsLogNeeded(ULONG level)
// Returns true when logging is necessary according to the log's severity and a set log level.
{
    return !!(g_logp_debug_flag & level);
}


static bool LogpIsDbgPrintNeeded()
// Returns true when DbgPrint is requested
{
    return (g_logp_debug_flag & kLogOptDisableDbgPrint) == 0;
}


_Use_decl_annotations_ static VOID LogpBufferFlushThreadRoutine(void *start_context)
// A thread runs as long as info.buffer_flush_thread_should_be_alive is true and flushes a log buffer to a log file every kLogpLogFlushIntervalMsec msec.
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    LogBufferInfo * info = reinterpret_cast<LogBufferInfo *>(start_context);
    info->buffer_flush_thread_started = true;

    while (info->buffer_flush_thread_should_be_alive)
    {
        NT_ASSERT(LogpIsLogFileActivated(*info));
        if (info->log_buffer_head[0]) {
            NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
            NT_ASSERT(!KeAreAllApcsDisabled());
            status = LogpFlushLogBuffer(info);
            // Do not flush the file for overall performance. Even a case of bug check, we should be able to recover logs by looking at both log buffers.
        }
        LogpSleep(kLogpLogFlushIntervalMsec);
    }

    PsTerminateSystemThread(status);
}


_Use_decl_annotations_ static NTSTATUS LogpSleep(LONG millisecond)
// Sleep the current thread's execution for milliseconds.
{
    PAGED_CODE();

    LARGE_INTEGER interval = {};
    interval.QuadPart = -(10000ll * millisecond);  // msec
    return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


_Use_decl_annotations_ static void LogpSetPrintedBit(char *message, bool on)
// Marks the message as it is already printed out, or clears the printed bit and restores it to the original
{
    if (on) {
        message[0] |= 0x80;
    } else {
        message[0] &= 0x7f;
    }
}


_Use_decl_annotations_ static bool LogpIsPrinted(char *message)
// Tests if the printed bit is on
{
    return (message[0] & 0x80) != 0;
}

}  // extern "C"
