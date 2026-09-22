/*
 * minifilter.h
 * Windows minifilter driver - Header definitions
 * Production-grade kernel-level file system monitoring
 * Synchronizes with Rust av-service via IOCTL/FilterPort communication
 */

#ifndef __MINIFILTER_H__
#define __MINIFILTER_H__

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntdef.h>
#include <ntstatus.h>

#pragma warning(disable:4201)

// ============================================================================
// Event Type Definitions (match eBPF events for consistency)
// ============================================================================
#define EVENT_FILE_CREATE   0x01
#define EVENT_FILE_WRITE    0x04
#define EVENT_FILE_DELETE   0x02
#define EVENT_FILE_RENAME   0x08
#define EVENT_FILE_EXECUTE  0x10

// ============================================================================
// Scan Decision Codes
// ============================================================================
#define AV_SCAN_ALLOW       0
#define AV_SCAN_BLOCK       1
#define AV_SCAN_QUARANTINE  2
#define AV_SCAN_UNKNOWN     3

// ============================================================================
// IPC Configuration
// ============================================================================
#define COMM_PORT_NAME      L"\\AVFilterPort"
#define MAX_FILENAME_LEN    512
#define MAX_THREAT_NAME_LEN 256
#define MAX_ENGINE_NAME_LEN 64

// ============================================================================
// IOCTL Codes (matching av-service expectations)
// ============================================================================
#define FILE_DEVICE_ANTIVIRUS 0x8000

#define IOCTL_GET_FILE_EVENT \
    CTL_CODE(FILE_DEVICE_ANTIVIRUS, 0x800, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

#define IOCTL_SEND_SCAN_RESULT \
    CTL_CODE(FILE_DEVICE_ANTIVIRUS, 0x801, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)

#define IOCTL_GET_DRIVER_VERSION \
    CTL_CODE(FILE_DEVICE_ANTIVIRUS, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// Data Structures (shared between kernel and userspace)
// ============================================================================

#pragma pack(push, 1)

/*
 * File event from kernel to userspace
 * Sent via FilterPort message or IOCTL
 */
typedef struct _AV_FILE_EVENT {
    ULONGLONG RequestId;          // Unique ID for request/response correlation
    ULONG ProcessId;              // Process performing the operation
    ULONG ParentProcessId;        // Parent process ID
    ULONGLONG Timestamp;          // Event timestamp (100-ns intervals since 1/1/1601)
    ULONG EventType;              // EVENT_FILE_CREATE, EVENT_FILE_WRITE, etc.
    ULONG FileAttributes;         // File attributes
    ULONGLONG FileSize;           // File size (at event time)
    WCHAR FilePath[MAX_FILENAME_LEN];  // Full file path
} AV_FILE_EVENT, * PAV_FILE_EVENT;

/*
 * Scan response from userspace to kernel
 * Received via FilterPort message or IOCTL
 */
typedef struct _AV_SCAN_RESPONSE {
    ULONGLONG RequestId;          // Must match corresponding REQUEST_ID
    ULONG Decision;               // AV_SCAN_ALLOW, AV_SCAN_BLOCK, AV_SCAN_QUARANTINE
    ULONG ThreatLevel;            // 0=clean, 1-3=suspicious, 4-5=malicious
    CHAR Engine[MAX_ENGINE_NAME_LEN];     // Scanner engine (ClamAV, YARA, VT, etc.)
    CHAR ThreatName[MAX_THREAT_NAME_LEN]; // Threat name/signature
    NTSTATUS Status;              // Operation status
} AV_SCAN_RESPONSE, * PAV_SCAN_RESPONSE;

#pragma pack(pop)

// ============================================================================
// Global State
// ============================================================================

extern PFLT_FILTER gFilterHandle;
extern PFLT_PORT gServerPort;
extern PFLT_PORT gClientPort;

extern LONG gOutstandingRequests;   // Number of pending scan requests
extern KSPIN_LOCK gRequestLock;
extern ULONGLONG gCurrentRequestId;

// ============================================================================
// Function Prototypes
// ============================================================================

// Driver lifecycle
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
AVFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Communication port callbacks
NTSTATUS
FilterConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID
FilterDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
FilterMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

// File system operation callbacks
FLT_PREOP_CALLBACK_STATUS
PreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Teardown callback
NTSTATUS
FilterQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// Helper functions
NTSTATUS
GetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
);

NTSTATUS
SendEventToUserspace(
    _In_ ULONGLONG RequestId,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG EventType,
    _In_ ULONGLONG FileSize
);

ULONGLONG
GenerateRequestId(
    VOID
);

#endif /* __MINIFILTER_H__ */
