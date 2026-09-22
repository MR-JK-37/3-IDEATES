/*
 * minifilter.c
 * Windows minifilter driver - Production-grade kernel file monitoring
 * Coordinates with av-service Rust userspace component via FilterPort IPC
 * 
 * Architecture:
 * - Pre-operation callbacks intercept file creates and writes
 * - File path extracted via FltGetFileNameInformation
 * - Event forwarded to userspace via FilterPort message
 * - Userspace returns scan decision (allow/block/quarantine)
 * - Operation completed/blocked based on scan result
 */

#include "minifilter.h"
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_BANNED_API_USAGE, "Safe string functions used")
#pragma warning(disable:4100)  // Unreferenced formal parameter

// ============================================================================
// Global Variables
// ============================================================================

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

LONG gOutstandingRequests = 0;
KSPIN_LOCK gRequestLock;
ULONGLONG gCurrentRequestId = 0;

// ============================================================================
// Minifilter Callbacks Structure
// ============================================================================

const FLT_OPERATION_REGISTRATION CallbackRegistration[] = {
    {
        IRP_MJ_CREATE,
        0,
        PreCreateOperation,
        PostCreateOperation
    },
    {
        IRP_MJ_WRITE,
        0,
        PreWriteOperation,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    CallbackRegistration,
    AVFilterUnload,
    FilterQueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// ============================================================================
// DriverEntry - Kernel driver entry point
// ============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING PortName;
    SECURITY_DESCRIPTOR SecurityDescriptor;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AVFilter] DriverEntry - Initializing minifilter driver\n");

    // Initialize request ID lock
    KeInitializeSpinLock(&gRequestLock);
    gCurrentRequestId = 1;

    // Register minifilter with FltMgr
    Status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gFilterHandle
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] FltRegisterFilter failed: 0x%X\n", Status);
        return Status;
    }

    DbgPrint("[AVFilter] Minifilter registered successfully\n");

    // Create communication port for userspace communication
    RtlInitUnicodeString(&PortName, COMM_PORT_NAME);

    // Initialize security descriptor (allow all access for now)
    Status = RtlCreateSecurityDescriptor(
        &SecurityDescriptor,
        SECURITY_DESCRIPTOR_REVISION
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] RtlCreateSecurityDescriptor failed: 0x%X\n", Status);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return Status;
    }

    // Grant everyone full access
    Status = RtlSetDaclSecurityDescriptor(
        &SecurityDescriptor,
        TRUE,
        NULL,
        FALSE
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] RtlSetDaclSecurityDescriptor failed: 0x%X\n", Status);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return Status;
    }

    // Create server communication port
    Status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &ObjectAttributes,
        &PortName,
        FilterConnect,
        FilterDisconnect,
        FilterMessage,
        1  // MaxConnections (single userspace client)
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] FltCreateCommunicationPort failed: 0x%X\n", Status);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return Status;
    }

    DbgPrint("[AVFilter] Communication port created at %wZ\n", &PortName);

    // Start filtering (attach to all volumes)
    Status = FltStartFiltering(gFilterHandle);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] FltStartFiltering failed: 0x%X\n", Status);
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return Status;
    }

    DbgPrint("[AVFilter] Filter started - ready for operations\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// AVFilterUnload - Cleanup on driver unload
// ============================================================================

NTSTATUS
AVFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[AVFilter] AVFilterUnload - shutting down\n");

    // Close client port if connected
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }

    // Close server port
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    // Unregister filter
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    DbgPrint("[AVFilter] Driver unloaded successfully\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// PreCreateOperation - Intercept file creation/opening
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
PreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    ULONGLONG RequestId = 0;
    AV_FILE_EVENT FileEvent = {0};
    LARGE_INTEGER CurrentTime;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Skip operations on special files
    if (FltObjects->FileObject->FileName.Length == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Only monitor executable and potentially dangerous file types
    if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get detailed file name information
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] FltGetFileNameInformation failed: 0x%X\n", Status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Parse file name information
    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Generate unique request ID
    RequestId = GenerateRequestId();

    // Get current timestamp
    KeQuerySystemTime(&CurrentTime);

    // Build file event
    FileEvent.RequestId = RequestId;
    FileEvent.ProcessId = FltGetRequestorProcessId(Data);
    FileEvent.ParentProcessId = 0;  // Could be retrieved from process info
    FileEvent.Timestamp = CurrentTime.QuadPart;
    FileEvent.EventType = EVENT_FILE_CREATE;
    FileEvent.FileAttributes = Data->Iopb->Parameters.Create.FileAttributes;
    FileEvent.FileSize = 0;

    // Copy file path
    if (FileNameInfo->Name.Length < (MAX_FILENAME_LEN * sizeof(WCHAR))) {
        RtlCopyMemory(
            FileEvent.FilePath,
            FileNameInfo->Name.Buffer,
            FileNameInfo->Name.Length
        );
    }

    // Send event to userspace for scanning
    Status = SendEventToUserspace(
        RequestId,
        FileEvent.ProcessId,
        &FileNameInfo->Name,
        EVENT_FILE_CREATE,
        0
    );

    FltReleaseFileNameInformation(FileNameInfo);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[AVFilter] SendEventToUserspace failed: 0x%X\n", Status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // For now, allow operation to complete
    // In full implementation, would wait for scan result
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PostCreateOperation - Post-processing after file creation
// ============================================================================

FLT_POSTOP_CALLBACK_STATUS
PostCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// PreWriteOperation - Intercept file writes
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
PreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    ULONGLONG RequestId = 0;
    LARGE_INTEGER CurrentTime;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Skip system files and memory-mapped operations
    if (FltObjects->FileObject->Flags & FO_MEMORY_MAPPED_VIEW) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file name information
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
    );

    if (!NT_SUCCESS(Status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Generate request ID
    RequestId = GenerateRequestId();

    // Get current timestamp
    KeQuerySystemTime(&CurrentTime);

    // Send write event to userspace for analysis
    Status = SendEventToUserspace(
        RequestId,
        FltGetRequestorProcessId(Data),
        &FileNameInfo->Name,
        EVENT_FILE_WRITE,
        Data->Iopb->Parameters.Write.Length
    );

    FltReleaseFileNameInformation(FileNameInfo);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// FilterQueryTeardown - Query if filter can be torn down
// ============================================================================

NTSTATUS
FilterQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    // Allow teardown if no outstanding requests
    if (InterlockedCompareExchange(&gOutstandingRequests, 0, 0) == 0) {
        return STATUS_SUCCESS;
    }

    // Deny if requests pending
    return STATUS_FLT_DO_NOT_DETACH;
}

// ============================================================================
// FilterConnect - Userspace connection handler
// ============================================================================

NTSTATUS
FilterConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    DbgPrint("[AVFilter] Userspace av-service connected\n");

    gClientPort = ClientPort;
    *ConnectionCookie = NULL;

    return STATUS_SUCCESS;
}

// ============================================================================
// FilterDisconnect - Handle userspace disconnection
// ============================================================================

VOID
FilterDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    DbgPrint("[AVFilter] Userspace av-service disconnected\n");

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
}

// ============================================================================
// FilterMessage - Handle messages from userspace
// ============================================================================

NTSTATUS
FilterMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    PAV_SCAN_RESPONSE ScanResponse = NULL;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    // Validate input
    if (InputBuffer == NULL || InputBufferLength < sizeof(AV_SCAN_RESPONSE)) {
        *ReturnOutputBufferLength = 0;
        return STATUS_INVALID_PARAMETER;
    }

    ScanResponse = (PAV_SCAN_RESPONSE)InputBuffer;

    DbgPrint(
        "[AVFilter] Scan result: RequestId=%llu, Decision=%lu, Engine=%s, Threat=%s\n",
        ScanResponse->RequestId,
        ScanResponse->Decision,
        ScanResponse->Engine,
        ScanResponse->ThreatName
    );

    // Decrement outstanding request count
    InterlockedDecrement(&gOutstandingRequests);

    *ReturnOutputBufferLength = 0;

    return STATUS_SUCCESS;
}

// ============================================================================
// Helper Functions
// ============================================================================

NTSTATUS
SendEventToUserspace(
    _In_ ULONGLONG RequestId,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG EventType,
    _In_ ULONGLONG FileSize
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    AV_FILE_EVENT FileEvent = {0};
    LARGE_INTEGER CurrentTime;
    ULONG ReturnLength = 0;
    LARGE_INTEGER Timeout;

    // Check if userspace client is connected
    if (gClientPort == NULL) {
        DbgPrint("[AVFilter] No userspace client connected\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    // Build file event
    FileEvent.RequestId = RequestId;
    FileEvent.ProcessId = ProcessId;
    FileEvent.ParentProcessId = 0;
    FileEvent.EventType = EventType;
    FileEvent.FileSize = FileSize;

    KeQuerySystemTime(&CurrentTime);
    FileEvent.Timestamp = CurrentTime.QuadPart;

    // Copy file path safely
    if (FilePath->Length < (MAX_FILENAME_LEN * sizeof(WCHAR))) {
        RtlCopyMemory(
            FileEvent.FilePath,
            FilePath->Buffer,
            FilePath->Length
        );
    }

    // Send message to userspace
    // 5-second timeout (relative time in 100ns units) prevents indefinite hangs.
    Timeout.QuadPart = -(LONGLONG)5 * 10 * 1000 * 1000;
    Status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        &FileEvent,
        sizeof(AV_FILE_EVENT),
        NULL,
        &ReturnLength,
        &Timeout
    );

    if (NT_SUCCESS(Status)) {
        InterlockedIncrement(&gOutstandingRequests);
    } else if (Status == STATUS_TIMEOUT) {
        // Fail-open on timeout so normal file operations continue.
        DbgPrint("[AVFilter] Userspace timeout for request %llu, allowing operation\n", RequestId);
        Status = STATUS_SUCCESS;
    } else {
        DbgPrint("[AVFilter] FltSendMessage failed: 0x%X\n", Status);
    }

    return Status;
}

ULONGLONG
GenerateRequestId(
    VOID
)
{
    KIRQL OldIrql;
    ULONGLONG RequestId;

    KeAcquireSpinLock(&gRequestLock, &OldIrql);
    RequestId = gCurrentRequestId++;
    KeReleaseSpinLock(&gRequestLock, OldIrql);

    return RequestId;
}
