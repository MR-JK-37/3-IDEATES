import Foundation
import EndpointSecurity
import os.log

/// Main Endpoint Security file monitor for macOS
/// Intercepts file open and process execution events
class FileMonitor {
    private var client: OpaquePointer?
    private let logger = os.log.init(subsystem: "com.cybershield.es", category: "FileMonitor")
    private let xpcConnection: XPCConnection
    
    init(xpcConnection: XPCConnection) {
        self.xpcConnection = xpcConnection
    }
    
    /// Start monitoring file system events
    func start() -> Bool {
        os_log("Starting Endpoint Security monitoring...", log: logger, type: .info)
        
        let result = es_new_client(&client) { [weak self] client, message in
            self?.handleEvent(message: message)
        }
        
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            os_log("Failed to create ES client: %{public}@", log: logger, type: .error, "\(result)")
            return false
        }
        
        // Subscribe to critical file and execution events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,      // File open/creation
            ES_EVENT_TYPE_AUTH_EXEC,      // Process execution
            ES_EVENT_TYPE_NOTIFY_WRITE,   // File write (informational)
            ES_EVENT_TYPE_NOTIFY_RENAME   // File rename (informational)
        ]
        
        let subscribeResult = es_subscribe(client!, events, UInt32(events.count))
        
        guard subscribeResult == ES_RETURN_SUCCESS else {
            os_log("Failed to subscribe to events", log: logger, type: .error)
            es_delete_client(client!)
            return false
        }
        
        os_log("✅ Endpoint Security monitoring started successfully", log: logger, type: .info)
        return true
    }
    
    /// Handle incoming security events from Endpoint Security framework
    private func handleEvent(message: UnsafePointer<es_message_t>) {
        let event = message.pointee
        
        switch event.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleFileOpen(message: message, event: event)
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleExecution(message: message, event: event)
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            handleFileWrite(event: event)
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleFileRename(event: event)
        default:
            break
        }
    }
    
    /// Handle file open authorization event
    /// - Parameters:
    ///   - message: The ES message containing event details
    ///   - event: The event structure
    private func handleFileOpen(message: UnsafePointer<es_message_t>, event: es_message_t) {
        guard let openEvent = event.event.open else { return }
        
        let filePtr = openEvent.file
        let filePath = String(cString: filePtr.pointee.path.data)
        let pid = audit_token_to_pid(event.process.pointee.audit_token)
        let uid = audit_token_to_uid(event.process.pointee.audit_token)
        
        os_log("📁 File open: %{public}@ (PID: %d, UID: %d)", 
               log: logger, type: .debug, filePath, pid, uid)
        
        // Skip system files and common benign operations
        if shouldSkipFile(filePath) {
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }
        
        // Send to Rust service for scanning
        let fileEvent = FileEvent(
            requestId: UInt64.random(in: 1...UInt64.max),
            processId: UInt32(pid),
            parentProcessId: 0, // Could be retrieved from process info
            timestamp: UInt64(Date().timeIntervalSince1970 * 1_000_000_000),
            eventType: .fileOpen,
            filePath: filePath,
            fileSize: getFileSize(filePath)
        )
        
        // Dispatch to Rust service via XPC
        let decision = xpcConnection.requestScan(fileEvent: fileEvent)
        
        switch decision {
        case .allow:
            os_log("✅ Allow: %{public}@", log: logger, type: .info, filePath)
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
        case .deny:
            os_log("🚫 Block: %{public}@", log: logger, type: .warning, filePath)
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_DENY, false)
        case .unknown:
            os_log("❓ Unknown: %{public}@", log: logger, type: .info, filePath)
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    
    /// Handle process execution authorization event
    private func handleExecution(message: UnsafePointer<es_message_t>, event: es_message_t) {
        guard let execEvent = event.event.exec else { return }
        
        let targetProcess = execEvent.target
        let executablePath = String(cString: targetProcess.pointee.executable.pointee.path.data)
        let pid = audit_token_to_pid(event.process.pointee.audit_token)
        
        os_log("🚀 Process exec: %{public}@ (PID: %d)", 
               log: logger, type: .debug, executablePath, pid)
        
        // Skip system processes
        if shouldSkipFile(executablePath) {
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }
        
        // Send to Rust service for scanning
        let fileEvent = FileEvent(
            requestId: UInt64.random(in: 1...UInt64.max),
            processId: UInt32(pid),
            parentProcessId: 0,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1_000_000_000),
            eventType: .processExec,
            filePath: executablePath,
            fileSize: getFileSize(executablePath)
        )
        
        let decision = xpcConnection.requestScan(fileEvent: fileEvent)
        
        switch decision {
        case .allow:
            os_log("✅ Allow exec: %{public}@", log: logger, type: .info, executablePath)
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
        case .deny:
            os_log("🚫 Block exec: %{public}@", log: logger, type: .warning, executablePath)
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_DENY, false)
        case .unknown:
            es_respond_auth_result(event.client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    
    /// Handle informational file write event (not authorization)
    private func handleFileWrite(event: es_message_t) {
        guard let writeEvent = event.event.write else { return }
        
        let filePath = String(cString: writeEvent.target.pointee.path.data)
        
        // Only log suspicious write patterns (excluded system directories)
        if !shouldSkipFile(filePath) {
            os_log("✏️ File write: %{public}@", log: logger, type: .debug, filePath)
        }
    }
    
    /// Handle informational file rename event (not authorization)
    private func handleFileRename(event: es_message_t) {
        guard let renameEvent = event.event.rename else { return }
        
        let oldPath = String(cString: renameEvent.source.pointee.path.data)
        let newPath = String(cString: renameEvent.destination.pointee.path.data)
        
        if !shouldSkipFile(oldPath) {
            os_log("📝 File rename: %{public}@ -> %{public}@", 
                   log: logger, type: .debug, oldPath, newPath)
        }
    }
    
    /// Determine if file should be skipped from scanning
    private func shouldSkipFile(_ path: String) -> Bool {
        let skipPrefixes = [
            "/System",
            "/Library",
            "/usr",
            "/var",
            "/tmp",
            "/dev",
            "/proc",
            "/.Trash",
            "/Applications/CyberShield"
        ]
        
        return skipPrefixes.contains { path.hasPrefix($0) }
    }
    
    /// Get file size in bytes
    private func getFileSize(_ path: String) -> UInt64 {
        let fileManager = FileManager.default
        do {
            let attributes = try fileManager.attributesOfItem(atPath: path)
            return (attributes[.size] as? UInt64) ?? 0
        } catch {
            return 0
        }
    }
    
    deinit {
        if let client = client {
            os_log("Shutting down Endpoint Security client", log: logger, type: .info)
            es_delete_client(client)
        }
    }
}

/// File event structure for communication with Rust service
struct FileEvent: Codable {
    let requestId: UInt64
    let processId: UInt32
    let parentProcessId: UInt32
    let timestamp: UInt64
    let eventType: EventType
    let filePath: String
    let fileSize: UInt64
    
    enum EventType: String, Codable {
        case fileOpen = "file_open"
        case fileWrite = "file_write"
        case fileRename = "file_rename"
        case processExec = "process_exec"
    }
}

/// Scan decision from Rust service
enum ScanDecision: String, Codable {
    case allow = "allow"
    case deny = "deny"
    case quarantine = "quarantine"
    case unknown = "unknown"
}
