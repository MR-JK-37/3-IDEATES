import Foundation
import EndpointSecurity
import NetworkExtension

/// macOS Security Engine - Endpoint Security Framework Integration
/// Monitors file/process/network activity on macOS 11+

class MacOSSecurityEngine {
    static let shared = MacOSSecurityEngine()
    
    private var esClient: es_client_t?
    private var isMonitoring = false
    private var threatCallback: ((Threat) -> Void)?
    
    // MARK: - Initialization
    
    func startMonitoring(callback: @escaping (Threat) -> Void) {
        guard !isMonitoring else { return }
        
        threatCallback = callback
        
        // Create Endpoint Security client
        let handler: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<es_message_t>) -> Void = { context, message in
            let engine = Unmanaged<MacOSSecurityEngine>.fromOpaque(context!).takeUnretainedValue()
            engine.handleESMessage(message)
        }
        
        let result = es_new_client(&esClient, handler, UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()))
        
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            print("[ES] Failed to create client")
            return
        }
        
        subscribeToEvents()
        isMonitoring = true
        print("[ES] Monitoring started on macOS")
    }
    
    func stopMonitoring() {
        guard isMonitoring, let client = esClient else { return }
        es_delete_client(client)
        isMonitoring = false
        print("[ES] Monitoring stopped")
    }
    
    // MARK: - Event Subscription
    
    private func subscribeToEvents() {
        guard let client = esClient else { return }
        
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_AUTH_KEXT_LOAD,
        ]
        
        for event in events {
            var mutableEvent = event
            es_subscribe(client, &mutableEvent, 1)
        }
    }
    
    // MARK: - Event Handling
    
    private func handleESMessage(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleProcessExecution(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleFileOpen(message)
        case ES_EVENT_TYPE_AUTH_CREATE:
            handleFileCreate(message)
        case ES_EVENT_TYPE_AUTH_RENAME:
            handleFileRename(message)
        case ES_EVENT_TYPE_AUTH_KEXT_LOAD:
            handleKernelExtensionLoad(message)
        default:
            break
        }
    }
    
    private func handleProcessExecution(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.exec.pointee
        
        let processPath = String(cString: event.executable.pointee.path.data)
        let pid = event.executable.pointee.stat.st_ino
        
        // Verify code signature
        let isSignedByApple = verifyCodeSignature(processPath: processPath)
        let isNotarized = checkNotarization(processPath: processPath)
        
        if !isSignedByApple {
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .process,
                severity: .high,
                source: processPath,
                details: "Unsigned/invalid code signature: \(processPath) (Notarized: \(isNotarized))"
            )
            threatCallback?(threat)
        }
        
        // Check for process injection indicators
        if detectProcessInjection(pid: pid) {
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .process,
                severity: .critical,
                source: processPath,
                details: "Process injection detected in: \(processPath)"
            )
            threatCallback?(threat)
        }
    }
    
    private func handleFileOpen(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.open.pointee
        
        let filePath = String(cString: event.file.pointee.path.data)
        let processPath = String(cString: event.executable.pointee.path.data)
        
        // Check for sensitive file access
        let sensitivePatterns = [
            "/.ssh/",
            "/.gnupg/",
            "/Library/Keychains/",
            "/var/db/sudo",
            "/.aws/",
            "/.kube/"
        ]
        
        if sensitivePatterns.contains(where: { filePath.contains($0) }) {
            // Verify if process is authorized to access this
            if !isProcessAuthorizedForPath(processPath, filePath) {
                let threat = Threat(
                    id: UUID().uuidString,
                    timestamp: Date(),
                    type: .file,
                    severity: .high,
                    source: processPath,
                    details: "Unauthorized access to sensitive file: \(filePath)"
                )
                threatCallback?(threat)
            }
        }
    }
    
    private func handleFileCreate(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.create.pointee
        
        let filePath = String(cString: event.destination_type.dir.pointee.path.data)
        let processPath = String(cString: event.executable.pointee.path.data)
        
        // Check for suspicious file creation
        let suspiciousExtensions = [".app", ".deb", ".pkg", ".sh", ".bin"]
        let fileExt = URL(fileURLWithPath: filePath).pathExtension
        
        if suspiciousExtensions.contains("." + fileExt) && !isSystemPath(filePath) {
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .file,
                severity: .medium,
                source: processPath,
                details: "Suspicious file created: \(filePath)"
            )
            threatCallback?(threat)
        }
    }
    
    private func handleFileRename(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.rename.pointee
        
        let oldPath = String(cString: event.source.pointee.path.data)
        let newName = String(cString: event.destination_type.existing_file.pointee.path.data)
        
        // Detect ransomware file extension changes
        let ransomwareExtensions = [".locked", ".encrypted", ".cryptowall", ".cerber", ".locky"]
        let newExt = URL(fileURLWithPath: newName).pathExtension
        
        if ransomwareExtensions.contains("." + newExt) {
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .file,
                severity: .critical,
                source: String(cString: event.executable.pointee.path.data),
                details: "Ransomware extension detected: \(oldPath) → \(newName)"
            )
            threatCallback?(threat)
        }
    }
    
    private func handleKernelExtensionLoad(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.kext_load.pointee
        
        let kextPath = String(cString: event.identifier.data)
        
        // Only Apple-signed kexts should load
        let threat = Threat(
            id: UUID().uuidString,
            timestamp: Date(),
            type: .system,
            severity: .critical,
            source: kextPath,
            details: "Kernel extension load attempt: \(kextPath)"
        )
        threatCallback?(threat)
    }
    
    // MARK: - Code Signature Verification
    
    private func verifyCodeSignature(processPath: String) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        task.arguments = ["-v", "-R", "=", processPath]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    private func checkNotarization(processPath: String) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        task.arguments = ["--assess", "--type", "execute", processPath]
        
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    // MARK: - Detection Logic
    
    private func detectProcessInjection(pid: pid_t) -> Bool {
        // Check for code injection indicators using pgrep and lsof
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/lsof")
        task.arguments = ["-p", String(pid)]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            // Look for suspicious memory mappings
            return output.contains("DEL") || output.contains("socket")
        } catch {
            return false
        }
    }
    
    private func isProcessAuthorizedForPath(_ processPath: String, _ filePath: String) -> Bool {
        // Check entitlements
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        task.arguments = ["-d", "--entitlements", "-", processPath]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let entitlements = String(data: data, encoding: .utf8) ?? ""
            
            // Check for keychain access entitlement
            if filePath.contains("Keychain") {
                return entitlements.contains("keychain-access-groups")
            }
            
            return true
        } catch {
            return false
        }
    }
    
    private func isSystemPath(_ path: String) -> Bool {
        let systemPaths = ["/System", "/Library/System", "/usr/libexec", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        return systemPaths.contains(where: { path.hasPrefix($0) })
    }
    
    // MARK: - File Scanning
    
    func scanFile(at path: String) -> ThreatScore {
        let url = URL(fileURLWithPath: path)
        
        guard let data = try? Data(contentsOf: url) else {
            return ThreatScore(score: 0.0, reasons: ["File not readable"])
        }
        
        var score = 0.0
        var reasons: [String] = []
        
        // Entropy analysis
        let entropy = calculateEntropy(data)
        if entropy > 7.5 {
            score += 0.3
            reasons.append("High entropy: \(String(format: "%.2f", entropy))")
        }
        
        // Code signature check
        if !verifyCodeSignature(processPath: path) {
            score += 0.25
            reasons.append("Invalid/missing code signature")
        }
        
        // File size
        if data.count > 50_000_000 {
            score += 0.15
            reasons.append("Large file: \(data.count / 1_000_000)MB")
        }
        
        // Check if notarized (positive indicator)
        if checkNotarization(processPath: path) {
            score = max(0, score - 0.1)
            reasons.append("Apple notarized")
        }
        
        return ThreatScore(score: min(score, 1.0), reasons: reasons)
    }
    
    private func calculateEntropy(_ data: Data) -> Double {
        guard !data.isEmpty else { return 0.0 }
        
        var frequencies = [UInt8: Int]()
        for byte in data {
            frequencies[byte, default: 0] += 1
        }
        
        var entropy: Double = 0
        let count = Double(data.count)
        
        for frequency in frequencies.values {
            let probability = Double(frequency) / count
            entropy -= probability * log2(probability)
        }
        
        return entropy
    }
}

// MARK: - Data Models

struct Threat: Codable {
    let id: String
    let timestamp: Date
    let type: ThreatType
    let severity: ThreatSeverity
    let source: String
    let details: String
    
    enum ThreatType: String, Codable {
        case process, file, network, system
    }
    
    enum ThreatSeverity: String, Codable {
        case low, medium, high, critical
    }
}

struct ThreatScore: Codable {
    let score: Double
    let reasons: [String]
}
