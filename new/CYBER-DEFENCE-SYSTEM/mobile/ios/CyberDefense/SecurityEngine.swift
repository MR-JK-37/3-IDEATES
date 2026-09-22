import Foundation
import EndpointSecurity
import Network
import CoreML

/// iOS Security Engine - Endpoint Security Framework Integration
/// Monitors process/file/network activity on iOS 15+

@objc class IOSSecurityEngine: NSObject {
    static let shared = IOSSecurityEngine()
    
    private var esClient: es_client_t?
    private var isMonitoring = false
    private var threatCallback: ((Threat) -> Void)?
    
    // MARK: - Initialization
    @objc func startMonitoring(callback: @escaping (Threat) -> Void) {
        guard !isMonitoring else { return }
        
        threatCallback = callback
        
        // Create Endpoint Security client
        let handler: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<es_message_t>) -> Void = { context, message in
            let engine = Unmanaged<IOSSecurityEngine>.fromOpaque(context!).takeUnretainedValue()
            engine.handleESMessage(message)
        }
        
        let result = es_new_client(&esClient, handler, UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()))
        
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            print("[ES] Failed to create client")
            return
        }
        
        // Subscribe to events
        subscribeToEvents()
        isMonitoring = true
        print("[ES] Monitoring started")
    }
    
    @objc func stopMonitoring() {
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
            ES_EVENT_TYPE_AUTH_WRITE,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_WRITE,
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
        case ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXEC:
            handleProcessExecution(message)
        case ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_OPEN:
            handleFileOpen(message)
        case ES_EVENT_TYPE_AUTH_WRITE, ES_EVENT_TYPE_NOTIFY_WRITE:
            handleFileWrite(message)
        default:
            break
        }
    }
    
    private func handleProcessExecution(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.exec.pointee
        
        let processName = String(cString: event.executable.pointee.path.data)
        let pid = event.executable.pointee.stat.st_ino
        
        // Check code signature
        let isSignedByApple = verifyCodeSignature(processPath: processName)
        
        let threat = Threat(
            id: UUID().uuidString,
            timestamp: Date(),
            type: .process,
            severity: isSignedByApple ? .low : .high,
            source: processName,
            details: "Process exec: \(processName) (PID: \(pid), Signed: \(isSignedByApple))"
        )
        
        threatCallback?(threat)
    }
    
    private func handleFileOpen(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.open.pointee
        
        let filePath = String(cString: event.file.pointee.path.data)
        let processName = String(cString: event.executable.pointee.path.data)
        
        // Check for suspicious file access patterns
        let isSuspicious = filePath.contains(".sensitive") || 
                          filePath.contains("keychain") ||
                          filePath.contains("cache")
        
        if isSuspicious {
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .file,
                severity: .medium,
                source: processName,
                details: "Suspicious file access: \(filePath)"
            )
            threatCallback?(threat)
        }
    }
    
    private func handleFileWrite(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.write.pointee
        
        let filePath = String(cString: event.file.pointee.path.data)
        let processName = String(cString: event.executable.pointee.path.data)
        
        // Detect rapid file writes (ransomware pattern)
        let bytesWritten = event.byte_offset + event.byte_count
        if bytesWritten > 100_000_000 { // > 100MB in single write
            let threat = Threat(
                id: UUID().uuidString,
                timestamp: Date(),
                type: .file,
                severity: .critical,
                source: processName,
                details: "Mass file write detected: \(filePath) (\(bytesWritten) bytes)"
            )
            threatCallback?(threat)
        }
    }
    
    // MARK: - Code Signature Verification
    private func verifyCodeSignature(processPath: String) -> Bool {
        // Use Security framework to verify code signature
        let secStaticCode = UnsafeMutablePointer<SecStaticCode?>.allocate(capacity: 1)
        defer { secStaticCode.deallocate() }
        
        let url = URL(fileURLWithPath: processPath)
        let result = SecStaticCodeCreateWithPath(url as CFURL, [], secStaticCode)
        
        guard result == errSecSuccess else { return false }
        
        let validationResult = SecStaticCodeCheckValidityWithErrors(secStaticCode.pointee, [.all], nil, nil)
        return validationResult == errSecSuccess
    }
    
    // MARK: - Threat Detection
    @objc func scanFile(at path: String) -> ThreatScore {
        let url = URL(fileURLWithPath: path)
        
        // Calculate entropy
        guard let data = try? Data(contentsOf: url) else {
            return ThreatScore(score: 0.0, reasons: ["File not readable"])
        }
        
        let entropy = calculateEntropy(data)
        
        // Check file extension
        let `extension` = url.pathExtension.lowercased()
        let suspiciousExtensions = ["app", "deb", "pkg", "dmg", "apk"]
        let hasUnusualExt = suspiciousExtensions.contains(`extension`)
        
        var score = 0.0
        var reasons: [String] = []
        
        if entropy > 7.5 {
            score += 0.3
            reasons.append("High entropy: \(String(format: "%.2f", entropy))")
        }
        
        if hasUnusualExt {
            score += 0.2
            reasons.append("Suspicious extension: \(`extension`)")
        }
        
        // Check file size (large binaries suspicious)
        if data.count > 50_000_000 { // > 50MB
            score += 0.15
            reasons.append("Large binary: \(data.count / 1_000_000)MB")
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
    let score: Double // 0.0-1.0
    let reasons: [String]
}
