import Foundation

/// XPC Communication wrapper for macOS Endpoint Security
/// Handles bidirectional communication between system extension and Rust av-service
class XPCConnection {
    private let xpcConnection: NSXPCConnection
    private let logger = os.log.init(subsystem: "com.cybershield.es", category: "XPC")
    
    init(serviceName: String = "com.cybershield.av-service") {
        self.xpcConnection = NSXPCConnection(serviceName: serviceName)
        self.xpcConnection.remoteObjectInterface = NSXPCInterface(with: AVServiceXPCProtocol.self)
        self.xpcConnection.resume()
        
        os_log("XPC connection initialized to %{public}@", log: logger, type: .info, serviceName)
    }
    
    /// Request file scan from Rust av-service
    /// - Parameter fileEvent: The file event to scan
    /// - Returns: The scan decision (allow/deny/quarantine)
    func requestScan(fileEvent: FileEvent) -> ScanDecision {
        guard let proxy = xpcConnection.synchronousRemoteObjectProxyWithErrorHandler({ error in
            os_log("XPC error: %{public}@", log: self.logger, type: .error, error.localizedDescription)
        }) as? AVServiceXPCProtocol else {
            os_log("Failed to get XPC proxy", log: logger, type: .error)
            return .unknown
        }
        
        var decision: ScanDecision = .unknown
        let semaphore = DispatchSemaphore(value: 0)
        
        do {
            let eventData = try JSONEncoder().encode(fileEvent)
            
            proxy.scanFile(with: eventData) { (decisionData: Data?) in
                if let decisionData = decisionData,
                   let scanDecision = try? JSONDecoder().decode(ScanDecision.self, from: decisionData) {
                    decision = scanDecision
                }
                semaphore.signal()
            }
            
            // Wait up to 60 seconds for response (Endpoint Security deadline)
            _ = semaphore.wait(timeout: .now() + 60)
        } catch {
            os_log("Failed to encode event: %{public}@", log: logger, type: .error, error.localizedDescription)
        }
        
        return decision
    }
    
    deinit {
        xpcConnection.invalidate()
    }
}

/// XPC Protocol for communication with av-service
@objc protocol AVServiceXPCProtocol {
    func scanFile(with eventData: Data, completionHandler: @escaping (Data?) -> Void)
    func getServiceStatus(completionHandler: @escaping (String?) -> Void)
}

// Import os.log for logging
import os.log
