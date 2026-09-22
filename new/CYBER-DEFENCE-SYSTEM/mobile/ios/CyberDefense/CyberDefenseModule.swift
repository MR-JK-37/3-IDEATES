import React
import Foundation

@objc(CyberDefenseModule)
class CyberDefenseModule: NSObject {
    
    private let securityEngine = IOSSecurityEngine.shared
    private let dataStore = ThreatDataStore.shared
    
    @objc static func requiresMainQueueSetup() -> Bool {
        return true
    }
    
    // MARK: - Start/Stop Monitoring
    @objc func startMonitoring(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            self.securityEngine.startMonitoring { threat in
                self.dataStore.saveThreat(threat)
                self.sendEvent(threat: threat)
            }
            resolve(["status": "monitoring"])
        }
    }
    
    @objc func stopMonitoring(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            self.securityEngine.stopMonitoring()
            resolve(["status": "stopped"])
        }
    }
    
    // MARK: - Fetch Threats
    @objc func getRecentThreats(_ limit: NSNumber, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let threats = dataStore.getRecentThreats(limit: limit.intValue)
        let encoded = threats.map { threat in
            [
                "id": threat.id,
                "timestamp": ISO8601DateFormatter().string(from: threat.timestamp),
                "type": threat.type.rawValue,
                "severity": threat.severity.rawValue,
                "source": threat.source,
                "details": threat.details
            ]
        }
        resolve(encoded)
    }
    
    // MARK: - File Scanning
    @objc func scanFile(_ filePath: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let score = securityEngine.scanFile(at: filePath)
        resolve([
            "score": score.score,
            "reasons": score.reasons
        ])
    }
    
    // MARK: - Event Emission
    private func sendEvent(threat: Threat) {
        // Implement native event emission back to React Native
        // This would use RCTEventEmitter in production
    }
}
