import Foundation

/// Main entry point for CyberShield Endpoint Security system extension
/// Runs as a system extension (daemon) on macOS 10.15+

let fileMonitor = FileMonitor(xpcConnection: XPCConnection())

// Start monitoring
if fileMonitor.start() {
    os_log("CyberShield ES daemon started successfully", 
           log: os.log.init(subsystem: "com.cybershield.es", category: "Main"), 
           type: .info)
    
    // Keep the daemon running
    RunLoop.main.run()
} else {
    os_log("Failed to start CyberShield ES daemon", 
           log: os.log.init(subsystem: "com.cybershield.es", category: "Main"), 
           type: .error)
    exit(1)
}

import Foundation
import os.log
