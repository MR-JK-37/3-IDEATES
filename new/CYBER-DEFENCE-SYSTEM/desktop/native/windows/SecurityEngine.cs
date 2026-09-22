using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace CyberDefense.Windows
{
    /// <summary>
    /// Windows Security Engine - FileSystemWatcher, ETW, WMI Integration
    /// Monitors file/process/network activity on Windows 10+
    /// </summary>
    public class WindowsSecurityEngine
    {
        private FileSystemWatcher _fileWatcher;
        private EventTraceSession _etwSession;
        private WmiEventWatcher _processWatcher;
        public event EventHandler<ThreatEventArgs> ThreatDetected;
        
        private readonly List<string> _monitoredDirectories = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AppData")
        };
        
        public void StartMonitoring()
        {
            // 1. Setup file system monitoring
            SetupFileSystemMonitoring();
            
            // 2. Setup ETW (Event Tracing for Windows)
            SetupETWMonitoring();
            
            // 3. Setup WMI process monitoring
            SetupWMIMonitoring();
            
            Console.WriteLine("[Windows] Security monitoring started");
        }
        
        public void StopMonitoring()
        {
            _fileWatcher?.Dispose();
            _etwSession?.Dispose();
            _processWatcher?.Dispose();
            Console.WriteLine("[Windows] Security monitoring stopped");
        }
        
        /// <summary>
        /// Monitor file system for suspicious activity
        /// </summary>
        private void SetupFileSystemMonitoring()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            
            _fileWatcher = new FileSystemWatcher(userProfile)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName,
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };
            
            // Exclude system directories
            var excludePatterns = new[] { "\\AppData\\Local\\Microsoft", "\\AppData\\Roaming\\Microsoft", "\\Windows", "\\System32" };
            
            _fileWatcher.Created += (s, e) => OnFileCreated(e.FullPath, excludePatterns);
            _fileWatcher.Changed += (s, e) => OnFileModified(e.FullPath, excludePatterns);
            _fileWatcher.Renamed += (s, e) => OnFileRenamed(e.OldFullPath, e.FullPath, excludePatterns);
        }
        
        private void OnFileCreated(string path, string[] excludePatterns)
        {
            if (excludePatterns.Any(p => path.Contains(p))) return;
            
            try
            {
                var fileInfo = new FileInfo(path);
                
                // Check for executable/script creation in unusual locations
                var suspiciousExtensions = new[] { ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs" };
                var ext = fileInfo.Extension.ToLower();
                
                if (suspiciousExtensions.Contains(ext) && !IsSystemPath(path))
                {
                    RaiseThreat(new Threat
                    {
                        Id = Guid.NewGuid().ToString(),
                        Timestamp = DateTime.UtcNow,
                        Type = ThreatType.File,
                        Severity = ThreatSeverity.High,
                        Source = GetProcessByFile(path) ?? "Unknown",
                        Details = $"Suspicious executable created: {path}"
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FileWatcher] Error: {ex.Message}");
            }
        }
        
        private void OnFileModified(string path, string[] excludePatterns)
        {
            if (excludePatterns.Any(p => path.Contains(p))) return;
            
            try
            {
                var fileInfo = new FileInfo(path);
                
                // Detect suspicious file modifications (ransomware pattern)
                if (fileInfo.Exists && fileInfo.Length > 100_000_000) // > 100MB
                {
                    var entropy = CalculateFileEntropy(path);
                    if (entropy > 7.5)
                    {
                        RaiseThreat(new Threat
                        {
                            Id = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            Type = ThreatType.File,
                            Severity = ThreatSeverity.Critical,
                            Source = GetProcessByFile(path) ?? "Unknown",
                            Details = $"Mass file modification detected: {path} (Entropy: {entropy:F2})"
                        });
                    }
                }
            }
            catch { }
        }
        
        private void OnFileRenamed(string oldPath, string newPath, string[] excludePatterns)
        {
            if (excludePatterns.Any(p => newPath.Contains(p))) return;
            
            // Detect ransomware file extension changes
            var ransomwareExtensions = new[] { ".locked", ".encrypted", ".cryptowall", ".cerber", ".locky", ".wannacry", ".petya" };
            var newExt = Path.GetExtension(newPath).ToLower();
            
            if (ransomwareExtensions.Contains(newExt))
            {
                RaiseThreat(new Threat
                {
                    Id = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    Type = ThreatType.File,
                    Severity = ThreatSeverity.Critical,
                    Source = GetProcessByFile(newPath) ?? "Unknown",
                    Details = $"File renamed to ransomware extension: {oldPath} → {newPath}"
                });
            }
        }
        
        /// <summary>
        /// Setup ETW (Event Tracing for Windows) for detailed event monitoring
        /// </summary>
        private void SetupETWMonitoring()
        {
            try
            {
                _etwSession = new EventTraceSession("CyberDefenseETW");
                
                // Monitor process events via Windows Event Log
                var processWatcher = new EventLogWatcher("Security")
                {
                    Query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4688)]]")
                };
                
                processWatcher.EventRecordWritten += (s, e) => OnProcessCreated(e.EventRecord);
                processWatcher.Enabled = true;
                
                Console.WriteLine("[ETW] Process monitoring enabled");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ETW] Setup failed: {ex.Message}");
            }
        }
        
        private void OnProcessCreated(EventRecord record)
        {
            try
            {
                var cmdLine = record.Properties[8].Value?.ToString() ?? "";
                var parentPid = int.TryParse(record.Properties[6].Value?.ToString(), out var pid) ? pid : 0;
                
                // Check for suspicious process spawning
                var suspiciousPatterns = new[] { "powershell", "cmd.exe", "wscript.exe", "cscript.exe" };
                
                if (suspiciousPatterns.Any(p => cmdLine.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    // Check if parent is suspicious
                    var parentProc = GetProcessById(parentPid);
                    if (parentProc != null && IsProcessSuspicious(parentProc.ProcessName))
                    {
                        RaiseThreat(new Threat
                        {
                            Id = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            Type = ThreatType.Process,
                            Severity = ThreatSeverity.High,
                            Source = parentProc.ProcessName,
                            Details = $"Suspicious process spawn: {cmdLine}"
                        });
                    }
                }
            }
            catch { }
        }
        
        /// <summary>
        /// Setup WMI monitoring for process creation
        /// </summary>
        private void SetupWMIMonitoring()
        {
            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                
                var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                _processWatcher = new ManagementEventWatcher(scope, query);
                _processWatcher.EventArrived += OnWMIProcessCreated;
                _processWatcher.Start();
                
                Console.WriteLine("[WMI] Process monitoring enabled");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WMI] Setup failed: {ex.Message}");
            }
        }
        
        private void OnWMIProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var processName = e.NewEvent.Properties["ProcessName"].Value?.ToString() ?? "";
                var processId = int.TryParse(e.NewEvent.Properties["ProcessID"].Value?.ToString(), out var pid) ? pid : 0;
                
                // Detect suspicious process characteristics
                var suspiciousIndicators = IsProcessSuspicious(processName);
                
                if (suspiciousIndicators)
                {
                    RaiseThreat(new Threat
                    {
                        Id = Guid.NewGuid().ToString(),
                        Timestamp = DateTime.UtcNow,
                        Type = ThreatType.Process,
                        Severity = ThreatSeverity.Medium,
                        Source = processName,
                        Details = $"Suspicious process detected: {processName} (PID: {processId})"
                    });
                }
            }
            catch { }
        }
        
        // MARK: - File Analysis
        
        public (double score, List<string> reasons) ScanFile(string path)
        {
            var score = 0.0;
            var reasons = new List<string>();
            
            try
            {
                var fileInfo = new FileInfo(path);
                if (!fileInfo.Exists) return (0, new List<string> { "File not found" });
                
                // 1. Entropy analysis
                var entropy = CalculateFileEntropy(path);
                if (entropy > 7.5)
                {
                    score += 0.3;
                    reasons.Add($"High entropy: {entropy:F2}");
                }
                
                // 2. Digital signature verification
                var isSigned = VerifyDigitalSignature(path);
                if (!isSigned)
                {
                    score += 0.2;
                    reasons.Add("No valid digital signature");
                }
                
                // 3. File extension check
                var ext = fileInfo.Extension.ToLower();
                var executableExts = new[] { ".exe", ".dll", ".sys", ".scr" };
                if (executableExts.Contains(ext))
                {
                    score += 0.1;
                    reasons.Add($"Executable type: {ext}");
                }
                
                // 4. File size (large binaries suspicious)
                if (fileInfo.Length > 50_000_000)
                {
                    score += 0.15;
                    reasons.Add($"Large file: {fileInfo.Length / 1_000_000}MB");
                }
            }
            catch (Exception ex)
            {
                reasons.Add($"Scan error: {ex.Message}");
            }
            
            return (Math.Min(score, 1.0), reasons);
        }
        
        private double CalculateFileEntropy(string path)
        {
            try
            {
                using (var stream = File.OpenRead(path))
                {
                    var buffer = new byte[Math.Min(1_000_000, stream.Length)];
                    stream.Read(buffer, 0, buffer.Length);
                    
                    var frequencies = new int[256];
                    foreach (var b in buffer)
                    {
                        frequencies[b]++;
                    }
                    
                    double entropy = 0;
                    foreach (var freq in frequencies)
                    {
                        if (freq == 0) continue;
                        var p = (double)freq / buffer.Length;
                        entropy -= p * Math.Log2(p);
                    }
                    
                    return entropy;
                }
            }
            catch { return 0; }
        }
        
        private bool VerifyDigitalSignature(string path)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                return cert != null;
            }
            catch { return false; }
        }
        
        // MARK: - Helpers
        
        private bool IsSystemPath(string path)
        {
            var systemPaths = new[] { "\\Windows", "\\System32", "\\Program Files", "\\ProgramData" };
            return systemPaths.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase));
        }
        
        private bool IsProcessSuspicious(string processName)
        {
            var suspiciousProcesses = new[] { "svchost.exe", "lsass.exe", "wininit.exe", "userinit.exe" };
            var injectionIndicators = new[] { "rundll32", "regsvcs", "regasm", "installutil", "mshta", "cscript", "wscript" };
            
            return suspiciousProcesses.Contains(Path.GetFileName(processName), StringComparer.OrdinalIgnoreCase) ||
                   injectionIndicators.Any(ind => processName.Contains(ind, StringComparison.OrdinalIgnoreCase));
        }
        
        private string GetProcessByFile(string path)
        {
            try
            {
                var handle = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        if (p.Modules.Cast<ProcessModule>().Any(m => m.FileName == path))
                            return p.ProcessName;
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }
        
        private Process GetProcessById(int pid)
        {
            try { return Process.GetProcessById(pid); }
            catch { return null; }
        }
        
        private void RaiseThreat(Threat threat)
        {
            ThreatDetected?.Invoke(this, new ThreatEventArgs { Threat = threat });
        }
    }
    
    // MARK: - Data Models
    
    public class Threat
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public ThreatType Type { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Source { get; set; }
        public string Details { get; set; }
    }
    
    public enum ThreatType { Process, File, Network, System }
    public enum ThreatSeverity { Low, Medium, High, Critical }
    
    public class ThreatEventArgs : EventArgs
    {
        public Threat Threat { get; set; }
    }
    
    // ETW Session placeholder
    public class EventTraceSession : IDisposable
    {
        private string _name;
        public EventTraceSession(string name) => _name = name;
        public void Dispose() { }
    }
}
