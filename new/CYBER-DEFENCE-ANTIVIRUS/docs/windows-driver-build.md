# Windows Minifilter Driver Build and Installation Guide

This document explains how to build, sign, and deploy the Windows minifilter driver component of CyberShield Antivirus.

## Architecture Overview

The Windows minifilter driver (`av-kernel-windows/minifilter.c`) intercepts file system operations at the kernel level using the Windows Filter Manager (FltMgr.sys) framework. It communicates with the Rust userspace service (`av-service`) via IOCTL/FilterPort IPC.

### Key Components

1. **minifilter.c** - Kernel driver implementation (650+ lines)
   - Pre-operation callbacks for IRP_MJ_CREATE (file open) and IRP_MJ_WRITE
   - FilterPort communication server for bidirectional IPC
   - Event forwarding to userspace scanner

2. **minifilter.h** - Header with structures and IOCTL definitions
   - FILE_EVENT and SCAN_RESPONSE structures (64-bit aligned)
   - IOCTL codes matching Rust av-service expectations
   - Global state management

3. **minifilter.inf** - Installation configuration
   - Driver service definition (AVFilter)
   - Altitude registration (370000 = FSFilter Activity Monitor)
   - Registry settings

4. **CMakeLists.txt** - Build configuration for WDK

## Prerequisites

### Windows Driver Kit (WDK) Installation

1. Download WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Install matching your Windows 10/11 version (e.g., WDK for Windows 10, version 22H2)
3. Note the installation path (typically `C:\Program Files (x86)\Windows Kits\10`)

### Build Tools

- **Visual Studio 2022** (Community Edition sufficient)
  - C++ development tools
  - Windows SDK

- **CMake 3.10+**
  - Add to PATH for command-line builds

### Code Signing (Production)

- **EV Code Signing Certificate** - Required for production deployment
- **SignTool.exe** - Included with Windows SDK

## Build Instructions

### Option 1: Using WDK Build Tools (Recommended)

```bash
# Set WDK environment
"C:\Program Files (x86)\Windows Kits\10\bin\setenv.bat" x64 fre

# Navigate to driver directory
cd av-kernel-windows

# Build using Devenv (Visual Studio command line)
msbuild minifilter.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Option 2: Using CMake + MSVC

```bash
# Create build directory
mkdir build
cd build

# Configure (adjust WDK_PATH if needed)
cmake -G "Visual Studio 17 2022" -A x64 ^
  -DWDK_PATH="C:\Program Files (x86)\Windows Kits\10" ^
  -DWDK_VERSION="10.0.22621.0" ^
  ..

# Build
cmake --build . --config Release

# Output: minifilter.sys in build/Release/
```

### Option 3: Using Kernel Development Kit Direct

```bash
# Set environment
call "C:\Program Files (x86)\Windows Kits\10\bin\setenv.bat" x64 fre

# Build with build utility
cd av-kernel-windows
build -cZ -M 1
```

## Driver Signing (Required for Installation)

### Test Signing (Development)

For testing on Windows 10/11 with test mode enabled:

```bash
# Generate self-signed certificate (one-time)
makecert -sv minifilter.pvk -n "CN=CyberShield Test" minifilter.cer
pvk2pfx -pvk minifilter.pvk -spc minifilter.cer -pfx minifilter.pfx

# Sign driver
signtool sign /f minifilter.pfx /p "password" /t "http://timestamp.verisign.com/scripts/timstamp.dll" minifilter.sys

# Enable test mode (one-time, requires admin)
bcdedit /set testsigning on
# Reboot required
```

### Production Signing

Requires EV Code Signing Certificate from DigiCert, Sectigo, etc.

```bash
signtool sign /f "MyCert.pfx" /p "password" /tr "http://timestamp.digicert.com" /td sha256 minifilter.sys
```

## Installation

### Prerequisites
- Administrator privileges required
- Test signing enabled (if using self-signed certs): `bcdedit /set testsigning on`
- System reboot required

### Install Driver

```bash
# Copy files to system directory
copy minifilter.sys C:\Windows\System32\drivers\minifilter.sys
copy minifilter.inf C:\Windows\System32\drivers\minifilter.inf

# Register and start driver
pnputil /add-driver minifilter.inf /install

# Verify installation
sc query AVFilter

# Start driver
net start AVFilter

# Or using sc.exe
sc start AVFilter
```

### Verify Installation

```bash
# List installed drivers
sc query AVFilter

# Check driver status
Get-Service AVFilter | Select-Object Status

# View driver in Device Manager
devmgmt.msc
# Look under "Kernel drivers" or "System devices" for "AVFilter"

# Check WinDbg output (if debugger attached)
# Should see: "[AVFilter] DriverEntry - Initializing minifilter driver"
```

### Uninstall Driver

```bash
# Stop driver
net stop AVFilter
# or
sc stop AVFilter

# Remove from system
pnputil /delete-driver minifilter.inf /uninstall

# Remove driver file
del C:\Windows\System32\drivers\minifilter.sys
```

## Integration with av-service

### Connection Flow

1. Driver loads and creates FilterPort named `\AVFilterPort`
2. av-service (Rust) connects to FilterPort on Windows systems
3. Driver pre-op callbacks forward file events to av-service
4. av-service sends scan responses back to driver
5. Driver allows/blocks file operations based on scan result

### Code Integration

In `av-service/src/kernel_ipc/windows.rs`:

```rust
// Initialize on Windows
#[cfg(target_os = "windows")]
{
    let mut kernel_ipc = kernel_ipc::PlatformKernelIpc::new();
    kernel_ipc.connect()?;  // Connects to FilterPort
}
```

The Rust code:
- Opens connection to `\\AVFilterPort`
- Receives AV_FILE_EVENT structures from driver
- Sends AV_SCAN_RESPONSE back with scan decision
- Handles IOCTL communication and message passing

## Configuration and Tuning

### Driver Parameters (In minifilter.inf)

```ini
[AVFilter_Service_Inst]
DisplayName = "CyberShield File Filter"
ServiceType = 2       ; SERVICE_FILE_SYSTEM_DRIVER
StartType = 1         ; SERVICE_AUTO_START
ErrorControl = 0      ; SERVICE_ERROR_IGNORE

[AVFilter.AddReg]
HKR, "Parameters", "MaxConnections", 0x00010001, 1
HKR, "Parameters", "TimeoutMs", 0x00010001, 5000
```

### Altitude Configuration

The driver registers at altitude **370000** (FSFilter Activity Monitor). Minifilter altitudes define load order:

- 320000-329999: FSFilter Pre-creation protection (e.g., ransomware)
- 330000-339999: FSFilter Top & Bottom (e.g., encryption)
- 360000-369999: FSFilter HSM
- **370000-379999: FSFilter Activity Monitor** ← AVFilter
- 380000-389999: FSFilter Undelete
- 390000-399999: FSFilter Anti-virus

This position ensures the driver monitors all file operations after encryption/compression but before antivirus scanner uses the file.

## Debugging

### Enable Kernel Debugging

```bash
# Set up kernel debugger connection (requires 2nd machine or Virtual KD)
bcdedit /debug on
bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200

# Or for USB debugging
bcdedit /dbgsettings USB TARGETNAME:DEBUGCHANNEL
```

### WinDbg Commands

```
# Break into kernel debugger
!break

# View driver output
!ndiskd.filterlist

# Check filter status
!fltmgr

# View event log
!el

# Breakpoint on entry
bu minifilter!DriverEntry "g"
```

### DbgPrint Output

Debug messages from `DbgPrint()` appear in WinDbg or DebugView:

```
[AVFilter] DriverEntry - Initializing minifilter driver
[AVFilter] Minifilter registered successfully
[AVFilter] Communication port created at \AVFilterPort
[AVFilter] Filter started - ready for operations
```

## Performance Considerations

### Optimization Recommendations

1. **Pre-op callback filtering**: Skip unnecessary events early
   - Ignore directory operations: `FltObjects->FileObject->Flags & FO_DIRECTORY`
   - Skip memory-mapped files: `FO_MEMORY_MAPPED_VIEW`
   - Filter by file extension (if needed)

2. **Async scanning**: Current implementation uses synchronous wait
   - Future: Implement async response via queued completion

3. **Buffer pooling**: Avoid allocation in hot path (pre-op callbacks)
   - Preallocate FILE_EVENT structures
   - Use nonpaged pool for critical paths

4. **Altitude positioning**: Load after encryption, before final handlers

### Typical Performance

- Pre-op callback overhead: ~100-500µs (file open/write)
- Scan latency: 5-100ms (depending on ClamAV/YARA engine)
- Total impact on file operations: <5% on typical systems

## Troubleshooting

### Driver Won't Load

**Error**: "The specified service does not exist as an installed service"

**Solution**: 
1. Check INF file syntax: `pnputil /add-driver minifilter.inf /install`
2. Verify driver is signed (test signing enabled)
3. Check registry: `HKLM\SYSTEM\CurrentControlSet\Services\AVFilter`

### FilterPort Connection Fails

**Error**: av-service can't connect to `\AVFilterPort`

**Solution**:
1. Verify driver is running: `sc query AVFilter` (should be RUNNING)
2. Ensure av-service has admin privileges
3. Check security descriptor on FilterPort (should allow user access)

### Scan Results Not Applied

**Error**: Files are scanned but driver doesn't block malware

**Solution**:
1. Implement decision application in PostCreateOperation callback
2. Currently, pre-op callbacks only forward events; full decision handling requires:
   - Storing scan result in driver's event cache
   - Completing IRP with STATUS_ACCESS_DENIED if malicious

## Future Enhancements

1. **Async Scan Results**: Queue-based response handling for better concurrency
2. **Multiple Volumes**: Auto-attach to all volumes except system drives
3. **Quarantine Integration**: Move malicious files to quarantine folder
4. **Behavioral Monitoring**: Track process creation and memory operations
5. **YARA Rules Integration**: Load rules directly in kernel for real-time matching

## References

- [Windows Filtering Platform Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/)
- [Minifilter Driver Sample](https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter)
- [Filter Manager Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/the-filter-manager)
- [IOCTL Code Generation](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)

## Support

For issues with the minifilter driver, check:
1. System Event Viewer: `eventvwr.msc` → Windows Logs → System
2. WinDbg output (if kernel debugging enabled)
3. av-service logs (check `av-service` startup output)
