@echo off
REM Windows minifilter driver build script
REM Usage: build-driver.bat [clean|release|test-sign]

setlocal enabledelayedexpansion

set WDK_PATH=C:\Program Files (x86)\Windows Kits\10
set WDK_VERSION=10.0.22621.0
set DRIVER_DIR=%CD%\av-kernel-windows
set BUILD_DIR=%DRIVER_DIR%\build
set OUTPUT_DIR=%BUILD_DIR%\Release

echo.
echo ============================================
echo CyberShield Windows Minifilter Driver Build
echo ============================================
echo.

REM Check prerequisites
echo Checking prerequisites...

if not exist "%WDK_PATH%" (
    echo ERROR: Windows Driver Kit not found at %WDK_PATH%
    echo Please install WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: CMake not found in PATH
    echo Please install CMake: https://cmake.org/download/
    exit /b 1
)

echo [OK] WDK found at %WDK_PATH%
echo [OK] CMake found in PATH
echo.

REM Parse arguments
set BUILD_TYPE=Release
set SKIP_SIGN=0

if "%1"=="clean" (
    echo Cleaning build directory...
    if exist "%BUILD_DIR%" (
        rmdir /s /q "%BUILD_DIR%"
    )
    echo Done.
    exit /b 0
)

if "%1"=="test-sign" (
    set SKIP_SIGN=0
    echo Build type: Release with test signing
) else if "%1"=="release" (
    set SKIP_SIGN=1
    echo Build type: Release (no signing)
) else (
    echo Build type: Release (default)
)

echo.
echo ============================================
echo Step 1: Creating build directory
echo ============================================
echo.

if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
)

cd /d "%BUILD_DIR%" || exit /b 1
echo Created: %BUILD_DIR%

echo.
echo ============================================
echo Step 2: Configuring with CMake
echo ============================================
echo.

cmake -G "Visual Studio 17 2022" -A x64 ^
    -DWDK_PATH="%WDK_PATH%" ^
    -DWDK_VERSION="%WDK_VERSION%" ^
    ..

if %errorlevel% neq 0 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo [OK] CMake configuration successful

echo.
echo ============================================
echo Step 3: Building driver
echo ============================================
echo.

cmake --build . --config Release

if %errorlevel% neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo [OK] Build successful

echo.
echo ============================================
echo Step 4: Locating output files
echo ============================================
echo.

if exist "%OUTPUT_DIR%\minifilter.sys" (
    echo [OK] Driver: %OUTPUT_DIR%\minifilter.sys
    echo Size: 
    for /f %%A in ('dir /-C "%OUTPUT_DIR%\minifilter.sys" ^| find "minifilter.sys"') do (
        echo %%A
    )
) else (
    echo ERROR: minifilter.sys not found
    exit /b 1
)

if exist "%DRIVER_DIR%\minifilter.inf" (
    echo [OK] INF: %DRIVER_DIR%\minifilter.inf
) else (
    echo ERROR: minifilter.inf not found
    exit /b 1
)

echo.
echo ============================================
echo Step 5: Test-signing driver (if requested)
echo ============================================
echo.

if "%1"=="test-sign" (
    REM Check for signtool
    where signtool >nul 2>&1
    if %errorlevel% neq 0 (
        echo ERROR: signtool not found (should be in Windows SDK bin directory)
        echo Please add to PATH: %WDK_PATH%\bin\x64
        exit /b 1
    )
    
    echo Generating test certificate...
    
    if not exist "%BUILD_DIR%\minifilter.cer" (
        makecert -sv "%BUILD_DIR%\minifilter.pvk" ^
                 -n "CN=CyberShield Test Certificate" ^
                 "%BUILD_DIR%\minifilter.cer"
        
        if %errorlevel% neq 0 (
            echo ERROR: Certificate generation failed
            exit /b 1
        )
        echo [OK] Certificate created
    )
    
    if not exist "%BUILD_DIR%\minifilter.pfx" (
        echo Converting to PFX format...
        pvk2pfx -pvk "%BUILD_DIR%\minifilter.pvk" ^
               -spc "%BUILD_DIR%\minifilter.cer" ^
               -pfx "%BUILD_DIR%\minifilter.pfx" ^
               -f
        
        if %errorlevel% neq 0 (
            echo ERROR: PFX conversion failed
            exit /b 1
        )
        echo [OK] PFX created
    )
    
    echo Signing driver with test certificate...
    signtool sign /f "%BUILD_DIR%\minifilter.pfx" ^
                 /t "http://timestamp.verisign.com/scripts/timstamp.dll" ^
                 "%OUTPUT_DIR%\minifilter.sys"
    
    if %errorlevel% neq 0 (
        echo ERROR: Signing failed
        exit /b 1
    )
    echo [OK] Driver signed successfully
    
    echo.
    echo NOTE: Test mode must be enabled:
    echo   bcdedit /set testsigning on
    echo   (requires admin, reboot required)
)

echo.
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Output files:
echo   - Driver:   %OUTPUT_DIR%\minifilter.sys
echo   - Config:   %DRIVER_DIR%\minifilter.inf
echo.
echo Next steps:
echo 1. Copy files to drivers folder
echo 2. Install with: pnputil /add-driver minifilter.inf /install
echo 3. Start driver with: net start AVFilter
echo.
echo For details, see: docs/windows-driver-build.md
echo.

endlocal
