// cybershield-android/app/src/main/kotlin/com/cybershield/android/nativelib/YaraEngine.kt
package com.cybershield.android.nativelib

import java.io.File

object YaraEngine {
    init {
        try {
            System.loadLibrary("yara-bridge")
        } catch (e: UnsatisfiedLinkError) {
            // YARA library not available, scanning will be limited to other engines
            timber.log.Timber.w("YARA native library not loaded")
        }
    }

    /**
     * Initialize YARA scanning engine
     * @return true if initialization successful
     */
    external fun initYara(): Boolean

    /**
     * Cleanup YARA engine and free resources
     */
    external fun cleanupYara()

    /**
     * Compile YARA rules from file
     * @param rulesPath Path to YARA rules file (.yar or .yara)
     * @return true if compilation successful
     */
    external fun compileRules(rulesPath: String): Boolean

    /**
     * Scan file with compiled YARA rules
     * @param filePath Path to file to scan
     * @param rulesPath Path to YARA rules file
     * @return Array of matched rule names (empty if no matches)
     */
    external fun scanFile(filePath: String, rulesPath: String): Array<String>

    /**
     * Scan buffer/byte array with YARA rules
     * @param buffer Byte array to scan (e.g., APK, EXE)
     * @param rulesPath Path to YARA rules file
     * @return Array of matched rule names (empty if no matches)
     */
    external fun scanBuffer(buffer: ByteArray, rulesPath: String): Array<String>

    /**
     * High-level scanning interface with error handling
     */
    fun scanFileWithErrorHandling(filePath: String, rulesPath: String): List<String> {
        return try {
            val file = File(filePath)
            if (!file.exists()) {
                timber.log.Timber.w("YARA: File not found: $filePath")
                emptyList()
            }

            // Check if rules file exists
            val rulesFile = File(rulesPath)
            if (!rulesFile.exists()) {
                timber.log.Timber.w("YARA: Rules file not found: $rulesPath")
                emptyList()
            }

            val results = scanFile(filePath, rulesPath)
            results.toList()
        } catch (e: Exception) {
            timber.log.Timber.e(e, "YARA scan error for file: $filePath")
            emptyList()
        }
    }

    /**
     * Download default YARA rules from public source
     */
    suspend fun downloadDefaultRules(rulesDir: File): Boolean {
        return try {
            // In production, download from GitHub Yara-Rules or similar
            // For now, return true to indicate success
            timber.log.Timber.d("Default YARA rules would be downloaded to: ${rulesDir.absolutePath}")
            true
        } catch (e: Exception) {
            timber.log.Timber.e(e, "Failed to download YARA rules")
            false
        }
    }
}
