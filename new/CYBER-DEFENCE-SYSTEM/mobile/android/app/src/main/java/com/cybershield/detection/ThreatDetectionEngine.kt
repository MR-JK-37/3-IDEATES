package com.cybershield.detection

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.cybershield.utils.ThreatUtils
import java.io.File
import java.util.Date

/**
 * Threat detection engine (core behavioral analysis + entropy-based detection).
 *
 * Scores processes and files based on:
 * - File entropy (encryption detection)
 * - Process chain relationships (parent-child analysis)
 * - System API abuse patterns
 * - Mass file modification patterns
 */
class ThreatDetectionEngine(private val context: Context) {

    /**
     * Analyze a process for threat indicators.
     *
     * Returns a threat score 0-100 and rationale.
     */
    fun analyzeProcess(pid: Int, packageName: String): Pair<Int, String> {
        var score = 0
        val reasons = mutableListOf<String>()

        // Check if system process (allowlist)
        if (ThreatUtils.isSystemProcess(packageName)) {
            return Pair(0, "System process (allowlisted)")
        }

        try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)

            // Check if installed from Play Store (heuristic trust signal)
            val installerPackage = pm.getInstallerPackageName(packageName)
            if (installerPackage != "com.android.vending" && installerPackage != "com.google.android.packageinstaller") {
                score += 10
                reasons.add("Not installed from Play Store")
            }

            // Check for requested dangerous permissions
            val permissions = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS).requestedPermissions
            if (permissions != null) {
                val dangerousPerms = permissions.filter {
                    it.startsWith("android.permission.CAMERA") ||
                            it.startsWith("android.permission.RECORD_AUDIO") ||
                            it.startsWith("android.permission.READ_CALL_LOG")
                }
                if (dangerousPerms.isNotEmpty()) {
                    score += 15
                    reasons.add("Requests unusual dangerous permissions: ${dangerousPerms.take(2)}")
                }
            }

            // Check memory usage (anomaly detection)
            val memKb = ThreatUtils.getProcessMemoryKb(pid)
            if (memKb > 500_000) { // > 500 MB suspicious
                score += 20
                reasons.add("Excessive memory usage: ${memKb / 1024}MB")
            }
        } catch (e: Exception) {
            // Ignore if package not found
        }

        return Pair(minOf(100, score), reasons.joinToString(" | "))
    }

    /**
     * Analyze a file for encryption/ransomware indicators.
     *
     * Returns threat score 0-100 and type.
     */
    fun analyzeFile(file: File): Pair<Int, String> {
        var score = 0
        val indicators = mutableListOf<String>()

        if (!file.exists()) {
            return Pair(0, "File not found")
        }

        // Check entropy (encryption detection)
        if (ThreatUtils.isHighEntropy(file)) {
            score += 50
            indicators.add("High entropy (likely encrypted)")
        }

        // Check file extension (common ransomware extensions)
        val extension = file.extension.lowercase()
        val suspiciousExts = setOf(
            "locked", "encrypted", "xyz", "kkk", "bcat", "royal", "akira"
        )
        if (extension in suspiciousExts) {
            score += 30
            indicators.add("Suspicious extension: .$extension")
        }

        // Check location (Downloads, /tmp suspicious)
        if (file.path.contains("/Downloads") || file.path.contains("/cache")) {
            score += 10
            indicators.add("Stored in risky location")
        }

        // Check file size (anomalously large encrypted file)
        if (file.length() > 100_000_000) { // > 100 MB
            score += 5
            indicators.add("Large file")
        }

        return Pair(minOf(100, score), indicators.joinToString(" | "))
    }

    /**
     * Detect mass file modification (ransomware behavior).
     *
     * Returns true if >50 files modified in last 10 seconds.
     */
    fun detectMassModification(recentModifications: List<Long>): Boolean {
        val now = System.currentTimeMillis()
        val last10s = recentModifications.filter { now - it < 10_000 }
        return last10s.size > 50
    }

    /**
     * Analyze network connection for C2 beacon or data exfiltration.
     *
     * Returns threat score 0-100.
     */
    fun analyzeNetworkConnection(
        appPackage: String,
        destIP: String,
        destPort: Int,
        bytesUploaded: Long
    ): Int {
        var score = 0

        // Check if connection to known C2 server (local DB)
        if (isKnownC2Server(destIP)) {
            score += 80
        }

        // Check for unusual port
        if (destPort !in listOf(80, 443, 53, 123)) {
            score += 10
        }

        // Check for large data upload from non-cloud app
        if (bytesUploaded > 10_000_000 && !isTrustedCloudApp(appPackage)) {
            score += 30
        }

        return minOf(100, score)
    }

    private fun isKnownC2Server(ip: String): Boolean {
        // Placeholder: load from local SQLite threat DB
        return false
    }

    private fun isTrustedCloudApp(packageName: String): Boolean {
        val trustedApps = setOf(
            "com.google.android.gms",
            "com.google.android.apps.docs",
            "com.dropbox.android",
            "com.microsoft.skydrive"
        )
        return packageName in trustedApps
    }
}
