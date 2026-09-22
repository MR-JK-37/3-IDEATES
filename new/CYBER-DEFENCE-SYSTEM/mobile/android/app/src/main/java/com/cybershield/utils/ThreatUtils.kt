package com.cybershield.utils

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.File
import java.util.Collections

/**
 * Utilities for entropy calculation, process introspection, and risk scoring.
 */
object ThreatUtils {

    /**
     * Calculate Shannon entropy of a byte array (0.0 - 8.0 for bytes).
     * High entropy (>7.5) suggests encryption or compression.
     */
    fun shannonEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        val freq = IntArray(256)
        for (b in data) {
            freq[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val len = data.size.toDouble()
        for (count in freq) {
            if (count > 0) {
                val p = count / len
                entropy -= p * kotlin.math.log2(p)
            }
        }
        return entropy
    }

    /**
     * Get memory info for a process (via /proc/pid/status on Android).
     */
    fun getProcessMemoryKb(pid: Int): Long {
        return try {
            val statusFile = File("/proc/$pid/status")
            if (!statusFile.exists()) return -1L
            val lines = statusFile.readLines()
            val vmRss = lines.firstOrNull { it.startsWith("VmRSS:") }
                ?.substringAfter(":")
                ?.trim()
                ?.substringBefore(" ")
                ?.toLongOrNull() ?: return -1L
            vmRss
        } catch (e: Exception) {
            -1L
        }
    }

    /**
     * Check if a process has suspicious API call patterns.
     * Returns a score 0-50 based on heuristics.
     */
    fun assessProcessSuspicion(processName: String, nativeLibraries: List<String>): Int {
        var score = 0

        // Check for injection/reflection libraries
        if (nativeLibraries.any { it.contains("xposed") || it.contains("frida") }) {
            score += 30
        }

        // Check for suspicious names
        if (processName.contains("inject") || processName.contains("hook")) {
            score += 20
        }

        return minOf(50, score)
    }

    /**
     * Check if a file has suspicious entropy (likely encrypted/compressed).
     */
    fun isHighEntropy(file: File, threshold: Double = 7.5): Boolean {
        return try {
            val sample = file.inputStream().use {
                val buffer = ByteArray(minOf(65536, it.available()))
                it.read(buffer)
                buffer
            }
            shannonEntropy(sample) > threshold
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if a process is a system process (signature-based allowlist).
     */
    fun isSystemProcess(packageName: String): Boolean {
        return packageName.startsWith("android.") ||
                packageName.startsWith("com.android.") ||
                packageName.startsWith("com.google.android.")
    }

    /**
     * Convert a threat score (0-100) to a severity level.
     */
    fun threatScoreToSeverity(score: Int): String {
        return when {
            score < 20 -> "SAFE"
            score < 40 -> "WATCH"
            score < 60 -> "SUSPICIOUS"
            score < 80 -> "MALICIOUS"
            else -> "CRITICAL"
        }
    }

    /**
     * Sanitize a string for logging (remove PII).
     */
    fun sanitize(value: String): String {
        return value
            .replace(Regex("""\d{3}-\d{2}-\d{4}"""), "***-**-****") // SSN
            .replace(Regex("""\b\d{16}\b"""), "****-****-****-****") // Card
    }
}
