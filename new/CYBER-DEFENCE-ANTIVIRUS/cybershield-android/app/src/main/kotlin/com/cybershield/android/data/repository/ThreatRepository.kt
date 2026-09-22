// cybershield-android/app/src/main/kotlin/com/cybershield/android/data/repository/ThreatRepository.kt
package com.cybershield.android.data.repository

import android.content.Context
import com.cybershield.android.data.api.VirusTotalApi
import com.cybershield.android.data.api.VirusTotalUrlApi
import com.cybershield.android.data.dao.ScanResultDao
import com.cybershield.android.data.dao.ThreatDao
import com.cybershield.android.data.dao.UrlScanDao
import com.cybershield.android.data.entity.ThreatEntity
import com.cybershield.android.data.entity.UrlScanEntity
import kotlinx.coroutines.flow.Flow
import timber.log.Timber
import java.io.File
import java.security.MessageDigest
import java.time.LocalDateTime
import java.util.UUID

class ThreatRepository(
    private val threatDao: ThreatDao,
    private val scanResultDao: ScanResultDao,
    private val urlScanDao: UrlScanDao,
    private val virusTotalApi: VirusTotalApi,
    private val virusTotalUrlApi: VirusTotalUrlApi,
    private val apiKey: String
) {
    // Recent threats
    fun getRecentThreats(limit: Int = 50): Flow<List<ThreatEntity>> =
        threatDao.getRecentThreats(limit)

    // Malicious threats
    fun getMaliciousThreats(): Flow<List<ThreatEntity>> =
        threatDao.getMaliciousThreats()

    // Suspicious threats
    fun getSuspiciousThreats(): Flow<List<ThreatEntity>> =
        threatDao.getSuspiciousThreats()

    // Count statistics
    fun getMaliciousCount(): Flow<Int> = threatDao.getMaliciousCount()
    fun getSuspiciousCount(): Flow<Int> = threatDao.getSuspiciousCount()

    // Calculate SHA256 hash of file
    suspend fun calculateFileHash(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    // Check file with VirusTotal (hash only - privacy first)
    suspend fun checkFileWithVirusTotal(filePath: String): Result<ThreatEntity?> = try {
        val file = File(filePath)
        if (!file.exists()) {
            return Result.failure(Exception("File not found: $filePath"))
        }

        // Check cache first
        val hash = calculateFileHash(file)
        val cached = threatDao.getThreatByHash(hash)
        if (cached != null) {
            Timber.d("Cache hit for file: $filePath")
            return Result.success(cached)
        }

        // Query VirusTotal API with hash only (privacy-first approach)
        val response = virusTotalApi.getFileAnalysis(hash, apiKey)
        val fileAnalysis = response.data
        val stats = fileAnalysis?.attributes?.lastAnalysisStats

        if (stats != null && (stats.malicious > 0 || stats.suspicious > 0)) {
            val threatLevel = when {
                stats.malicious > 0 -> "MALICIOUS"
                stats.suspicious > 0 -> "SUSPICIOUS"
                else -> "CLEAN"
            }

            val threat = ThreatEntity(
                filePath = filePath,
                fileName = file.name,
                fileSize = file.length(),
                fileHash = hash,
                threatName = "VT_Detection",
                threatLevel = threatLevel,
                detectedBy = "VirusTotal",
                confidence = (stats.malicious.toFloat() / 70).coerceIn(0f, 1f),
                detectionTimestamp = LocalDateTime.now(),
                scanId = UUID.randomUUID().toString()
            )

            threatDao.insertThreat(threat)
            Result.success(threat)
        } else {
            Result.success(null) // Clean file
        }
    } catch (e: Exception) {
        Timber.e(e, "Error checking file with VirusTotal")
        Result.failure(e)
    }

    // Check URL with VirusTotal
    suspend fun checkUrlWithVirusTotal(url: String): Result<UrlScanEntity?> = try {
        // Simple base64-like encoding of URL to create ID (VirusTotal expects this)
        val urlId = java.util.Base64.getUrlEncoder().encodeToString(url.toByteArray())
            .trimEnd('=') // Remove padding

        val response = virusTotalUrlApi.getUrlAnalysis(urlId, apiKey)
        val urlAnalysis = response.data
        val stats = urlAnalysis?.attributes?.lastAnalysisStats

        if (stats != null && (stats.malicious > 0 || stats.suspicious > 0)) {
            val threatLevel = when {
                stats.malicious > 0 -> "MALICIOUS"
                stats.suspicious > 0 -> "SUSPICIOUS"
                else -> "CLEAN"
            }

            val urlScan = UrlScanEntity(
                url = url,
                threatLevel = threatLevel,
                threatDescription = if (stats.malicious > 0) "Malware detected" else "Suspicious content",
                detectionCount = stats.malicious + stats.suspicious,
                scanTime = LocalDateTime.now(),
                sourceEngine = "VirusTotal"
            )

            urlScanDao.insertUrlScan(urlScan)
            Result.success(urlScan)
        } else {
            Result.success(null) // Safe URL
        }
    } catch (e: Exception) {
        Timber.e(e, "Error checking URL with VirusTotal")
        Result.failure(e)
    }

    // Save threat to database
    suspend fun saveThreat(threat: ThreatEntity) {
        threatDao.insertThreat(threat)
    }

    // Save multiple threats
    suspend fun saveThreats(threats: List<ThreatEntity>) {
        threatDao.insertThreats(threats)
    }

    // Delete threat
    suspend fun deleteThreat(threatId: Long) {
        threatDao.deleteThreatById(threatId)
    }

    // Quarantine threat
    suspend fun quarantineThreat(threatId: Long, quarantineLocation: String) {
        threatDao.updateQuarantineStatus(threatId, true, quarantineLocation)
    }
}
