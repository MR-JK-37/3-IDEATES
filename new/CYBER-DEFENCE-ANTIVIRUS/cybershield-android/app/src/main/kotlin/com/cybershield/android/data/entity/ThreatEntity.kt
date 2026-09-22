// cybershield-android/app/src/main/kotlin/com/cybershield/android/data/entity/ThreatEntity.kt
package com.cybershield.android.data.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.time.LocalDateTime

@Entity(tableName = "threats")
data class ThreatEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val filePath: String,
    val fileName: String,
    val fileSize: Long,
    val fileHash: String, // SHA256
    val threatName: String,
    val threatLevel: String, // CLEAN, SUSPICIOUS, MALICIOUS
    val detectedBy: String, // Engine name (ClamAV, YARA, VirusTotal, Heuristics)
    val confidence: Float,
    val detectionTimestamp: LocalDateTime,
    val scanId: String,
    val isQuarantined: Boolean = false,
    val quarantineLocation: String? = null
)

@Entity(tableName = "scan_results")
data class ScanResultEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val scanId: String, // Unique scan identifier
    val scanType: String, // FILE, DIRECTORY, URL, APK
    val targetPath: String,
    val startTime: LocalDateTime,
    val endTime: LocalDateTime,
    val totalFiles: Int,
    val totalThreatsFound: Int,
    val totalSuspicious: Int,
    val totalMalicious: Int,
    val scanStatus: String // PENDING, IN_PROGRESS, COMPLETED, FAILED
)

@Entity(tableName = "url_scans")
data class UrlScanEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val threatLevel: String,
    val threatDescription: String?,
    val detectionCount: Int,
    val scanTime: LocalDateTime,
    val sourceEngine: String // VirusTotal, URLhaus, etc.
)

@Entity(tableName = "settings")
data class SettingsEntity(
    @PrimaryKey
    val key: String,
    val value: String
)
