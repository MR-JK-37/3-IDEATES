// cybershield-android/app/src/main/kotlin/com/cybershield/android/data/dao/ThreatDao.kt
package com.cybershield.android.data.dao

import androidx.room.*
import com.cybershield.android.data.entity.ScanResultEntity
import com.cybershield.android.data.entity.ThreatEntity
import com.cybershield.android.data.entity.UrlScanEntity
import kotlinx.coroutines.flow.Flow
import java.time.LocalDateTime

@Dao
interface ThreatDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(threat: ThreatEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreats(threats: List<ThreatEntity>)

    @Query("SELECT * FROM threats ORDER BY detectionTimestamp DESC LIMIT :limit")
    fun getRecentThreats(limit: Int = 50): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE threatLevel = 'MALICIOUS' ORDER BY detectionTimestamp DESC")
    fun getMaliciousThreats(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE threatLevel = 'SUSPICIOUS' ORDER BY detectionTimestamp DESC")
    fun getSuspiciousThreats(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE fileHash = :hash LIMIT 1")
    suspend fun getThreatByHash(hash: String): ThreatEntity?

    @Query("SELECT * FROM threats WHERE scanId = :scanId")
    fun getThreatsForScan(scanId: String): Flow<List<ThreatEntity>>

    @Query("SELECT COUNT(*) FROM threats WHERE threatLevel = 'MALICIOUS'")
    fun getMaliciousCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM threats WHERE threatLevel = 'SUSPICIOUS'")
    fun getSuspiciousCount(): Flow<Int>

    @Delete
    suspend fun deleteThreat(threat: ThreatEntity)

    @Query("DELETE FROM threats WHERE id = :id")
    suspend fun deleteThreatById(id: Long)

    @Query("UPDATE threats SET isQuarantined = :quarantined, quarantineLocation = :location WHERE id = :id")
    suspend fun updateQuarantineStatus(id: Long, quarantined: Boolean, location: String?)
}

@Dao
interface ScanResultDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScanResult(result: ScanResultEntity)

    @Query("SELECT * FROM scan_results ORDER BY startTime DESC LIMIT :limit")
    fun getRecentScans(limit: Int = 20): Flow<List<ScanResultEntity>>

    @Query("SELECT * FROM scan_results WHERE scanId = :scanId LIMIT 1")
    suspend fun getScanResult(scanId: String): ScanResultEntity?

    @Query("SELECT * FROM scan_results WHERE scanStatus = 'COMPLETED' ORDER BY startTime DESC")
    fun getCompletedScans(): Flow<List<ScanResultEntity>>

    @Update
    suspend fun updateScanResult(result: ScanResultEntity)

    @Delete
    suspend fun deleteScanResult(result: ScanResultEntity)
}

@Dao
interface UrlScanDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUrlScan(urlScan: UrlScanEntity)

    @Query("SELECT * FROM url_scans ORDER BY scanTime DESC LIMIT :limit")
    fun getRecentUrlScans(limit: Int = 50): Flow<List<UrlScanEntity>>

    @Query("SELECT * FROM url_scans WHERE url = :url LIMIT 1")
    suspend fun getUrlScan(url: String): UrlScanEntity?

    @Query("SELECT * FROM url_scans WHERE threatLevel IN ('SUSPICIOUS', 'MALICIOUS') ORDER BY scanTime DESC")
    fun getMaliciousUrls(): Flow<List<UrlScanEntity>>

    @Delete
    suspend fun deleteUrlScan(urlScan: UrlScanEntity)
}

@Dao
interface SettingsDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSetting(setting: com.cybershield.android.data.entity.SettingsEntity)

    @Query("SELECT value FROM settings WHERE key = :key LIMIT 1")
    suspend fun getSetting(key: String): String?

    @Query("SELECT value FROM settings WHERE key = :key LIMIT 1")
    fun getSettingFlow(key: String): Flow<String?>

    @Update
    suspend fun updateSetting(setting: com.cybershield.android.data.entity.SettingsEntity)

    @Query("DELETE FROM settings WHERE key = :key")
    suspend fun deleteSetting(key: String)
}
