package com.cybershield.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import java.util.Date

/**
 * Local threat event database (Room).
 *
 * Stores detected threats, behavioral events, and telemetry for offline forensic analysis.
 * Auto-deletes events older than 30 days to conserve storage.
 */
@Database(
    entities = [ThreatEvent::class, BehaviorLog::class],
    version = 1,
    exportSchema = false
)
@TypeConverters(DateConverter::class)
abstract class CyberShieldDb : RoomDatabase() {
    abstract fun threatEventDao(): ThreatEventDao
    abstract fun behaviorLogDao(): BehaviorLogDao
}

/**
 * Detected threat event (ransomware, malware, phishing, etc.)
 */
@androidx.room.Entity(tableName = "threat_events")
data class ThreatEvent(
    @androidx.room.PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Date,
    val threatType: String, // "ransomware", "malware", "phishing", "data_exfiltration"
    val appName: String,
    val appPackage: String,
    val severity: Int, // 0-100 threat score
    val details: String, // JSON blob with details
    val mitigated: Boolean = false
)

/**
 * Behavioral event log for process/network activity.
 */
@androidx.room.Entity(tableName = "behavior_logs")
data class BehaviorLog(
    @androidx.room.PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Date,
    val eventType: String, // "process_create", "file_modify", "network_connect", etc.
    val sourceProcess: String,
    val targetResource: String,
    val riskScore: Int // 0-100
)

/**
 * DAO for threat events.
 */
@androidx.room.Dao
interface ThreatEventDao {
    @androidx.room.Insert
    suspend fun insert(event: ThreatEvent): Long

    @androidx.room.Query("SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT :limit")
    suspend fun recent(limit: Int = 100): List<ThreatEvent>

    @androidx.room.Query("DELETE FROM threat_events WHERE timestamp < datetime('now', '-30 days')")
    suspend fun deleteOld()
}

/**
 * DAO for behavior logs.
 */
@androidx.room.Dao
interface BehaviorLogDao {
    @androidx.room.Insert
    suspend fun insert(log: BehaviorLog): Long

    @androidx.room.Query("SELECT * FROM behavior_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun recent(limit: Int = 100): List<BehaviorLog>
}

/**
 * Type converter for java.util.Date ↔ Long (milliseconds since epoch).
 */
class DateConverter {
    @androidx.room.TypeConverter
    fun fromDate(value: Date?): Long? = value?.time

    @androidx.room.TypeConverter
    fun toDate(value: Long?): Date? = value?.let { Date(it) }
}
