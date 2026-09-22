// cybershield-android/app/src/main/kotlin/com/cybershield/android/data/db/CyberShieldDatabase.kt
package com.cybershield.android.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.cybershield.android.data.dao.SettingsDao
import com.cybershield.android.data.dao.ScanResultDao
import com.cybershield.android.data.dao.ThreatDao
import com.cybershield.android.data.dao.UrlScanDao
import com.cybershield.android.data.entity.ScanResultEntity
import com.cybershield.android.data.entity.SettingsEntity
import com.cybershield.android.data.entity.ThreatEntity
import com.cybershield.android.data.entity.UrlScanEntity

@Database(
    entities = [
        ThreatEntity::class,
        ScanResultEntity::class,
        UrlScanEntity::class,
        SettingsEntity::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class CyberShieldDatabase : RoomDatabase() {
    abstract fun threatDao(): ThreatDao
    abstract fun scanResultDao(): ScanResultDao
    abstract fun urlScanDao(): UrlScanDao
    abstract fun settingsDao(): SettingsDao

    companion object {
        @Volatile
        private var INSTANCE: CyberShieldDatabase? = null

        fun getDatabase(context: Context): CyberShieldDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    CyberShieldDatabase::class.java,
                    "cybershield_db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}

// Type converters for LocalDateTime
import androidx.room.TypeConverter
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

object Converters {
    private val formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME

    @TypeConverter
    fun fromLocalDateTime(value: LocalDateTime?): String? {
        return value?.format(formatter)
    }

    @TypeConverter
    fun toLocalDateTime(value: String?): LocalDateTime? {
        return value?.let {
            LocalDateTime.parse(it, formatter)
        }
    }
}
