package com.cybershield.services

import android.app.Service
import android.content.Intent
import android.os.FileObserver
import android.os.IBinder
import android.util.Log
import androidx.room.Room
import com.cybershield.db.CyberShieldDb
import com.cybershield.db.ThreatEvent
import com.cybershield.detection.ThreatDetectionEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancel
import java.io.File
import java.util.Collections
import java.util.Date

/**
 * File monitor service.
 *
 * Watches key directories (Downloads, Documents, cache) for:
 * - Rapid mass file modifications (ransomware behavior)
 * - High-entropy writes (encryption detection)
 * - Suspicious file extensions
 *
 * Uses Android FileObserver API for efficiency.
 */
class FileMonitorService : Service() {
    companion object {
        private const val TAG = "CyberShield.FileMonitor"
    }

    private lateinit var db: CyberShieldDb
    private lateinit var detectionEngine: ThreatDetectionEngine
    private val observers = mutableListOf<FileObserver>()
    private val scope = CoroutineScope(Dispatchers.IO)

    // Track recent file modifications for mass-mod detection
    private val recentModifications = Collections.synchronizedList(mutableListOf<Long>())

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "FileMonitorService created")

        db = Room.databaseBuilder(
            this,
            CyberShieldDb::class.java,
            "cybershield.db"
        ).build()

        detectionEngine = ThreatDetectionEngine(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "FileMonitorService started")

        // Monitor critical directories
        val dirsToWatch = listOf(
            "${getExternalFilesDir(null)?.parent}/Downloads",
            "${getExternalFilesDir(null)?.parent}/Documents",
            cacheDir.absolutePath
        ).mapNotNull { path ->
            if (path != null && File(path).exists()) path else null
        }

        for (dirPath in dirsToWatch) {
            val observer = createFileObserver(dirPath)
            observer.startWatching()
            observers.add(observer)
            Log.d(TAG, "Started watching $dirPath")
        }

        return START_STICKY
    }

    private fun createFileObserver(path: String): FileObserver {
        return object : FileObserver(path, ALL_EVENTS) {
            override fun onEvent(event: Int, filename: String?) {
                when (event) {
                    CREATE, MODIFY -> {
                        filename?.let { fname ->
                            val file = File(path, fname)
                            if (file.isFile) {
                                // Record modification timestamp
                                recentModifications.add(System.currentTimeMillis())

                                // Check for mass modification (>50 in 10s)
                                val isMassMod = detectionEngine.detectMassModification(recentModifications)
                                if (isMassMod) {
                                    Log.w(TAG, "MASS MODIFICATION DETECTED")
                                    scope.launch {
                                        val event = ThreatEvent(
                                            timestamp = Date(),
                                            threatType = "ransomware",
                                            appName = "File System",
                                            appPackage = "",
                                            severity = 90,
                                            details = "Mass file modification detected (>50 files/10s)"
                                        )
                                        db.threatEventDao().insert(event)
                                    }
                                }

                                // Analyze individual file
                                val (threatScore, details) = detectionEngine.analyzeFile(file)
                                if (threatScore > 50) {
                                    Log.w(TAG, "Suspicious file: $fname score=$threatScore")
                                    scope.launch {
                                        val evt = ThreatEvent(
                                            timestamp = Date(),
                                            threatType = "suspicious_file",
                                            appName = "File System",
                                            appPackage = "",
                                            severity = threatScore,
                                            details = details
                                        )
                                        db.threatEventDao().insert(evt)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "FileMonitorService destroyed")
        observers.forEach { it.stopWatching() }
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
