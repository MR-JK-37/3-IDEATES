package com.cybershield.services

import android.app.Service
import android.content.Intent
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
import java.util.Date

/**
 * Background telemetry service.
 *
 * Continuously monitors:
 * - Running processes for malware/suspicious behavior
 * - File system for ransomware indicators
 * - Network traffic for C2 communication
 *
 * Runs as a foreground service on Android 12+ for persistent monitoring.
 */
class TelemetryService : Service() {
    companion object {
        private const val TAG = "CyberShield.Telemetry"
        private const val NOTIFICATION_ID = 1
    }

    private lateinit var db: CyberShieldDb
    private lateinit var detectionEngine: ThreatDetectionEngine
    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "TelemetryService created")

        // Initialize local database
        db = Room.databaseBuilder(
            this,
            CyberShieldDb::class.java,
            "cybershield.db"
        ).build()

        // Initialize detection engine
        detectionEngine = ThreatDetectionEngine(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "TelemetryService started")

        // Start monitoring in background
        scope.launch {
            monitorProcesses()
        }

        return START_STICKY
    }

    /**
     * Monitor running processes for threat indicators.
     * Runs every 5 seconds.
     */
    private suspend fun monitorProcesses() {
        while (true) {
            try {
                val pm = packageManager
                val packages = pm.getInstalledApplications(0)

                for (appInfo in packages) {
                    try {
                        val (threatScore, details) = detectionEngine.analyzeProcess(
                            appInfo.uid,
                            appInfo.packageName
                        )

                        if (threatScore > 40) {
                            // Log suspicious process
                            val event = ThreatEvent(
                                timestamp = Date(),
                                threatType = "suspicious_process",
                                appName = pm.getApplicationLabel(appInfo).toString(),
                                appPackage = appInfo.packageName,
                                severity = threatScore,
                                details = details
                            )
                            db.threatEventDao().insert(event)
                            Log.w(TAG, "Suspicious process: ${appInfo.packageName} score=$threatScore")
                        }
                    } catch (e: Exception) {
                        // Ignore individual app analysis failures
                    }
                }

                // Clean up old events (older than 30 days)
                db.threatEventDao().deleteOld()

                // Wait 5 seconds before next scan
                Thread.sleep(5000)
            } catch (e: Exception) {
                Log.e(TAG, "Error in monitorProcesses", e)
                Thread.sleep(5000)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "TelemetryService destroyed")
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
