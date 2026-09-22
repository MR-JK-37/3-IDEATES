// cybershield-android/app/src/main/kotlin/com/cybershield/android/service/ScannerService.kt
package com.cybershield.android.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.work.BackgroundExecutor
import androidx.work.WorkManager
import com.cybershield.android.MainActivity
import com.cybershield.android.R
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import timber.log.Timber
import java.io.File
import javax.inject.Inject

@AndroidEntryPoint
class ScannerService : Service() {

    companion object {
        private const val CHANNEL_ID = "cybershield_scan_channel"
        private const val NOTIFICATION_ID = 1001
        const val ACTION_SCAN_FILE = "com.cybershield.android.action.SCAN_FILE"
        const val ACTION_SCAN_DIR = "com.cybershield.android.action.SCAN_DIR"
        const val ACTION_STOP_SCAN = "com.cybershield.android.action.STOP_SCAN"
        const val EXTRA_PATH = "scan_path"
    }

    private var isScanRunning = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        Timber.d("ScannerService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.let {
            when (it.action) {
                ACTION_SCAN_FILE -> {
                    val filePath = it.getStringExtra(EXTRA_PATH)
                    if (filePath != null) {
                        scanFile(filePath)
                    }
                }
                ACTION_SCAN_DIR -> {
                    val dirPath = it.getStringExtra(EXTRA_PATH)
                    if (dirPath != null) {
                        scanDirectory(dirPath)
                    }
                }
                ACTION_STOP_SCAN -> {
                    stopScan()
                }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun scanFile(filePath: String) {
        if (isScanRunning) {
            Timber.w("Scan already running")
            return
        }

        isScanRunning = true
        updateNotification("Scanning file: $filePath", 0, true)

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val file = File(filePath)
                if (!file.exists()) {
                    updateNotification("File not found: $filePath", 100, false)
                    isScanRunning = false
                    return@launch
                }

                Timber.d("Starting scan for file: $filePath")

                // Simulate scanning - in real implementation, call scanner API
                Thread.sleep(2000)

                updateNotification("Scan completed for: ${file.name}", 100, false)
                isScanRunning = false
            } catch (e: Exception) {
                Timber.e(e, "Error during file scan")
                updateNotification("Scan error: ${e.message}", 100, false)
                isScanRunning = false
            }
        }
    }

    private fun scanDirectory(dirPath: String) {
        if (isScanRunning) {
            Timber.w("Scan already running")
            return
        }

        isScanRunning = true
        updateNotification("Scanning directory: $dirPath", 0, true)

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val directory = File(dirPath)
                if (!directory.isDirectory) {
                    updateNotification("Invalid directory: $dirPath", 100, false)
                    isScanRunning = false
                    return@launch
                }

                val files = directory.walkTopDown().filter { it.isFile }.toList()
                Timber.d("Found ${files.size} files to scan in $dirPath")

                files.forEachIndexed { index, file ->
                    if (!isScanRunning) return@forEachIndexed

                    val progress = ((index + 1) * 100) / files.size
                    updateNotification(
                        "Scanning: ${file.name}",
                        progress,
                        true
                    )

                    // Simulate scanning each file
                    Thread.sleep(500)
                }

                updateNotification("Scan completed: ${files.size} files scanned", 100, false)
                isScanRunning = false
            } catch (e: Exception) {
                Timber.e(e, "Error during directory scan")
                updateNotification("Scan error: ${e.message}", 100, false)
                isScanRunning = false
            }
        }
    }

    private fun stopScan() {
        Timber.d("Stopping scan")
        isScanRunning = false
        updateNotification("Scan stopped", 100, false)
    }

    private fun updateNotification(title: String, progress: Int, isIndeterminate: Boolean) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText("Progress: $progress%")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setProgress(100, progress, isIndeterminate)
            .setOnlyAlertOnce(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this,
                    0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or
                            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                PendingIntent.FLAG_IMMUTABLE
                            } else 0)
                )
            )
            .build()

        val notificationManager =
            getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)

        if (!isIndeterminate) {
            // Auto-dismiss after showing
            Thread {
                Thread.sleep(3000)
                notificationManager.cancel(NOTIFICATION_ID)
            }.start()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CyberShield Scanner",
                NotificationManager.IMPORTANCE_HIGH
            )
            channel.description = "Notifications for file scanning operations"
            val notificationManager =
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}
