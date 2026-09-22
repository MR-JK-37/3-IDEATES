package com.cybershield.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.cybershield.services.TelemetryService
import com.cybershield.services.FileMonitorService

/**
 * Boot receiver: starts CyberShield monitoring services on device boot.
 *
 * Ensures telemetry and file monitoring are running even if the app wasn't
 * explicitly opened by the user.
 */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "CyberShield.BootReceiver"
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.d(TAG, "Boot completed, starting CyberShield services")

            context?.let {
                // Start telemetry service
                val telemetryIntent = Intent(it, TelemetryService::class.java)
                it.startForegroundService(telemetryIntent)

                // Start file monitor service
                val fileMonitorIntent = Intent(it, FileMonitorService::class.java)
                it.startService(fileMonitorIntent)
            }
        }
    }
}
