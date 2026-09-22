package com.cybershield

import android.os.Bundle
import android.content.Intent
import android.util.Log
import com.facebook.react.ReactActivity
import com.cybershield.services.TelemetryService
import com.cybershield.services.FileMonitorService

/**
 * Main Activity for CyberShield React Native app.
 *
 * Handles:
 * - Initializing native bridges
 * - Starting background monitoring services
 * - Requesting necessary runtime permissions
 */
class MainActivity : ReactActivity() {
    companion object {
        private const val TAG = "CyberShield.MainActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d(TAG, "MainActivity created")

        // Start background monitoring services
        startMonitoringServices()

        // Request runtime permissions (handled by React Native)
    }

    override fun onResume() {
        super.onResume()
        Log.d(TAG, "MainActivity resumed")
        // Ensure services are still running
        startMonitoringServices()
    }

    private fun startMonitoringServices() {
        try {
            val telemetryIntent = Intent(this, TelemetryService::class.java)
            startForegroundService(telemetryIntent)

            val fileMonitorIntent = Intent(this, FileMonitorService::class.java)
            startService(fileMonitorIntent)
            Log.d(TAG, "Background services started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start background services", e)
        }
    }

    override fun getMainComponentName(): String? {
        return "CyberShieldRN"
    }
}
