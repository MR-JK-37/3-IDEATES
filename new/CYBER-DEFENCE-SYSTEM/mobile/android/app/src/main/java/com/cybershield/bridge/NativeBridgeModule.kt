package com.cybershield.bridge

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import android.content.Intent
import android.util.Log
import androidx.room.Room
import com.cybershield.services.TelemetryService
import com.cybershield.services.FileMonitorService
import com.cybershield.db.CyberShieldDb

/**
 * React Native bridge module.
 *
 * Provides JavaScript -> Kotlin IPC for:
 * - Starting/stopping monitoring services
 * - Fetching threat events from local database
 * - Querying system status
 */
class NativeBridgeModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        private const val TAG = "CyberShield.NativeBridge"
        private const val MODULE_NAME = "CyberShieldNative"
    }

    private val db: CyberShieldDb by lazy {
        Room.databaseBuilder(
            reactContext,
            CyberShieldDb::class.java,
            "cybershield.db"
        ).build()
    }

    override fun getName(): String = MODULE_NAME

    /**
     * Start background monitoring services (telemetry + file monitor).
     */
    @ReactMethod
    fun startMonitoring(promise: Promise) {
        try {
            val intent1 = Intent(reactContext, TelemetryService::class.java)
            reactContext.startForegroundService(intent1)

            val intent2 = Intent(reactContext, FileMonitorService::class.java)
            reactContext.startService(intent2)

            Log.d(TAG, "Monitoring services started")
            promise.resolve("Monitoring started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start monitoring", e)
            promise.reject("START_ERROR", e.message)
        }
    }

    /**
     * Stop monitoring services.
     */
    @ReactMethod
    fun stopMonitoring(promise: Promise) {
        try {
            reactContext.stopService(Intent(reactContext, TelemetryService::class.java))
            reactContext.stopService(Intent(reactContext, FileMonitorService::class.java))
            Log.d(TAG, "Monitoring services stopped")
            promise.resolve("Monitoring stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop monitoring", e)
            promise.reject("STOP_ERROR", e.message)
        }
    }

    /**
     * Get recent threat events from local database (last N).
     */
    @ReactMethod
    fun getRecentThreats(limit: Int, promise: Promise) {
        try {
            val events = kotlin.runBlocking {
                db.threatEventDao().recent(limit)
            }
            val result = events.map { event ->
                mapOf(
                    "id" to event.id,
                    "timestamp" to event.timestamp.time,
                    "threatType" to event.threatType,
                    "appName" to event.appName,
                    "appPackage" to event.appPackage,
                    "severity" to event.severity,
                    "details" to event.details,
                    "mitigated" to event.mitigated
                )
            }
            promise.resolve(com.facebook.react.bridge.WritableNativeArray(result.map {
                com.facebook.react.bridge.WritableNativeMap().apply {
                    it.forEach { (k, v) ->
                        when (v) {
                            is String -> putString(k, v)
                            is Int -> putInt(k, v)
                            is Long -> putDouble(k, v.toDouble())
                            is Boolean -> putBoolean(k, v)
                        }
                    }
                }
            }))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get threats", e)
            promise.reject("QUERY_ERROR", e.message)
        }
    }

    /**
     * Get system status (monitoring active, last scan time, etc.)
     */
    @ReactMethod
    fun getSystemStatus(promise: Promise) {
        try {
            val status = mapOf(
                "monitoringActive" to true,
                "lastScan" to System.currentTimeMillis(),
                "osVersion" to android.os.Build.VERSION.SDK_INT,
                "deviceModel" to android.os.Build.MODEL
            )
            promise.resolve(status)
        } catch (e: Exception) {
            promise.reject("STATUS_ERROR", e.message)
        }
    }
}
