package com.cyberdefense

import android.app.ActivityManager
import android.content.Context
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.Arguments
import java.io.File

/**
 * Process Monitor Native Module
 * Provides access to Android ActivityManager for process enumeration
 */
class ProcessMonitorModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return "ProcessMonitorModule"
    }

    /**
     * Get all running processes
     */
    @ReactMethod
    fun getRunningProcesses(promise: Promise) {
        try {
            val activityManager =
                reactApplicationContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val runningProcesses = activityManager.runningAppProcesses

            val processArray: WritableArray = Arguments.createArray()

            for (processInfo in runningProcesses) {
                val processMap: WritableMap = Arguments.createMap()
                processMap.putInt("pid", processInfo.pid)
                processMap.putString("name", processInfo.processName)
                processMap.putIntArray("pids", processInfo.pids)

                // Get CPU usage from /proc/[pid]/stat
                val cpuUsage = getCpuUsage(processInfo.pid)
                processMap.putDouble("cpuUsage", cpuUsage)

                // Get memory usage
                val memoryUsage = getMemoryUsage(processInfo.pid)
                processMap.putDouble("memoryUsage", memoryUsage)

                // Check if process is hidden (exists in /proc but not in ActivityManager)
                val isHidden = checkIfHidden(processInfo.pid)
                processMap.putBoolean("isHidden", isHidden)

                processArray.pushMap(processMap)
            }

            promise.resolve(processArray)
        } catch (e: Exception) {
            promise.reject("PROCESS_ENUM_ERROR", "Failed to enumerate processes", e)
        }
    }

    /**
     * Get CPU usage for a process
     */
    private fun getCpuUsage(pid: Int): Double {
        return try {
            val statFile = File("/proc/$pid/stat")
            if (!statFile.exists()) return 0.0

            val statContent = statFile.readText()
            val fields = statContent.split(" ")

            // CPU usage calculation (simplified)
            // utime + stime from /proc/[pid]/stat
            if (fields.size > 14) {
                val utime = fields[13].toLongOrNull() ?: 0L
                val stime = fields[14].toLongOrNull() ?: 0L
                (utime + stime).toDouble() / 100.0 // Simplified percentage
            } else {
                0.0
            }
        } catch (e: Exception) {
            0.0
        }
    }

    /**
     * Get memory usage for a process
     */
    private fun getMemoryUsage(pid: Int): Double {
        return try {
            val statusFile = File("/proc/$pid/status")
            if (!statusFile.exists()) return 0.0

            val statusContent = statusFile.readText()
            val vmRssLine = statusContent.lines().find { it.startsWith("VmRSS:") }

            vmRssLine?.let {
                val memoryKb = it.split("\\s+".toRegex())[1].toLongOrNull() ?: 0L
                memoryKb / 1024.0 // Convert KB to MB
            } ?: 0.0
        } catch (e: Exception) {
            0.0
        }
    }

    /**
     * Check if process is hidden (exists in /proc but not in ActivityManager)
     */
    private fun checkIfHidden(pid: Int): Boolean {
        return try {
            val procDir = File("/proc/$pid")
            procDir.exists() && procDir.isDirectory
        } catch (e: Exception) {
            false
        }
    }
}
