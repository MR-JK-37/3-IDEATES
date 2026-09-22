package com.cyberdefense

import android.os.FileObserver
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.Arguments
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.io.File

/**
 * File Monitor Native Module
 * Monitors file system events using Android FileObserver
 */
class FileMonitorModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private var fileObserver: FileObserver? = null

    override fun getName(): String {
        return "FileMonitorModule"
    }

    /**
     * Start monitoring a directory
     */
    @ReactMethod
    fun startWatching(path: String, promise: Promise) {
        try {
            val directory = File(path)
            if (!directory.exists() || !directory.isDirectory) {
                promise.reject("INVALID_PATH", "Directory does not exist: $path")
                return
            }

            fileObserver = object : FileObserver(directory.absolutePath, ALL_EVENTS) {
                override fun onEvent(event: Int, path: String?) {
                    val eventMap: WritableMap = Arguments.createMap()
                    eventMap.putString("path", path)
                    
                    when (event and ALL_EVENTS) {
                        CREATE -> {
                            eventMap.putString("type", "CREATE")
                            sendEvent("FileEvent", eventMap)
                        }
                        MODIFY -> {
                            eventMap.putString("type", "MODIFY")
                            sendEvent("FileEvent", eventMap)
                        }
                        DELETE -> {
                            eventMap.putString("type", "DELETE")
                            sendEvent("FileEvent", eventMap)
                        }
                    }
                }
            }

            fileObserver?.startWatching()
            promise.resolve(true)
        } catch (e: Exception) {
            promise.reject("FILE_OBSERVER_ERROR", "Failed to start file observer", e)
        }
    }

    /**
     * Stop monitoring
     */
    @ReactMethod
    fun stopWatching(promise: Promise) {
        try {
            fileObserver?.stopWatching()
            fileObserver = null
            promise.resolve(true)
        } catch (e: Exception) {
            promise.reject("FILE_OBSERVER_ERROR", "Failed to stop file observer", e)
        }
    }

    /**
     * Scan for APK files in a directory
     */
    @ReactMethod
    fun scanForAPKs(path: String, promise: Promise) {
        try {
            val directory = File(path)
            val apkFiles = mutableListOf<WritableMap>()

            if (directory.exists() && directory.isDirectory) {
                scanDirectoryForAPKs(directory, apkFiles)
            }

            val result = Arguments.createArray()
            apkFiles.forEach { result.pushMap(it) }
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("APK_SCAN_ERROR", "Failed to scan for APKs", e)
        }
    }

    /**
     * Recursively scan directory for APK files
     */
    private fun scanDirectoryForAPKs(directory: File, apkFiles: MutableList<WritableMap>) {
        try {
            directory.listFiles()?.forEach { file ->
                if (file.isDirectory) {
                    scanDirectoryForAPKs(file, apkFiles)
                } else if (file.name.endsWith(".apk", ignoreCase = true)) {
                    val apkMap: WritableMap = Arguments.createMap()
                    apkMap.putString("path", file.absolutePath)
                    apkMap.putDouble("size", file.length().toDouble())
                    apkFiles.add(apkMap)
                }
            }
        } catch (e: Exception) {
            // Ignore permission errors
        }
    }

    /**
     * Send event to React Native
     */
    private fun sendEvent(eventName: String, params: WritableMap?) {
        reactApplicationContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(eventName, params)
    }
}
