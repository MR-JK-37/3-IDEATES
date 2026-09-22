package com.cybershield

import android.app.Application
import android.content.Context
import android.util.Log

/**
 * Application class for CyberShield.
 *
 * Initializes global state and telemetry on app startup.
 */
class CyberShieldApp : Application() {
    companion object {
        private const val TAG = "CyberShield.App"
        lateinit var instance: Context
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        Log.d(TAG, "CyberShield app initialized")
    }
}
