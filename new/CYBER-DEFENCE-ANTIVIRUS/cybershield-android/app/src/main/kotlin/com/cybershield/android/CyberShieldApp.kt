// cybershield-android/app/src/main/kotlin/com/cybershield/android/CyberShieldApp.kt
package com.cybershield.android

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import timber.log.Timber

@HiltAndroidApp
class CyberShieldApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize Timber logging
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        } else {
            // In production, plant a crash reporting tree
            Timber.plant(object : Timber.Tree() {
                override fun log(
                    priority: Int,
                    tag: String?,
                    message: String,
                    t: Throwable?
                ) {
                    // Send to crash reporting service
                    // e.g., Firebase Crashlytics
                }
            })
        }

        Timber.d("CyberShield application initialized")
    }
}
