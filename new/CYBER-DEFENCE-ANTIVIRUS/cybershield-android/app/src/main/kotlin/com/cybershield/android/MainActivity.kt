// cybershield-android/app/src/main/kotlin/com/cybershield/android/MainActivity.kt
package com.cybershield.android

import android.os.Bundle
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.cybershield.android.databinding.ActivityMainBinding
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var appBarConfiguration: AppBarConfiguration

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Setup toolbar
        setSupportActionBar(binding.toolbar)

        // Setup bottom navigation
        val navController = findNavController(R.id.nav_host_fragment)
        val bottomNav: BottomNavigationView = binding.bottomNavigation

        appBarConfiguration = AppBarConfiguration(
            setOf(
                R.id.nav_dashboard,
                R.id.nav_scanner,
                R.id.nav_url_scanner,
                R.id.nav_threats,
                R.id.nav_settings
            )
        )

        setupActionBarWithNavController(navController, appBarConfiguration)
        bottomNav.setupWithNavController(navController)

        // Request permissions
        requestRequiredPermissions()
    }

    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment)
        return navController.navigateUp(appBarConfiguration) || super.onSupportNavigateUp()
    }

    private fun requestRequiredPermissions() {
        val requiredPermissions = mutableListOf<String>()

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            requiredPermissions.add(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            requiredPermissions.add(android.Manifest.permission.MANAGE_EXTERNAL_STORAGE)
        } else {
            requiredPermissions.add(android.Manifest.permission.READ_EXTERNAL_STORAGE)
            requiredPermissions.add(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }

        if (requiredPermissions.isNotEmpty()) {
            androidx.core.app.ActivityCompat.requestPermissions(
                this,
                requiredPermissions.toTypedArray(),
                PERMISSION_REQUEST_CODE
            )
        }
    }

    companion object {
        private const val PERMISSION_REQUEST_CODE = 100
    }
}
