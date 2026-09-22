// cybershield-android/app/src/main/kotlin/com/cybershield/android/ui/viewmodel/ScannerViewModel.kt
package com.cybershield.android.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybershield.android.data.entity.ScanResultEntity
import com.cybershield.android.data.entity.ThreatEntity
import com.cybershield.android.data.repository.ThreatRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import java.io.File
import java.time.LocalDateTime
import java.util.UUID
import javax.inject.Inject

data class ScanState(
    val isScanning: Boolean = false,
    val scanProgress: Int = 0,
    val currentFile: String = "",
    val totalFiles: Int = 0,
    val threatsFound: Int = 0,
    val suspiciousFound: Int = 0,
    val maliciousFound: Int = 0,
    val scanError: String? = null
)

@HiltViewModel
class ScannerViewModel @Inject constructor(
    private val threatRepository: ThreatRepository
) : ViewModel() {

    private val _scanState = MutableStateFlow(ScanState())
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    private val _threatsFound = MutableStateFlow<List<ThreatEntity>>(emptyList())
    val threatsFound: StateFlow<List<ThreatEntity>> = _threatsFound.asStateFlow()

    fun scanFile(filePath: String) {
        viewModelScope.launch {
            try {
                _scanState.value = ScanState(isScanning = true, currentFile = filePath)

                val result = threatRepository.checkFileWithVirusTotal(filePath)
                result.onSuccess { threat ->
                    if (threat != null) {
                        _threatsFound.value = _threatsFound.value + threat
                        _scanState.value = _scanState.value.copy(
                            threatsFound = _threatsFound.value.size,
                            maliciousFound = if (threat.threatLevel == "MALICIOUS") {
                                _scanState.value.maliciousFound + 1
                            } else _scanState.value.maliciousFound,
                            suspiciousFound = if (threat.threatLevel == "SUSPICIOUS") {
                                _scanState.value.suspiciousFound + 1
                            } else _scanState.value.suspiciousFound
                        )
                    }
                }
                result.onFailure { error ->
                    _scanState.value = _scanState.value.copy(
                        scanError = error.message ?: "Unknown error"
                    )
                    Timber.e(error, "Scan error for file: $filePath")
                }

                _scanState.value = _scanState.value.copy(isScanning = false)
            } catch (e: Exception) {
                _scanState.value = _scanState.value.copy(
                    isScanning = false,
                    scanError = e.message ?: "Scan failed"
                )
                Timber.e(e, "Error scanning file")
            }
        }
    }

    fun scanDirectory(dirPath: String) {
        viewModelScope.launch {
            try {
                val directory = File(dirPath)
                if (!directory.isDirectory) {
                    _scanState.value = _scanState.value.copy(
                        scanError = "Invalid directory path"
                    )
                    return@launch
                }

                val files = directory.walkTopDown().filter { it.isFile }.toList()
                val scanId = UUID.randomUUID().toString()
                var threatsCount = 0

                _scanState.value = ScanState(
                    isScanning = true,
                    totalFiles = files.size
                )

                files.forEachIndexed { index, file ->
                    _scanState.value = _scanState.value.copy(
                        currentFile = file.absolutePath,
                        scanProgress = ((index + 1) * 100) / files.size
                    )

                    val result = threatRepository.checkFileWithVirusTotal(file.absolutePath)
                    result.onSuccess { threat ->
                        if (threat != null) {
                            threatsCount++
                            _threatsFound.value = _threatsFound.value + threat
                        }
                    }
                }

                _scanState.value = _scanState.value.copy(
                    isScanning = false,
                    threatsFound = threatsCount
                )
            } catch (e: Exception) {
                _scanState.value = _scanState.value.copy(
                    isScanning = false,
                    scanError = e.message ?: "Directory scan failed"
                )
                Timber.e(e, "Error scanning directory")
            }
        }
    }

    fun clearThreats() {
        _threatsFound.value = emptyList()
        _scanState.value = ScanState()
    }
}
