package io.iocscanner

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import io.iocscanner.data.IocRepository
import io.iocscanner.data.SettingsStore
import io.iocscanner.data.Severity
import io.iocscanner.data.SubjectType
import io.iocscanner.report.ReportExporter
import io.iocscanner.scanners.DevicePropertiesScanner
import io.iocscanner.scanners.NetworkScanner
import io.iocscanner.scanners.PackageScanner
import io.iocscanner.scanners.PersistenceScanner
import io.iocscanner.scanners.ProxywareScanner
import io.iocscanner.vt.VirusTotalClient
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    data class UiState(
        val ready: Boolean = false,
        val scanning: Boolean = false,
        val statusText: String = "",
        val findings: List<Finding> = emptyList(),
        val scanCompletedAt: String? = null,
        val iocDbName: String = "",
        val iocDbVersion: Int = 0,
        val iocDbUpdated: String = "",
        val iocCount: Int = 0,
        val vtKeySet: Boolean = false,
        val vtInProgress: Boolean = false,
        val vtProgress: String = "",
        val iocUpdateUrl: String = "",
        val iocUpdateStatus: String = "",
        val exportStatus: String = "",
    )

    private val repo = IocRepository(app)
    private val settings = SettingsStore(app)
    private var iocs: IocIndex? = null
    private var vtJob: Job? = null

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val index = try {
                repo.load()
            } catch (e: Exception) {
                null
            }
            iocs = index
            _state.update {
                applyDbInfo(it, index).copy(
                    ready = index != null,
                    vtKeySet = settings.vtApiKey.isNotBlank(),
                    iocUpdateUrl = settings.iocUpdateUrl,
                    statusText = if (index == null) "Failed to load IOC database" else "",
                )
            }
        }
    }

    private fun applyDbInfo(state: UiState, index: IocIndex?): UiState {
        index ?: return state
        return state.copy(
            iocDbName = index.db.name,
            iocDbVersion = index.db.version,
            iocDbUpdated = index.db.updated,
            iocCount = index.db.entries.size,
        )
    }

    fun startScan() {
        if (_state.value.scanning) return
        val index = iocs ?: return
        viewModelScope.launch {
            _state.update {
                it.copy(
                    scanning = true,
                    findings = emptyList(),
                    exportStatus = "",
                    vtProgress = "",
                    statusText = "Starting scan…",
                )
            }
            // Fast scanners first so findings appear early; the package
            // scanner hashes every APK and can take minutes on box firmware.
            val scanners = listOf(
                DevicePropertiesScanner(),
                NetworkScanner(),
                PersistenceScanner(),
                ProxywareScanner(),
                PackageScanner(),
            )
            val all = mutableListOf<Finding>()
            for (scanner in scanners) {
                _state.update { it.copy(statusText = "Scanning: ${scanner.name}…") }
                val result = try {
                    scanner.scan(getApplication(), index)
                } catch (e: Exception) {
                    listOf(
                        Finding(
                            scanner = scanner.name,
                            severity = Severity.INFO,
                            title = "Scanner failed",
                            subject = scanner.name,
                            subjectType = SubjectType.SETTING,
                            detail = e.message ?: "unknown error",
                        )
                    )
                }
                all += result
                _state.update { st -> st.copy(findings = all.sortedBy { it.severity.ordinal }) }
            }
            _state.update {
                it.copy(
                    scanning = false,
                    statusText = "",
                    scanCompletedAt = timestamp(),
                )
            }
        }
    }

    /**
     * Looks up eligible findings (APK hashes, domains, IPs) on VirusTotal,
     * paced for the free tier (4 requests/minute).
     */
    fun runVtChecks() {
        if (_state.value.vtInProgress) return
        val key = settings.vtApiKey
        if (key.isBlank()) {
            _state.update { it.copy(vtProgress = "Set a VirusTotal API key in Settings first.") }
            return
        }
        vtJob = viewModelScope.launch {
            _state.update { it.copy(vtInProgress = true) }
            var done = 0
            try {
                val client = VirusTotalClient(key)
                val targets = _state.value.findings
                    .filter { it.vt == null && it.vtEligible }
                    .take(MAX_VT_LOOKUPS)
                for (finding in targets) {
                    _state.update {
                        it.copy(
                            vtProgress = "VirusTotal ${done + 1}/${targets.size}: " +
                                finding.subject.take(40)
                        )
                    }
                    var result = client.lookup(finding)
                    if (result is VirusTotalClient.LookupResult.RateLimited) {
                        _state.update { it.copy(vtProgress = "Rate limited - waiting a minute…") }
                        delay(61_000)
                        result = client.lookup(finding)
                    }
                    when (result) {
                        is VirusTotalClient.LookupResult.Success ->
                            replaceFinding(finding, finding.copy(vt = result.verdict))
                        is VirusTotalClient.LookupResult.Error ->
                            if (result.fatal) {
                                _state.update { it.copy(vtProgress = result.message) }
                                return@launch
                            }
                        else -> { /* still rate limited - skip this one */ }
                    }
                    done++
                    if (done < targets.size) delay(VT_DELAY_MS)
                }
                _state.update { it.copy(vtProgress = "VirusTotal checks finished ($done lookups).") }
            } finally {
                _state.update { it.copy(vtInProgress = false) }
            }
        }
    }

    fun cancelVtChecks() {
        vtJob?.cancel()
        _state.update { it.copy(vtInProgress = false, vtProgress = "VirusTotal checks cancelled.") }
    }

    private fun replaceFinding(old: Finding, new: Finding) {
        _state.update { st ->
            st.copy(findings = st.findings.map { if (it === old) new else it })
        }
    }

    fun saveVtKey(key: String) {
        settings.vtApiKey = key
        _state.update { it.copy(vtKeySet = key.isNotBlank()) }
    }

    fun updateIocDb(url: String) {
        settings.iocUpdateUrl = url
        viewModelScope.launch {
            _state.update { it.copy(iocUpdateStatus = "Downloading…", iocUpdateUrl = url) }
            repo.updateFromUrl(url)
                .onSuccess { db ->
                    val index = IocIndex(db)
                    iocs = index
                    _state.update {
                        applyDbInfo(it, index).copy(
                            iocUpdateStatus = "Updated: ${db.name} v${db.version} " +
                                "(${db.entries.size} indicators)."
                        )
                    }
                }
                .onFailure { e ->
                    _state.update { it.copy(iocUpdateStatus = "Update failed: ${e.message}") }
                }
        }
    }

    fun resetIocDb() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val index = repo.resetToBundled()
                iocs = index
                _state.update {
                    applyDbInfo(it, index).copy(iocUpdateStatus = "Restored bundled database.")
                }
            } catch (e: Exception) {
                _state.update { it.copy(iocUpdateStatus = "Reset failed: ${e.message}") }
            }
        }
    }

    fun exportReport(activityContext: Context) {
        val index = iocs ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val report = ReportExporter.buildReport(
                    getApplication(),
                    _state.value.findings,
                    index.db,
                )
                val path = ReportExporter.writeAndShare(activityContext, report)
                _state.update { it.copy(exportStatus = "Saved: $path") }
            } catch (e: Exception) {
                _state.update { it.copy(exportStatus = "Export failed: ${e.message}") }
            }
        }
    }

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())

    private companion object {
        const val MAX_VT_LOOKUPS = 60
        const val VT_DELAY_MS = 15_500L
    }
}
