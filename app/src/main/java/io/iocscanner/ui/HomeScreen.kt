package io.iocscanner.ui

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.iocscanner.ScanViewModel
import io.iocscanner.data.Severity

@Composable
fun HomeScreen(
    state: ScanViewModel.UiState,
    onScan: () -> Unit,
    onShowResults: () -> Unit,
    onShowSettings: () -> Unit,
) {
    val counts = remember(state.findings) {
        state.findings.groupingBy { it.severity }.eachCount()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            // overscan-safe padding for TV
            .padding(horizontal = 48.dp, vertical = 27.dp),
    ) {
        Text(
            "Proxy Botnet IOC Scanner",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            "Defensive checks for BADBOX / Vo1d / Popa-NetNut-style proxy abuse " +
                "on Android TV boxes, phones and emulators.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(20.dp))

        InfoCard("This device") {
            Text(
                "${Build.MANUFACTURER} ${Build.MODEL} - Android " +
                    "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Build: ${Build.FINGERPRINT}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(12.dp))

        InfoCard("IOC database") {
            Text(
                if (state.iocCount > 0) {
                    "${state.iocDbName} v${state.iocDbVersion} - ${state.iocCount} " +
                        "indicators (updated ${state.iocDbUpdated})"
                } else {
                    "Loading…"
                },
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        Spacer(Modifier.height(20.dp))

        Button(
            onClick = onScan,
            enabled = state.ready && !state.scanning,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (state.scanning) "Scanning…" else "Run scan",
                modifier = Modifier.padding(vertical = 6.dp),
                style = MaterialTheme.typography.titleMedium,
            )
        }

        if (state.scanning) {
            Spacer(Modifier.height(10.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Spacer(Modifier.height(6.dp))
            Text(
                state.statusText +
                    "  (hashing every APK - this can take a few minutes)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        state.scanCompletedAt?.let { at ->
            Spacer(Modifier.height(14.dp))
            InfoCard("Last scan: $at") {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Severity.entries.forEach { sev ->
                        val n = counts[sev] ?: 0
                        if (n > 0) {
                            Text(
                                "$n ${sev.name}",
                                style = MaterialTheme.typography.labelMedium,
                                color = severityColor(sev),
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                    }
                    if (state.findings.isEmpty()) {
                        Text(
                            "No findings.",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(18.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = onShowResults,
                enabled = state.findings.isNotEmpty(),
            ) {
                Text("Results (${state.findings.size})")
            }
            Spacer(Modifier.width(0.dp))
            OutlinedButton(onClick = onShowSettings) {
                Text("Settings")
            }
        }
    }
}
