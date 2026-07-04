package io.iocscanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.iocscanner.ScanViewModel

@Composable
fun SettingsScreen(
    state: ScanViewModel.UiState,
    onSaveKey: (String) -> Unit,
    onUpdateDb: (String) -> Unit,
    onResetDb: () -> Unit,
    onBack: () -> Unit,
) {
    var apiKey by rememberSaveable { mutableStateOf("") }
    var url by rememberSaveable(state.iocUpdateUrl) { mutableStateOf(state.iocUpdateUrl) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 48.dp, vertical = 27.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Text(
                "Settings",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        }

        Spacer(Modifier.height(16.dp))

        InfoCard("VirusTotal") {
            Text(
                if (state.vtKeySet) {
                    "An API key is saved on this device."
                } else {
                    "No API key set. Create a free account at virustotal.com and " +
                        "copy the key from your profile."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it },
                label = { Text("API key") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    onSaveKey(apiKey)
                    apiKey = ""
                },
                enabled = apiKey.isNotBlank(),
            ) {
                Text("Save key")
            }
            Spacer(Modifier.height(6.dp))
            Text(
                "Free tier allows 4 lookups per minute - the app paces itself " +
                    "automatically, so enriching many findings takes a while.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(12.dp))

        InfoCard("IOC database") {
            Text(
                "Current: ${state.iocDbName} v${state.iocDbVersion} - " +
                    "${state.iocCount} indicators (updated ${state.iocDbUpdated})",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("HTTPS URL of an iocs.json update") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = { onUpdateDb(url) },
                    enabled = url.startsWith("https://"),
                ) {
                    Text("Download update")
                }
                OutlinedButton(onClick = onResetDb) {
                    Text("Restore bundled")
                }
            }
            if (state.iocUpdateStatus.isNotBlank()) {
                Spacer(Modifier.height(6.dp))
                Text(
                    state.iocUpdateStatus,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                "Host your own curated list (same JSON schema as the bundled " +
                    "assets/iocs.json) and update it here as new research drops.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(12.dp))

        InfoCard("About") {
            Text(
                "Defensive tool. Seed IOCs are compiled from public research: " +
                    "HUMAN Security Satori (BADBOX / BADBOX 2.0, PEACHPIT), " +
                    "XLab-Qianxin & Dr.Web (Vo1d), DesktopECHO's T95 analysis " +
                    "(Corejava), Krebs on Security (Popa / NetNut, June-July 2026) " +
                    "and community proxyware blocklists. A device-model match " +
                    "alone is correlation, not proof of infection. Findings " +
                    "should be verified - VirusTotal enrichment helps.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
