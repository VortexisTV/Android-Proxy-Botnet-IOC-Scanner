package io.iocscanner.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.iocscanner.ScanViewModel
import io.iocscanner.data.Finding

@Composable
fun ResultsScreen(
    state: ScanViewModel.UiState,
    onRunVt: () -> Unit,
    onCancelVt: () -> Unit,
    onExport: (Context) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 48.dp, vertical = 27.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Text(
                "Findings (${state.findings.size})",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f),
            )
            if (state.vtInProgress) {
                OutlinedButton(onClick = onCancelVt) { Text("Cancel VirusTotal") }
            } else {
                Button(
                    onClick = onRunVt,
                    enabled = state.findings.any { it.vtEligible && it.vt == null },
                ) {
                    Text(if (state.vtKeySet) "Check on VirusTotal" else "VirusTotal (needs key)")
                }
            }
            OutlinedButton(
                onClick = { onExport(context) },
                enabled = state.findings.isNotEmpty() && !state.scanning,
            ) {
                Text("Export report")
            }
        }

        if (state.vtProgress.isNotBlank()) {
            Text(
                state.vtProgress,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (state.exportStatus.isNotBlank()) {
            Text(
                state.exportStatus,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(10.dp))

        if (state.findings.isEmpty()) {
            Text(
                "No findings yet - run a scan from the home screen.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 24.dp),
            ) {
                items(state.findings) { finding ->
                    FindingCard(finding)
                }
            }
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(Modifier.height(IntrinsicSize.Min)) {
            Box(
                Modifier
                    .width(6.dp)
                    .fillMaxHeight()
                    .background(severityColor(f.severity))
            )
            Column(
                Modifier
                    .weight(1f)
                    .padding(14.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SeverityChip(f.severity)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        f.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    f.subject,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                )
                if (f.detail.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        f.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                val meta = buildList {
                    add(f.scanner)
                    f.family?.let { add("family: $it") }
                    f.source?.takeIf { it.isNotBlank() }?.let { add("source: $it") }
                }.joinToString("  ·  ")
                Spacer(Modifier.height(4.dp))
                Text(
                    meta,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                f.vt?.let { vt ->
                    val (text, color) = when {
                        !vt.found ->
                            "VirusTotal: never seen (no record)" to
                                MaterialTheme.colorScheme.onSurfaceVariant
                        vt.malicious > 0 ->
                            "VirusTotal: ${vt.malicious} engines flag MALICIOUS " +
                                "(${vt.suspicious} suspicious)" to Color(0xFFEF5350)
                        vt.suspicious > 0 ->
                            "VirusTotal: ${vt.suspicious} engines flag suspicious" to
                                Color(0xFFFFCA28)
                        else ->
                            "VirusTotal: clean (${vt.harmless} harmless, " +
                                "${vt.undetected} undetected)" to Color(0xFF81C784)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text,
                        style = MaterialTheme.typography.bodySmall,
                        color = color,
                        fontWeight = FontWeight.SemiBold,
                    )
                }

                f.sha256?.let { sha ->
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "sha256: $sha",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
