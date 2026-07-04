package io.iocscanner.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.iocscanner.data.Severity

private val DarkColors = darkColorScheme(
    primary = Color(0xFF64B5F6),
    onPrimary = Color(0xFF06263F),
    secondary = Color(0xFF80CBC4),
    background = Color(0xFF0E141B),
    onBackground = Color(0xFFE3E8EE),
    surface = Color(0xFF16202A),
    onSurface = Color(0xFFE3E8EE),
    surfaceVariant = Color(0xFF1E2A36),
    onSurfaceVariant = Color(0xFFB7C2CC),
    error = Color(0xFFEF5350),
)

@Composable
fun IocScannerTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkColors, content = content)
}

fun severityColor(severity: Severity): Color = when (severity) {
    Severity.CRITICAL -> Color(0xFFEF5350)
    Severity.HIGH -> Color(0xFFFF8A65)
    Severity.MEDIUM -> Color(0xFFFFCA28)
    Severity.LOW -> Color(0xFF4FC3F7)
    Severity.INFO -> Color(0xFF90A4AE)
}

@Composable
fun SeverityChip(severity: Severity) {
    val color = severityColor(severity)
    Text(
        text = severity.name,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        fontWeight = FontWeight.Bold,
        modifier = Modifier
            .border(1.dp, color, RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    )
}

@Composable
fun InfoCard(
    title: String,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(6.dp))
            content()
        }
    }
}
