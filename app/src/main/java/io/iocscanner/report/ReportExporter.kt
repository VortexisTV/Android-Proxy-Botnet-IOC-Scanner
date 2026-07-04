package io.iocscanner.report

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import io.iocscanner.data.DeviceInfo
import io.iocscanner.data.Finding
import io.iocscanner.data.IocDatabase
import io.iocscanner.data.ScanReport
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object ReportExporter {

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    fun buildReport(
        context: Context,
        findings: List<Finding>,
        db: IocDatabase,
    ): ScanReport {
        val pm = context.packageManager
        val appVersion = try {
            pm.getPackageInfo(context.packageName, 0).versionName ?: "?"
        } catch (e: Exception) {
            "?"
        }
        return ScanReport(
            generatedAt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format(Date()),
            appVersion = appVersion,
            iocDbName = db.name,
            iocDbVersion = db.version,
            iocDbUpdated = db.updated,
            device = DeviceInfo(
                manufacturer = Build.MANUFACTURER ?: "",
                model = Build.MODEL ?: "",
                device = Build.DEVICE ?: "",
                product = Build.PRODUCT ?: "",
                androidVersion = Build.VERSION.RELEASE ?: "",
                sdk = Build.VERSION.SDK_INT,
                buildFingerprint = Build.FINGERPRINT ?: "",
                buildTags = Build.TAGS ?: "",
                isTv = pm.hasSystemFeature(PackageManager.FEATURE_LEANBACK),
            ),
            findings = findings,
        )
    }

    /** Writes the report JSON and opens a share sheet. Returns the file path. */
    fun writeAndShare(context: Context, report: ScanReport): String {
        val dir = File(context.getExternalFilesDir(null), "reports").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(dir, "ioc-scan-$stamp.json")
        file.writeText(json.encodeToString(report))

        try {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file,
            )
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(
                Intent.createChooser(send, "Share scan report")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } catch (e: Exception) {
            // No share targets (common on TV boxes) - the file is still on disk;
            // pull it with: adb pull <path>
        }
        return file.absolutePath
    }
}
