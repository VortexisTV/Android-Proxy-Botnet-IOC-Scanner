package io.iocscanner.scanners

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import io.iocscanner.data.Severity
import io.iocscanner.data.SubjectType

/**
 * Checks the device's own identity: model strings against published
 * infected-firmware model lists, test-keys signing, and Play services
 * integrity (absent or impostor GMS).
 */
class DevicePropertiesScanner : Scanner {

    override val name = "Device identity"

    override suspend fun scan(context: Context, iocs: IocIndex): List<Finding> {
        val findings = mutableListOf<Finding>()

        val candidates = listOf(Build.MODEL, Build.DEVICE, Build.PRODUCT, Build.BOARD)
            .filterNotNull()
            .filter { it.isNotBlank() }
            .distinct()
        for (candidate in candidates) {
            val ioc = iocs.deviceModels[candidate.lowercase()] ?: continue
            findings += Finding(
                scanner = name,
                severity = Severity.HIGH,
                title = "Device model on infected-firmware list",
                subject = candidate,
                subjectType = SubjectType.DEVICE,
                detail = "This model string appears in published lists of devices " +
                    "shipped with ${ioc.family}-class malware. That is correlation, " +
                    "not proof - weigh it together with the other findings. ${ioc.note}".trim(),
                family = ioc.family,
                source = ioc.source,
            )
            break
        }

        if (Build.TAGS?.contains("test-keys") == true) {
            findings += Finding(
                scanner = name,
                severity = Severity.MEDIUM,
                title = "Firmware signed with test-keys",
                subject = Build.TAGS ?: "test-keys",
                subjectType = SubjectType.DEVICE,
                detail = "The build is signed with public AOSP test keys, so anyone " +
                    "can produce 'system' updates for it. Typical of uncertified " +
                    "TV boxes and a prerequisite for most firmware-level implants.",
            )
        }

        val pm = context.packageManager
        val gms = try {
            pm.getApplicationInfo("com.google.android.gms", 0)
        } catch (e: Exception) {
            null
        }
        if (gms == null) {
            findings += Finding(
                scanner = name,
                severity = Severity.INFO,
                title = "No Google Play services",
                subject = "com.google.android.gms",
                subjectType = SubjectType.PACKAGE,
                detail = "This is an uncertified AOSP build without Play Protect. " +
                    "Most devices shipping preinstalled proxy malware fall in this " +
                    "category.",
            )
        } else if ((gms.flags and ApplicationInfo.FLAG_SYSTEM) == 0) {
            findings += Finding(
                scanner = name,
                severity = Severity.HIGH,
                title = "Play services installed as a user app",
                subject = "com.google.android.gms",
                subjectType = SubjectType.PACKAGE,
                detail = "Genuine Play services is a system app. A user-installed " +
                    "copy is very likely an impostor (Vo1d ships a fake " +
                    "com.google.android.gms.stable).",
                family = "vo1d",
            )
        }

        return findings
    }
}
