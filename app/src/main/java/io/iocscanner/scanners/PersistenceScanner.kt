package io.iocscanner.scanners

import android.content.Context
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import io.iocscanner.data.Severity
import io.iocscanner.data.SubjectType
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Looks for filesystem persistence artifacts: known malware paths
 * (Corejava, Vo1d daemons, ...), root remnants, writable /system, and
 * networking tools that shouldn't ship on consumer firmware.
 * Uses a root shell for /data paths when one is available.
 */
class PersistenceScanner : Scanner {

    override val name = "Filesystem persistence"

    override suspend fun scan(context: Context, iocs: IocIndex): List<Finding> =
        withContext(Dispatchers.IO) {
            val findings = mutableListOf<Finding>()
            val rootWorks = Su.rootShellWorks()

            for (entry in iocs.filePaths) {
                val direct = runCatching { File(entry.value).exists() }.getOrDefault(false)
                val viaRoot = !direct && rootWorks && Su.fileExists(entry.value)
                if (direct || viaRoot) {
                    findings += Finding(
                        scanner = name,
                        severity = Severity.CRITICAL,
                        title = "Known malware artifact on filesystem",
                        subject = entry.value,
                        subjectType = SubjectType.FILE,
                        detail = "This path is a published ${entry.family} indicator. " +
                            entry.note,
                        family = entry.family,
                        source = entry.source,
                    )
                }
            }

            if (!rootWorks) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.INFO,
                    title = "No root shell - /data paths only partially checked",
                    subject = "filesystem access",
                    subjectType = SubjectType.SETTING,
                    detail = "Without root, artifacts under /data (e.g. " +
                        "/data/system/Corejava) can't be reliably confirmed absent. " +
                        "A clean result here is not a guarantee.",
                )
            }

            val suPresent = Su.suBinaryPresent()
            if (suPresent.isNotEmpty()) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.MEDIUM,
                    title = "su binary present (device rooted)",
                    subject = suPresent.joinToString(", "),
                    subjectType = SubjectType.FILE,
                    detail = "Firmware on preinfected boxes frequently ships rooted so " +
                        "implants can survive factory resets. If you didn't root this " +
                        "device yourself, treat this as suspicious.",
                )
            }

            if (runCatching { File("/system").canWrite() }.getOrDefault(false)) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.HIGH,
                    title = "/system partition is writable",
                    subject = "/system",
                    subjectType = SubjectType.FILE,
                    detail = "A writable system partition lets malware persist across " +
                        "resets and modify system apps. Production devices mount " +
                        "/system read-only.",
                )
            }

            val netTools = listOf(
                "/system/bin/nc", "/system/xbin/nc",
                "/system/bin/netcat", "/system/xbin/netcat",
                "/system/bin/tcpdump", "/system/xbin/tcpdump",
            ).filter { runCatching { File(it).exists() }.getOrDefault(false) }
            if (netTools.isNotEmpty()) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.MEDIUM,
                    title = "Network tooling present in firmware",
                    subject = netTools.joinToString(", "),
                    subjectType = SubjectType.FILE,
                    detail = "netcat/tcpdump in system partitions were reported on " +
                        "BADBOX 2.0-class boxes. Legitimate consumer firmware rarely " +
                        "ships them.",
                    family = "badbox2",
                )
            }

            val busybox = listOf("/system/bin/busybox", "/system/xbin/busybox")
                .filter { runCatching { File(it).exists() }.getOrDefault(false) }
            if (busybox.isNotEmpty()) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.LOW,
                    title = "busybox present in firmware",
                    subject = busybox.joinToString(", "),
                    subjectType = SubjectType.FILE,
                    detail = "Common on hobbyist ROMs, but also a convenience layer " +
                        "for firmware-level implants.",
                )
            }

            findings
        }
}
