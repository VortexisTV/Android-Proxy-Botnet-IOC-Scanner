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
 * Detects bandwidth-sharing / residential-proxy SDKs (NetNut, Bright Data,
 * Honeygain, LumiApps, Netas, ...) by matching SDK identifier substrings
 * against installed package names and their declared service classes.
 */
class ProxywareScanner : Scanner {

    override val name = "Proxyware SDKs"

    override suspend fun scan(context: Context, iocs: IocIndex): List<Finding> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val findings = mutableListOf<Finding>()
            if (iocs.sdkIds.isEmpty()) return@withContext findings

            for (pkg in installedPackages(pm)) {
                val appInfo = pkg.applicationInfo ?: continue
                val pkgName = pkg.packageName ?: continue
                if (pkgName == context.packageName) continue

                val serviceNames = pkg.services?.mapNotNull { it.name?.lowercase() } ?: emptyList()
                val pkgLower = pkgName.lowercase()

                val match = iocs.sdkIds.firstOrNull { entry ->
                    val id = entry.value.lowercase()
                    pkgLower.contains(id) || serviceNames.any { it.contains(id) }
                } ?: continue

                val label = try {
                    appInfo.loadLabel(pm).toString()
                } catch (e: Exception) {
                    pkgName
                }
                val apkPath = appInfo.publicSourceDir ?: appInfo.sourceDir
                val sha256 = apkPath?.let { Hashing.apkHashes(File(it))?.first }

                findings += Finding(
                    scanner = name,
                    severity = Severity.HIGH,
                    title = "Bandwidth-sharing / proxy SDK detected",
                    subject = pkgName,
                    subjectType = SubjectType.PACKAGE,
                    detail = "\"$label\" matches proxyware identifier " +
                        "\"${match.value}\" (${match.family}). This app can sell " +
                        "this device's internet connection as a residential proxy. " +
                        match.note,
                    family = match.family,
                    source = match.source,
                    sha256 = sha256,
                )
            }
            findings
        }
}
