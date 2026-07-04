package io.iocscanner.scanners

import android.content.Context
import android.content.pm.ApplicationInfo
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import io.iocscanner.data.Severity
import io.iocscanner.data.SubjectType
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Matches every installed app against IOC package names, app labels and
 * APK hashes (SHA-256 + MD5), and applies persistence heuristics that
 * are typical for proxy-botnet implants.
 */
class PackageScanner : Scanner {

    override val name = "Installed apps"

    override suspend fun scan(context: Context, iocs: IocIndex): List<Finding> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val findings = mutableListOf<Finding>()

            for (pkg in installedPackages(pm)) {
                val appInfo = pkg.applicationInfo ?: continue
                val pkgName = pkg.packageName ?: continue
                if (pkgName == context.packageName) continue

                val label = try {
                    appInfo.loadLabel(pm).toString()
                } catch (e: Exception) {
                    pkgName
                }
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                var flagged = false

                // APK hashes (also attached to heuristic findings for VT lookups)
                val apkPath = appInfo.publicSourceDir ?: appInfo.sourceDir
                val hashes = apkPath?.let { Hashing.apkHashes(File(it)) }
                val sha256 = hashes?.first

                iocs.packages[pkgName.lowercase()]?.let { ioc ->
                    flagged = true
                    findings += Finding(
                        scanner = name,
                        severity = Severity.CRITICAL,
                        title = "Known-malicious package installed",
                        subject = pkgName,
                        subjectType = SubjectType.PACKAGE,
                        detail = "\"$label\" matches an IOC package name for the " +
                            "${ioc.family} family. ${ioc.note}".trim(),
                        family = ioc.family,
                        source = ioc.source,
                        sha256 = sha256,
                    )
                }

                iocs.appLabels[label.lowercase()]?.let { ioc ->
                    flagged = true
                    findings += Finding(
                        scanner = name,
                        severity = Severity.HIGH,
                        title = "App name matches known proxy-bundling app",
                        subject = "$label ($pkgName)",
                        subjectType = SubjectType.PACKAGE,
                        detail = "Apps distributed under this name have been observed " +
                            "bundling ${ioc.family} proxy components. Name matches are " +
                            "a weaker signal than hash matches - verify with VirusTotal. " +
                            ioc.note,
                        family = ioc.family,
                        source = ioc.source,
                        sha256 = sha256,
                    )
                }

                if (hashes != null) {
                    val (sha, md5) = hashes
                    val hashIoc = iocs.sha256[sha] ?: iocs.md5[md5]
                    if (hashIoc != null) {
                        flagged = true
                        findings += Finding(
                            scanner = name,
                            severity = Severity.CRITICAL,
                            title = "APK hash matches known malware sample",
                            subject = pkgName,
                            subjectType = SubjectType.PACKAGE,
                            detail = "\"$label\" - APK digest matches a published " +
                                "${hashIoc.family} sample. ${hashIoc.note}".trim(),
                            family = hashIoc.family,
                            source = hashIoc.source,
                            sha256 = sha,
                        )
                    }
                }

                // Heuristic: headless app that starts at boot and talks to the network.
                val perms = pkg.requestedPermissions?.toSet() ?: emptySet()
                val hasBoot = "android.permission.RECEIVE_BOOT_COMPLETED" in perms
                val hasInternet = "android.permission.INTERNET" in perms
                val hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null ||
                    pm.getLeanbackLaunchIntentForPackage(pkgName) != null

                if (!isSystem && !flagged && hasBoot && hasInternet && !hasLauncher) {
                    flagged = true
                    findings += Finding(
                        scanner = name,
                        severity = Severity.MEDIUM,
                        title = "Headless boot-persistent app with network access",
                        subject = pkgName,
                        subjectType = SubjectType.PACKAGE,
                        detail = "\"$label\" has no launcher entry, starts at boot and " +
                            "can reach the internet - the classic shape of a proxy " +
                            "node or downloader. Check its hash on VirusTotal.",
                        sha256 = sha256,
                    )
                }

                // Heuristic: sideloaded app (no recognized installer).
                val installer = try {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(pkgName)
                } catch (e: Exception) {
                    null
                }
                if (!isSystem && !flagged && installer == null && hasInternet) {
                    findings += Finding(
                        scanner = name,
                        severity = Severity.LOW,
                        title = "Sideloaded app with network access",
                        subject = pkgName,
                        subjectType = SubjectType.PACKAGE,
                        detail = "\"$label\" was not installed by an app store. Common " +
                            "on TV boxes; worth a VirusTotal check of its hash.",
                        sha256 = sha256,
                    )
                }
            }
            findings
        }
}
