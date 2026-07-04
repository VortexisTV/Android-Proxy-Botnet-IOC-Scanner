package io.iocscanner.data

import kotlinx.serialization.Serializable

@Serializable
enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

@Serializable
enum class SubjectType { PACKAGE, DOMAIN, IP, FILE, HASH, SETTING, DEVICE, PORT }

@Serializable
data class VtVerdict(
    /** false = VirusTotal has never seen this artifact. */
    val found: Boolean,
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0,
    val link: String = "",
)

@Serializable
data class Finding(
    val scanner: String,
    val severity: Severity,
    val title: String,
    val subject: String,
    val subjectType: SubjectType,
    val detail: String = "",
    val family: String? = null,
    val source: String? = null,
    /** SHA-256 of the related APK, when the subject is an installed app. */
    val sha256: String? = null,
    val vt: VtVerdict? = null,
) {
    /** True when this finding carries something VirusTotal can be asked about. */
    val vtEligible: Boolean
        get() = sha256 != null ||
            subjectType == SubjectType.DOMAIN ||
            subjectType == SubjectType.IP ||
            subjectType == SubjectType.HASH
}

@Serializable
data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val device: String,
    val product: String,
    val androidVersion: String,
    val sdk: Int,
    val buildFingerprint: String,
    val buildTags: String,
    val isTv: Boolean,
)

@Serializable
data class ScanReport(
    val generatedAt: String,
    val appVersion: String,
    val iocDbName: String,
    val iocDbVersion: Int,
    val iocDbUpdated: String,
    val device: DeviceInfo,
    val findings: List<Finding>,
)
