package io.iocscanner.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class IocType {
    @SerialName("domain") DOMAIN,
    @SerialName("ip") IP,
    @SerialName("sha256") SHA256,
    @SerialName("md5") MD5,
    @SerialName("package") PACKAGE,
    @SerialName("app_label") APP_LABEL,
    @SerialName("file_path") FILE_PATH,
    @SerialName("device_model") DEVICE_MODEL,
    @SerialName("sdk_id") SDK_ID,
}

@Serializable
data class IocEntry(
    val type: IocType,
    val value: String,
    val family: String,
    val note: String = "",
    val source: String = "",
)

@Serializable
data class IocDatabase(
    val name: String = "bundled",
    val version: Int,
    val updated: String,
    val entries: List<IocEntry>,
)

/**
 * Pre-indexed view of an [IocDatabase] for fast lookups during a scan.
 * All keys are lowercase.
 */
class IocIndex(val db: IocDatabase) {

    val domains: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.DOMAIN }.associateBy { it.value.lowercase() }

    val ips: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.IP }.associateBy { it.value }

    val sha256: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.SHA256 }.associateBy { it.value.lowercase() }

    val md5: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.MD5 }.associateBy { it.value.lowercase() }

    val packages: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.PACKAGE }.associateBy { it.value.lowercase() }

    val appLabels: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.APP_LABEL }.associateBy { it.value.lowercase() }

    val filePaths: List<IocEntry> =
        db.entries.filter { it.type == IocType.FILE_PATH }

    val deviceModels: Map<String, IocEntry> =
        db.entries.filter { it.type == IocType.DEVICE_MODEL }.associateBy { it.value.lowercase() }

    val sdkIds: List<IocEntry> =
        db.entries.filter { it.type == IocType.SDK_ID }

    /** Matches a hostname exactly or as a subdomain of an IOC domain. */
    fun matchDomain(host: String): IocEntry? {
        val h = host.lowercase().trimEnd('.')
        domains[h]?.let { return it }
        var idx = h.indexOf('.')
        while (idx in 0 until h.length - 1) {
            domains[h.substring(idx + 1)]?.let { return it }
            idx = h.indexOf('.', idx + 1)
        }
        return null
    }
}
