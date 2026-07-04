package io.iocscanner.scanners

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import java.io.File
import java.net.InetAddress
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

interface Scanner {
    val name: String
    suspend fun scan(context: Context, iocs: IocIndex): List<Finding>
}

/**
 * Enumerates installed packages, degrading gracefully when the full flag set
 * overflows the binder transaction buffer on package-heavy devices.
 */
@Suppress("DEPRECATION")
internal fun installedPackages(pm: PackageManager): List<PackageInfo> {
    val flagSets = intArrayOf(
        PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES,
        PackageManager.GET_PERMISSIONS,
        0,
    )
    for (flags in flagSets) {
        try {
            return pm.getInstalledPackages(flags)
        } catch (e: Exception) {
            // fall through to a smaller flag set
        }
    }
    return emptyList()
}

internal object Hashing {

    private const val MAX_FILE_BYTES = 300L * 1024 * 1024

    /** Returns (sha256, md5) as lowercase hex, or null when unreadable/too large. */
    fun apkHashes(file: File): Pair<String, String>? {
        return try {
            if (!file.isFile || file.length() > MAX_FILE_BYTES) return null
            val sha = MessageDigest.getInstance("SHA-256")
            val md5 = MessageDigest.getInstance("MD5")
            file.inputStream().use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    sha.update(buf, 0, n)
                    md5.update(buf, 0, n)
                }
            }
            sha.digest().toHex() to md5.digest().toHex()
        } catch (e: Exception) {
            null
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

/** Best-effort root helper. Everything here fails soft: no root, no findings. */
internal object Su {

    val suBinaryPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/vendor/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
    )

    fun suBinaryPresent(): List<String> =
        suBinaryPaths.filter { runCatching { File(it).exists() }.getOrDefault(false) }

    suspend fun run(cmd: List<String>, timeoutMs: Long = 4000L): Pair<Int, String>? =
        withContext(Dispatchers.IO) {
            var tracked: Process? = null
            try {
                val process = ProcessBuilder(cmd).redirectErrorStream(true).start()
                tracked = process
                withTimeoutOrNull(timeoutMs) {
                    runInterruptible {
                        val output = process.inputStream.bufferedReader().readText()
                        val code = process.waitFor()
                        code to output
                    }
                }
            } catch (e: Exception) {
                null
            } finally {
                try {
                    tracked?.destroy()
                } catch (_: Exception) {
                }
            }
        }

    suspend fun rootShellWorks(): Boolean {
        if (suBinaryPresent().isEmpty()) return false
        val result = run(listOf("su", "-c", "id")) ?: return false
        return result.first == 0 && result.second.contains("uid=0")
    }

    suspend fun fileExists(path: String): Boolean {
        val result = run(listOf("su", "-c", "ls -d \"$path\"")) ?: return false
        return result.first == 0
    }
}

internal data class ProcConnection(
    val proto: String,
    val localIp: String,
    val localPort: Int,
    val remoteIp: String,
    val remotePort: Int,
    val state: Int,
) {
    companion object {
        const val STATE_LISTEN = 0x0A
    }
}

/**
 * Parser for /proc/net/{tcp,tcp6,udp,udp6}. Readable up to Android 9;
 * SELinux blocks it on most Android 10+ builds, in which case this
 * returns an empty list.
 */
internal object ProcNet {

    fun readConnections(): List<ProcConnection> {
        val result = mutableListOf<ProcConnection>()
        for (proto in listOf("tcp", "tcp6", "udp", "udp6")) {
            val lines = try {
                File("/proc/net/$proto").readLines()
            } catch (e: Exception) {
                continue
            }
            for (line in lines.drop(1)) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 4) continue
                val local = parseEndpoint(parts[1]) ?: continue
                val remote = parseEndpoint(parts[2]) ?: continue
                val state = parts[3].toIntOrNull(16) ?: continue
                result += ProcConnection(
                    proto = proto,
                    localIp = local.first,
                    localPort = local.second,
                    remoteIp = remote.first,
                    remotePort = remote.second,
                    state = state,
                )
            }
        }
        return result
    }

    private fun parseEndpoint(raw: String): Pair<String, Int>? {
        val pieces = raw.split(":")
        if (pieces.size != 2) return null
        val ip = hexToIp(pieces[0]) ?: return null
        val port = pieces[1].toIntOrNull(16) ?: return null
        return ip to port
    }

    /** Kernel encodes addresses as little-endian hex, per 32-bit word. */
    private fun hexToIp(hex: String): String? {
        return try {
            when (hex.length) {
                8 -> {
                    val bytes = hex.chunked(2).map { it.toInt(16) }.reversed()
                    bytes.joinToString(".")
                }
                32 -> {
                    val bytes = ByteArray(16)
                    for (group in 0 until 4) {
                        val word = hex.substring(group * 8, group * 8 + 8)
                        val wordBytes = word.chunked(2).map { it.toInt(16).toByte() }.reversed()
                        for (i in 0 until 4) bytes[group * 4 + i] = wordBytes[i]
                    }
                    // IPv4-mapped IPv6 (::ffff:a.b.c.d) -> plain IPv4
                    val mapped = bytes.take(10).all { it == 0.toByte() } &&
                        bytes[10] == 0xFF.toByte() && bytes[11] == 0xFF.toByte()
                    if (mapped) {
                        (12..15).joinToString(".") { (bytes[it].toInt() and 0xFF).toString() }
                    } else {
                        InetAddress.getByAddress(bytes).hostAddress
                    }
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }
}
