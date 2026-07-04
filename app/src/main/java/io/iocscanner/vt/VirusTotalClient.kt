package io.iocscanner.vt

import io.iocscanner.data.Finding
import io.iocscanner.data.SubjectType
import io.iocscanner.data.VtVerdict
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Minimal VirusTotal API v3 client for file-hash, domain and IP lookups.
 * The caller is responsible for pacing requests (free tier: 4/minute).
 */
class VirusTotalClient(private val apiKey: String) {

    sealed class LookupResult {
        data class Success(val verdict: VtVerdict) : LookupResult()
        object RateLimited : LookupResult()
        data class Error(val message: String, val fatal: Boolean = false) : LookupResult()
    }

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun lookup(finding: Finding): LookupResult {
        val hash = finding.sha256
            ?: finding.subject.takeIf { finding.subjectType == SubjectType.HASH }
        return when {
            hash != null ->
                query("files/$hash", "https://www.virustotal.com/gui/file/$hash")
            finding.subjectType == SubjectType.DOMAIN ->
                query(
                    "domains/${finding.subject}",
                    "https://www.virustotal.com/gui/domain/${finding.subject}",
                )
            finding.subjectType == SubjectType.IP ->
                query(
                    "ip_addresses/${finding.subject}",
                    "https://www.virustotal.com/gui/ip-address/${finding.subject}",
                )
            else -> LookupResult.Error("Finding has nothing VirusTotal can check")
        }
    }

    private suspend fun query(path: String, link: String): LookupResult =
        withContext(Dispatchers.IO) {
            try {
                val request = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/$path")
                    .header("x-apikey", apiKey)
                    .build()
                client.newCall(request).execute().use { resp ->
                    when {
                        resp.code == 404 ->
                            LookupResult.Success(VtVerdict(found = false, link = link))
                        resp.code == 429 -> LookupResult.RateLimited
                        resp.code == 401 || resp.code == 403 ->
                            LookupResult.Error("VirusTotal rejected the API key (HTTP ${resp.code})", fatal = true)
                        !resp.isSuccessful ->
                            LookupResult.Error("HTTP ${resp.code}")
                        else -> {
                            val body = resp.body?.string()
                                ?: return@use LookupResult.Error("Empty response")
                            val stats = json.parseToJsonElement(body)
                                .jsonObject["data"]?.jsonObject
                                ?.get("attributes")?.jsonObject
                                ?.get("last_analysis_stats")?.jsonObject
                                ?: return@use LookupResult.Error("Unexpected response shape")

                            fun stat(key: String) = stats[key]?.jsonPrimitive?.intOrNull ?: 0
                            LookupResult.Success(
                                VtVerdict(
                                    found = true,
                                    malicious = stat("malicious"),
                                    suspicious = stat("suspicious"),
                                    harmless = stat("harmless"),
                                    undetected = stat("undetected"),
                                    link = link,
                                )
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                LookupResult.Error(e.message ?: "network error")
            }
        }
}
