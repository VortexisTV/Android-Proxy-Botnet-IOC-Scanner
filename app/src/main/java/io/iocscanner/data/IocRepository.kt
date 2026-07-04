package io.iocscanner.data

import android.content.Context
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Loads the IOC database. Order of preference:
 * 1. a previously downloaded update stored in filesDir,
 * 2. the database bundled in assets.
 */
class IocRepository(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val localFile: File get() = File(context.filesDir, "iocs.json")

    fun load(): IocIndex {
        val db = readLocal() ?: readBundled()
        return IocIndex(db)
    }

    private fun readLocal(): IocDatabase? {
        return try {
            if (!localFile.exists()) return null
            json.decodeFromString<IocDatabase>(localFile.readText())
        } catch (e: Exception) {
            null
        }
    }

    private fun readBundled(): IocDatabase {
        val text = context.assets.open("iocs.json").bufferedReader().use { it.readText() }
        return json.decodeFromString(text)
    }

    /**
     * Downloads a replacement IOC database (same JSON schema) from [url],
     * validates it parses, then persists it.
     */
    suspend fun updateFromUrl(url: String): Result<IocDatabase> = withContext(Dispatchers.IO) {
        runCatching {
            require(url.startsWith("https://")) { "IOC update URL must use https" }
            val client = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build()
            val request = Request.Builder().url(url).build()
            client.newCall(request).execute().use { resp ->
                check(resp.isSuccessful) { "HTTP ${resp.code}" }
                val body = resp.body?.string() ?: error("Empty response")
                val db = json.decodeFromString<IocDatabase>(body) // validate before saving
                localFile.writeText(body)
                db
            }
        }
    }

    /** Discards any downloaded database and falls back to the bundled one. */
    fun resetToBundled(): IocIndex {
        localFile.delete()
        return IocIndex(readBundled())
    }
}
