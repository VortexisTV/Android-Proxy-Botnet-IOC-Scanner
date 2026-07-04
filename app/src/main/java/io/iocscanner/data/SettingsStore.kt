package io.iocscanner.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Small settings store. Uses EncryptedSharedPreferences when the device
 * keystore works; falls back to plain SharedPreferences on broken firmware
 * (common on cheap TV boxes) so the app still functions.
 */
class SettingsStore(context: Context) {

    private val prefs: SharedPreferences = createPrefs(context)

    private fun createPrefs(context: Context): SharedPreferences {
        repeat(2) { attempt ->
            try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                return EncryptedSharedPreferences.create(
                    context,
                    "secure_prefs",
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
                )
            } catch (e: Exception) {
                // Cheap boxes sometimes wipe the keystore across reboots, which
                // leaves secure_prefs undecryptable and create() throwing forever.
                // Drop the unreadable file once so the retry starts clean instead
                // of the app losing settings persistence entirely.
                if (attempt == 0) {
                    try {
                        context.deleteSharedPreferences("secure_prefs")
                    } catch (_: Exception) {
                    }
                }
            }
        }
        return context.getSharedPreferences("plain_prefs", Context.MODE_PRIVATE)
    }

    var vtApiKey: String
        get() = prefs.getString(KEY_VT_API, "") ?: ""
        set(value) { prefs.edit().putString(KEY_VT_API, value.trim()).apply() }

    var iocUpdateUrl: String
        get() = prefs.getString(KEY_IOC_URL, "") ?: ""
        set(value) { prefs.edit().putString(KEY_IOC_URL, value.trim()).apply() }

    private companion object {
        const val KEY_VT_API = "vt_api_key"
        const val KEY_IOC_URL = "ioc_update_url"
    }
}
