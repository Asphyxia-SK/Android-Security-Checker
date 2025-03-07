package com.example.securitycheck

import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject
import java.io.OutputStreamWriter

object SecurityChecker {
    private var suspiciousFlags = 0
    private const val SERVER_URL = "https://your-server.com/log"  // Replace with your actual server URL

    fun checkAppSecurity(context: Context) {
        val isSigned = isAppSigned(context)
        val isRooted = isDeviceRooted()

        if (!isSigned || isRooted) {
            suspiciousFlags++
        }

        Log.d("SecurityCheck", "App Signed: $isSigned, Device Rooted: $isRooted, Flags: $suspiciousFlags")

        // Send log to the server
        sendSecurityLog(context, isSigned, isRooted)

        if (suspiciousFlags >= 3) {
            alertDeveloper(context)
        }
    }

    private fun isAppSigned(context: Context): Boolean {
        return try {
            val packageInfo: PackageInfo = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo.hasMultipleSigners()
            } else {
                packageInfo.signatures.isNotEmpty()
            }
        } catch (e: Exception) {
            Log.e("SecurityCheck", "Error checking app signature: ${e.message}")
            false
        }
    }

    private fun isDeviceRooted(): Boolean {
        val rootPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )

        for (path in rootPaths) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    private fun alertDeveloper(context: Context) {
        AlertDialog.Builder(context)
            .setTitle("Security Alert")
            .setMessage("Suspicious activity detected. Manual checking required!")
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .show()
    }

    private fun sendSecurityLog(context: Context, isSigned: Boolean, isRooted: Boolean) {
        Thread {
            try {
                val url = URL(SERVER_URL)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true

                val json = JSONObject()
                json.put("package_name", context.packageName)
                json.put("is_signed", isSigned)
                json.put("is_rooted", isRooted)
                json.put("suspicious_flags", suspiciousFlags)

                val outputStream = OutputStreamWriter(conn.outputStream)
                outputStream.write(json.toString())
                outputStream.flush()
                outputStream.close()

                val responseCode = conn.responseCode
                Log.d("SecurityCheck", "Log sent to server. Response Code: $responseCode")

            } catch (e: Exception) {
                Log.e("SecurityCheck", "Error sending log to server: ${e.message}")
            }
        }.start()
    }
}
