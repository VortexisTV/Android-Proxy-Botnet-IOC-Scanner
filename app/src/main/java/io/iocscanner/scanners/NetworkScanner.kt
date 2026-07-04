package io.iocscanner.scanners

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import io.iocscanner.data.Finding
import io.iocscanner.data.IocIndex
import io.iocscanner.data.Severity
import io.iocscanner.data.SubjectType
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Checks live network state: active connections against IOC IPs
 * (via /proc/net where readable), proxy-style listening ports, the
 * device-wide HTTP proxy setting, and active VPN transports.
 */
class NetworkScanner : Scanner {

    override val name = "Network"

    private val proxyStylePorts = setOf(1080, 3128, 8118, 8888, 9050)

    override suspend fun scan(context: Context, iocs: IocIndex): List<Finding> =
        withContext(Dispatchers.IO) {
            val findings = mutableListOf<Finding>()

            checkGlobalProxy(context, iocs, findings)
            checkVpnTransport(context, findings)

            val conns = ProcNet.readConnections()
            if (conns.isEmpty()) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.INFO,
                    title = "Connection table not readable",
                    subject = "/proc/net",
                    subjectType = SubjectType.SETTING,
                    detail = "Android 10+ blocks /proc/net for regular apps, so live " +
                        "connections to C2 IPs can't be enumerated on this device. " +
                        "Falling back to a localhost proxy-port probe. For full " +
                        "visibility, watch this device's DNS at the router or Pi-hole.",
                )
                for (port in proxyStylePorts) {
                    if (probeLocalPort(port)) {
                        findings += Finding(
                            scanner = name,
                            severity = Severity.MEDIUM,
                            title = "Service listening on proxy-style port",
                            subject = "127.0.0.1:$port",
                            subjectType = SubjectType.PORT,
                            detail = "Something on this device accepts connections on a " +
                                "port commonly used by SOCKS/HTTP proxies. Identify " +
                                "which app owns it.",
                        )
                    }
                }
            } else {
                val reportedRemotes = mutableSetOf<String>()
                val reportedListens = mutableSetOf<Int>()
                for (c in conns) {
                    val ioc = iocs.ips[c.remoteIp]
                    if (ioc != null && c.remotePort != 0 && reportedRemotes.add(c.remoteIp)) {
                        findings += Finding(
                            scanner = name,
                            severity = Severity.CRITICAL,
                            title = "Active connection to known botnet address",
                            subject = c.remoteIp,
                            subjectType = SubjectType.IP,
                            detail = "A live ${c.proto} connection to port ${c.remotePort} " +
                                "points at an IP published as ${ioc.family} " +
                                "infrastructure. ${ioc.note}".trim(),
                            family = ioc.family,
                            source = ioc.source,
                        )
                    }
                    // Popa/NetNut relay fleet communicates on TCP 6000
                    // (s<N>.<domain>:6000). Relays churn faster than IOC lists,
                    // so flag the port even for unknown IPs.
                    val relayPortHit = ioc == null && c.remotePort == 6000 &&
                        c.proto.startsWith("tcp") &&
                        c.state != ProcConnection.STATE_LISTEN &&
                        !c.remoteIp.startsWith("127.") &&
                        c.remoteIp != "::1" && c.remoteIp != "0.0.0.0"
                    if (relayPortHit && reportedRemotes.add(c.remoteIp)) {
                        findings += Finding(
                            scanner = name,
                            severity = Severity.MEDIUM,
                            title = "Outbound connection on Popa relay port 6000",
                            subject = c.remoteIp,
                            subjectType = SubjectType.IP,
                            detail = "The Popa/NetNut relay fleet communicates over " +
                                "TCP port 6000 (Qurium / Nokia Deepfield research). " +
                                "This IP is not in the IOC list, so it may be benign " +
                                "- check it on VirusTotal.",
                            family = "popa-netnut",
                            source = "qurium.org/forensics/finding-popa",
                        )
                    }
                    val listening = c.state == ProcConnection.STATE_LISTEN &&
                        c.localPort in proxyStylePorts
                    if (listening && reportedListens.add(c.localPort)) {
                        val exposed = c.localIp == "0.0.0.0" || c.localIp == "::"
                        findings += Finding(
                            scanner = name,
                            severity = if (exposed) Severity.HIGH else Severity.MEDIUM,
                            title = if (exposed) {
                                "Proxy-style port open to the network"
                            } else {
                                "Service listening on proxy-style port"
                            },
                            subject = "${c.localIp}:${c.localPort}",
                            subjectType = SubjectType.PORT,
                            detail = "Port ${c.localPort} is a common SOCKS/HTTP proxy " +
                                "port. A TV box or phone should normally not run one." +
                                if (exposed) " It is reachable from other machines." else "",
                        )
                    }
                }
            }
            findings
        }

    private fun checkGlobalProxy(
        context: Context,
        iocs: IocIndex,
        findings: MutableList<Finding>,
    ) {
        val proxy = try {
            Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
        } catch (e: Exception) {
            null
        }
        if (proxy.isNullOrBlank() || proxy == ":0") return

        val host = proxy.substringBefore(":")
        val ioc = iocs.matchDomain(host) ?: iocs.ips[host]
        findings += if (ioc != null) {
            Finding(
                scanner = name,
                severity = Severity.CRITICAL,
                title = "Global proxy points at known-bad endpoint",
                subject = proxy,
                subjectType = SubjectType.SETTING,
                detail = "The device-wide HTTP proxy targets ${ioc.family} " +
                    "infrastructure. All traffic is being relayed. ${ioc.note}".trim(),
                family = ioc.family,
                source = ioc.source,
            )
        } else {
            Finding(
                scanner = name,
                severity = Severity.MEDIUM,
                title = "Device-wide HTTP proxy configured",
                subject = proxy,
                subjectType = SubjectType.SETTING,
                detail = "All HTTP traffic passes through this proxy. Fine if you set " +
                    "it yourself; a red flag if you did not.",
            )
        }
    }

    private fun checkVpnTransport(context: Context, findings: MutableList<Finding>) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? ConnectivityManager ?: return
            val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                findings += Finding(
                    scanner = name,
                    severity = Severity.INFO,
                    title = "VPN transport active",
                    subject = "active network",
                    subjectType = SubjectType.SETTING,
                    detail = "Traffic currently routes through a VPN interface. " +
                        "Expected if you run a VPN; proxy malware also uses VPN " +
                        "APIs to capture traffic.",
                )
            }
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun probeLocalPort(port: Int): Boolean = try {
        Socket().use {
            it.connect(InetSocketAddress("127.0.0.1", port), 250)
            true
        }
    } catch (e: Exception) {
        false
    }
}
