# Proxy Botnet IOC Scanner (Android / Android TV)

A on-device scanner that checks Android TV boxes, phones, tablets and
emulator images for indicators of compromise (IOCs) associated with the major
Android proxy botnets and residential-proxy ("proxyware") abuse:

| Family | What it is | Seed IOCs |
|---|---|---|
| **BADBOX / T95 "Corejava"** | Preinstalled firmware backdoor on cheap AOSP boxes (T95, X12, X88...) | C2 domains, C2 IP, `/data/system/Corejava` paths, malicious preinstalled packages, device models |
| **BADBOX 2.0** | 1M+ device botnet disrupted by HUMAN/Google/Trend Micro/FBI (2025) | C2 domains (`catmore88.com`, `ipmoyu.com`), `com.hs.app`, "secondstage" artifacts, ~55 published infected device models |
| **Vo1d** | 1.6M+ Android TV botnet (XLab / Dr.Web research) | 16 C2/downloader domains, 10 IPs, fake-GMS packages (`com.google.android.gms.stable`, `com.goog1e.apps`), `/data/google/*` daemons, 15 sample MD5s |
| **Popa / NetNut** | ~2M-device proxy botnet feeding the NetNut residential proxy platform (FBI seizure, July 2026); Popa is a Vo1d-linked plugin | Control domains (`gmslb.net`, `safernetwork.io`, `tera-home.com`, `ninjatech.io`), NetNut domains, names of streaming apps observed bundling the proxy component (CRICFy, DooFlix, Flixoid...) |
| **PEACHPIT / PROXYLIB / proxyware** | Ad-fraud and bandwidth-selling SDKs embedded in apps (LumiApps, Netas, Bright Data, Honeygain, IPRoyal Pawns...) | 21 SDK identifiers matched against package names *and* declared service classes, plus provider domains |

## What the scan does

1. **Device identity** - model/product/board strings vs. published infected-firmware
   model lists, `test-keys` firmware signing, missing or impostor Google Play services.
2. **Network** - live connections vs. IOC IPs (`/proc/net`, works up to Android 9;
   Android 10+ falls back to a localhost proxy-port probe), device-wide HTTP proxy
   setting (flags known-bad endpoints), proxy-style listening ports (1080/3128/8118/8888/9050),
   active VPN transports.
3. **Filesystem persistence** - known malware paths (Corejava, Vo1d daemons,
   secondstage...), uses a root shell for `/data` paths when available, `su` binaries,
   writable `/system`, netcat/tcpdump/busybox shipped in firmware.
4. **Proxyware SDKs** - every installed app's package name and service classes vs.
   proxyware SDK identifiers.
5. **Installed apps** - every APK hashed (SHA-256 + MD5) and matched against IOC
   hashes; package names and app labels vs. IOC lists; heuristics for headless
   boot-persistent networked apps and sideloaded apps.
6. **VirusTotal enrichment** (optional) - looks up finding hashes/domains/IPs via
   VT API v3, paced at 4 requests/minute for the free tier. Add your API key in
   Settings.
7. **Report export** - pretty-printed JSON report (device info + findings + IOC DB
   version) saved under `Android/data/io.iocscanner/files/reports/`
   and offered via the share sheet. On a box with no share targets:
   `adb pull /sdcard/Android/data/io.iocscanner/files/reports/`.

## VirusTotal Link of APK
https://www.virustotal.com/gui/file/1521c58e01a05cc3e4c5f7ade8c9689aa8c8eade2aeb88d67b964971299dd288?nocache=1

## Updatable IOC database

The bundled database lives at `app/src/main/assets/iocs.json`. Every entry carries
`type`, `value`, `family`, `note`, and `source`. Types:
`domain`, `ip`, `sha256`, `md5`, `package`, `app_label`, `file_path`,
`device_model`, `sdk_id`.

You can host a curated copy (same schema) anywhere reachable over HTTPS (a
GitHub raw URL), and pull it from **Settings → IOC database → Download update**.
This is how you keep the app current as new research drops, without rebuilding.

Good sources to watch for updates:
- HUMAN Security Satori blog (BADBOX, BADBOX 2.0, PEACHPIT, PROXYLIB)
- XLab-Qianxin blog (Vo1d, Kimwolf)
- Krebs on Security (Popa / NetNut coverage, June-July 2026)
- DesktopECHO/T95-H616-Malware on GitHub (T95-class boxes)
- Flo5k5/proxyware-blocklist on GitHub (proxyware/bandwidth-sharing domains)
- Shadowserver sinkhole reports and the FBI IC3 BADBOX 2.0 alert

## Building

Requirements: JDK 17, Android SDK (platform 34). No NDK.

- **Android Studio**: open the project folder, let it sync, Run.
- **CLI**:
  ```
  gradle assembleDebug        # or .\gradlew assembleDebug once the wrapper jar exists
  adb install app/build/outputs/apk/debug/app-debug.apk
  ```

### Installing on a TV box

```
adb connect <box-ip>:5555    # enable ADB over network in the box's developer options
adb install app-debug.apk
```
The app appears in the leanback launcher ("Proxy IOC Scanner") and is fully
D-pad navigable.

## Reading the results

- **CRITICAL** - direct IOC hit (known package, known hash, live C2 connection,
  known filesystem artifact). Treat the device as compromised: isolate it from the
  network. Preinstalled implants survive factory resets. Reflashing clean firmware
  or discarding the device is the honest remediation for firmware-level families.
- **HIGH** - strong correlation (proxyware SDK, infected-model list, impostor GMS,
  exposed proxy port). Investigate before trusting the device.
- **MEDIUM/LOW** - heuristics (rooted firmware, sideloaded/headless networked apps,
  global proxy set). Normal on some hobbyist setups; suspicious on a stock consumer box.
- A clean scan is **not** a clean bill of health: without root, `/data` can't be
  fully inspected, and on Android 10+ live connections can't be enumerated. The
  strongest complementary signal is watching the device's DNS at your router or
  Pi-hole for the IOC domains in `iocs.json`.

## Limitations & roadmap

- No traffic capture: a `VpnService`-based DNS monitor would let the app match IOC
  *domains* live (currently domains are matched only against the global-proxy
  setting; they're primarily there for router-side hunting and VT checks).
- No APK signature-certificate matching yet.
- Vo1d/BADBOX components living as native daemons outside `/data/app` are only
  detectable via the file-path IOCs (root helps a lot).
- Emulator images: install the APK into the running emulator; scanning `.img` files
  offline is out of scope for the on-device app.

## Ethics / scope

This is a detection-only tool: it reads public system state on a device you own or
are authorized to assess. It performs no exploitation, no traffic interception, and
contacts nothing except VirusTotal (with your key) and the IOC update URL you set.

## IOC sources

Seed IOCs were compiled 2026-07-04 from:
- HUMAN Satori: [BADBOX 2.0 disruption](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/) (with Google, Trend Micro, Shadowserver)
- Point Wild: [BADBOX 2.0 threat intel](https://www.pointwild.com/threat-intelligence/badbox-2-0-a-global-iot-botnet-threat/)
- Rescana: [BADBOX 2.0 and Vo1d impacted models](https://www.rescana.com/post/badbox-2-0-and-vo1d-botnets-android-tv-streaming-box-infections-impacted-models-and-mitigation-st)
- XLab-Qianxin: [Long Live the Vo1d Botnet](https://blog.xlab.qianxin.com/long-live-the-vo1d_botnet/)
- DesktopECHO: [T95-H616-Malware](https://github.com/DesktopECHO/T95-H616-Malware)
- Krebs on Security: ["Popa" botnet linked to publicly-traded Israeli firm](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/) and [FBI seizes NetNut proxy platform](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)
- Flo5k5: [proxyware-blocklist](https://github.com/Flo5k5/proxyware-blocklist)
- The Hacker News: [PROXYLIB / LumiApps proxyware apps](https://thehackernews.com/2024/04/malicious-apps-caught-secretly-turning.html)

A device-model match alone is correlation, not proof of infection — many of these
model strings are shared across clean and dirty firmware batches.
