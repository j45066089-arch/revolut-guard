# RevolutGuard Status — Stand 2026-09-27 (Fortsetzung morgen)

## Ziel
Revolut (iPhone 8, iOS 16.7.16, Dopamine2-roothide) erkennt JB → "Security Alert — This device does not meet the security standards" direkt beim Öffnen.

## Befund: ZWEI JB-Erkennungen in Revolut
1. **SEON-SDK** (`Revolut.app/Frameworks/SeonSDK.framework/SeonSDK`) — prüft Pfade + canOpenURL + getenv + sysctl
2. **Incognia** (in Revolut-Hauptbinary, 271 MB) — eigener Pfadkatalog (30+ Pfade inkl. roothide-Marker `/jb/jailbreakd.plist`, `/var/jb/.installed_dopamine`, `/usr/lib/libjailbreak.dylib`), `hookDetected`-Signal, `_dyld_image_count`/`_dyld_get_image_name`-Enumeration, `dlsym` nach MSHookFunction/SubstrateLoader, `opendir`/`readdir`

Extrahiert mit: `C:/Users/shosh/VCamUSB/scan_revolut_paths.py` (auf Device laufend, liest Binary).

## Gebaut & deployed
- **RevolutGuard 1.2.0** (`com.maurice.revolutguard`): voller Pfadkatalog + Hooks: fileExistsAtPath/stat/lstat/access/fopen/opendir/getenv/sysctlbyname/canOpenURL/dlsym/_dyld_get_image_name/_dyld_image_count. Repo: `j45066089-arch/revolut-guard`, GitHub Actions macos-14 build.
- **HeartBeat 1.0.0** (`com.maurice.heartbeat`): reiner ctor-Test (Marker `hb_injected.txt` in App-Container + Loopback-TCP 8788). Filter: com.revolut.revolut + com.apple.mobilesafari.
- Beide in beiden Ladepfaden: `/var/jb/usr/lib/TweakInject/` + `/var/jb/Library/MobileSubstrate/DynamicLibraries/`.

## WICHTIGSTER Befund: App-Injektion device-weit TOT
- HeartBeat lädt weder in Revolut noch Safari → kein Marker, Port 8788/8789 zu (wasserdicht via Loopback-TCP-Test).
- `com.opa334.Dopamine.startup` = **Exit 255** (startet jailbreakd nicht). `idownloadd` = disabled.
- Daemon-Injektion lebt noch: LordVCAM-FakeServer 443 OK, SensorForgePro 8797 OK.
- → systemhook lädt keine Tweaks in App-Prozesse (dyld-patch-Abfrage über jailbreakd tot). Revolut erkennt JB also, weil KEINE Tweaks in Apps laden.
- jailbreakd manuell gestartet (`/var/jb/basebin/jailbreakd` → exit 0) brachte nichts.

## Nächster Schritt (laut Skill ios-tweak-development "gebrochene Injektionskette")
1. **Power-Cycle** (komplett aus, 20s, an) — Userspace-Reboot reicht NICHT.
2. **Re-Jailbreak** aus Dopamine-App (baut launchd-Kette + Trustcache neu).
3. Verifikation: Revolut+Safari öffnen → `bash -c "exec 3<>/dev/tcp/127.0.0.1/8788 && echo OFFEN || echo ZU"` muss OFFEN zeigen + `hb_injected.txt` im App-Container.
4. Erst wenn HeartBeat injiziert → RevolutGuard-Wirkung testen (Security Alert weg?).
5. Falls Alert bleibt: DetectionMonitor.plist auf Revolut gefiltert (`com.revolut.revolut`) — Logs unter `/var/mobile/Library/Logs/DetectionMonitor/` zeigen welche API zündet (Format `bundle api arg result suspicious`).

## Offene Neben-Baustelle (XS, iOS 18.5)
LordVCAM 3.0.28 swappt nur Preview; echter Sensor läuft im Hintergrund (Gesichtserkennung). Revolut/TikTok swappen nicht. XS-plist wurde um com.apple.camera/etc. erweitert (Half-Fix, nicht der Kern). Strukturelles Problem: 3.0-App-Hooks (AVCaptureVideoDataOutput) decken Analyse-Pfad nicht — wie 2.0 zentral (FigCapture/BWPixelTransferNode) müsste in cameracaptured portiert werden. Großes Einzelprojekt, noch nicht begonnen.
