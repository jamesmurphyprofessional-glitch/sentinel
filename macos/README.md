# Sentinel

A simple macOS helper that explains, in everyday language:

1. Which **Mac settings** to turn on (firewall, FileVault, updates) and which **sharing** to turn off
2. **Who is on your Wi-Fi**, and whether those devices are sharing files or allowing remote access
3. **Safety tips** for the router, public Wi-Fi, passwords, and common scams

There is no malware scanner. Apple’s built-in protections (XProtect, Gatekeeper, Automatic Updates) already cover that job. Sentinel is for the boring switches and habits that actually make a home safer.

It does **not** try passwords, break into devices, or send attack traffic.

## What you will see

| Place | What it is for |
|---|---|
| **Home** | Start here. Confirm this is your network, then check this Mac and look at Wi-Fi. |
| **This Mac** | Firewall, disk encryption, sharing, guest login, updates — with the exact System Settings clicks. |
| **Your Wi-Fi** | Devices on the same network, described in plain language (router, printer, camera, another computer). |
| **Safety tips** | Router password, guest Wi-Fi, public hotspots, Apple ID, phishing, backups. |
| **What we found** | A single list of things to fix, plus a saveable report. |

## Requirements

- Apple Silicon Mac
- macOS 14 or later
- Local Network permission when macOS asks (only needed for the Wi-Fi look)

## Build

```bash
cd project/Sentinel
./build.sh
```

Or open `Sentinel.xcodeproj` in Xcode and run the Sentinel scheme.

## Use

1. Open Sentinel.
2. Press **Check this Mac** and follow the “how to change this” steps.
3. On Home, tick **This is my network**.
4. Press **Look at my Wi-Fi** and see if you recognize every device.
5. Read **Safety tips** for the router and everyday habits.

Only look at Wi-Fi at home, at work, or on a network you are allowed to check — not at a café.

## Limits

- This is a helper, not a professional security test
- Devices that ignore pings can be missed
- Apple’s own malware protection still runs separately
