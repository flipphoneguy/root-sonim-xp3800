# Root Manager for Sonim XP5800

## Overview
**Root Manager** is a lightweight, standalone Android application designed specifically for the **Sonim XP5800 (XP5s)**. It utilizes the CVE-2019-2215 vulnerability to provide temporary root access without requiring an unlocked bootloader.

Because the Sonim XP5800 has a locked bootloader and a read-only system partition, this app uses a "systemless" overlay approach. It mounts a temporary file system over `/sbin` to inject the `su` binary. This means root access is lost upon reboot, but this app includes a "Run on Boot" feature to automatically re-enable it every time you restart your phone.

## Features
* **One-Click Root:** Enable or disable root access instantly from the main interface.
* **Boot Persistence:** Automatically re-applies root access when the device restarts.
* **Blacklist Manager:** A built-in security tool that allows you to deny root access to specific applications while allowing everything else by default.
* **Minimalist UI:** Designed with a clean, high-contrast interface that is fully compatible with D-Pad navigation.

## Installation
1.  **Download the APK:** Download from releases below.
2.  **Install:** Install the resulting `RootManager.apk` on your Sonim XP5800.
3.  **Initialize:** Open the app once. It will extract the necessary files to its internal storage.
4.  **Root:** Click the "Install Root" button.

## How it Works (Technical)
* **The Exploit:** The app carries a custom compiled binary (`su`) that targets a Use-After-Free vulnerability in the kernel binder driver.
* **The Overlay:** When executed, it mounts a `tmpfs` (RAM disk) over `/sbin`.
* **The Injection:** It copies `su` and `nsenter` into this RAM disk. Since `/sbin` is in the global Android path, all apps can now find and use `su`.
* **Security:** The `su` binary is modified to check a configuration file located in the app's private data directory (`/data/data/com.flipphoneguy.root/files/blacklist.txt`).

## Disclaimer
This software leverages a kernel vulnerability to gain elevated privileges. While it has been tested on the Sonim XP5800, please use it responsibly. I am not responsible for any bricked devices or voided warranties.

**Created by flipphoneguy**
