# PLDT WiFi Manager

A local web-based management interface for PLDT HG6145D2 routers that provides device whitelisting, automatic MAC filtering, and network access control.

## Features

- **Device Management**: View all connected devices with real-time status
- **Auto-Whitelisting**: Devices on private SSIDs/LAN are automatically whitelisted
- **Public SSID Control**: Grant temporary 6-hour access to public SSID devices
- **MAC Randomization Cleanup**: Automatically removes stale MAC addresses after 6 hours
- **Persistent Configuration**: Settings survive server restarts
- **Background Automation**: Cleanup runs autonomously without user interaction

## Requirements

- Windows 10/11
- Python 3.8+
- Administrator privileges (for network configuration)
- PLDT HG6145D2 router (or compatible model)

## Installation

1. **Run setup as Administrator**:
   ```batch
   setup.bat
   ```

   This will:
   - Install Python dependencies to local `libs/` folder
   - Configure Windows Firewall (port 80)
   - Set static IP to 192.168.1.200
   - Create scheduled task to run on startup

2. **Access the interface**:
   ```
   http://192.168.1.200
   ```

## Configuration

1. Navigate to **Settings**
2. Enter your router credentials (same as https://192.168.1.1)
3. Add your private SSIDs to enable auto-whitelisting

## File Structure

```
├── server.py          # Flask backend server
├── components.js      # Frontend UI components
├── styles.css         # CSS styling
├── index.html         # Main device list page
├── settings.html      # Settings page
├── config.json        # User configuration (auto-generated)
├── setup.bat          # Installation script
├── uninstall.bat      # Removal script
├── requirements.txt   # Python dependencies
└── study_data.txt     # Router API documentation
```

## Management Commands

```batch
# Stop server
taskkill /f /im python.exe

# Start server
schtasks /run /tn PLDTWiFiManager

# View logs
type logs\server.log

# Uninstall
uninstall.bat
```

## Status Indicators

| Color | Meaning |
|-------|---------|
| 🟢 Green | Device is whitelisted (has internet access) |
| 🔴 Red | Device is not whitelisted (blocked) |
| ⚪ Gray | No router credentials configured |

## How It Works

1. **Private Connections** (LAN ports, private SSIDs):
   - Automatically whitelisted when detected
   - Tracked for 6-hour inactivity cleanup

2. **Public Connections** (guest SSIDs):
   - Require manual "Connect" to whitelist
   - Automatically removed after 6 hours

## License

For personal use only. Not affiliated with PLDT.
