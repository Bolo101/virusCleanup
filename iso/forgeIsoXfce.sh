#!/bin/bash

# Exit on any error
set -e

# Variables
ISO_NAME="$(pwd)/shadowClone-v0.1.iso"
WORK_DIR="$(pwd)/debian-live-build"
CODE_DIR="$(pwd)/../code"
DATABASE_DIR="$(pwd)/../database"

# Install necessary tools
echo "Installing live-build and required dependencies..."
sudo apt update
sudo apt install -y live-build python3 calamares calamares-settings-debian syslinux

# Create working directory
echo "Setting up live-build workspace..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Clean previous build
sudo lb clean

# Configure live-build
echo "Configuring live-build for Debian Bookworm..."
lb config --distribution=bookworm --architectures=amd64 \
    --linux-packages=linux-image \
    --debian-installer=live \
    --bootappend-live="boot=live components hostname=secure-eraser username=user locales=fr_FR.UTF-8 keyboard-layouts=fr"

# Add Debian repositories for firmware
mkdir -p config/archives
cat << EOF > config/archives/debian.list.chroot
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
EOF

# Add required packages
echo "Adding required packages..."
mkdir -p config/package-lists/
cat << EOF > config/package-lists/custom.list.chroot
coreutils
parted
ntfs-3g
python3
python3-tk
dosfstools
firmware-linux-free
firmware-linux-nonfree
calamares
calamares-settings-debian
squashfs-tools
xorg
xfce4
network-manager
network-manager-gnome
sudo
live-boot
live-config
live-tools
tasksel
tasksel-data
console-setup
keyboard-configuration
cryptsetup
dmsetup
clamav
clamav-daemon
libclamav11
EOF

# Set system locale and keyboard layout to French AZERTY
echo "Configuring live system for French AZERTY keyboard..."
mkdir -p config/includes.chroot/etc/default/

# Set default locale to French
cat << EOF > config/includes.chroot/etc/default/locale
LANG=fr_FR.UTF-8
LC_ALL=fr_FR.UTF-8
EOF

# Set keyboard layout to AZERTY
cat << EOF > config/includes.chroot/etc/default/keyboard
XKBMODEL="pc105"
XKBLAYOUT="fr"
XKBVARIANT="azerty"
XKBOPTIONS=""
EOF

# Set console keymap for tty
cat << EOF > config/includes.chroot/etc/default/console-setup
ACTIVE_CONSOLES="/dev/tty[1-6]"
CHARMAP="UTF-8"
CODESET="Lat15"
XKBLAYOUT="fr"
XKBVARIANT="azerty"
EOF

# Configure ClamAV for offline operation
echo "Configuring ClamAV for offline system..."
mkdir -p config/includes.chroot/etc/clamav/

# Configure clamd (ClamAV daemon) - disabled freshclam integration
cat << EOF > config/includes.chroot/etc/clamav/clamd.conf
# ClamAV daemon configuration for offline live system
LogFile /var/log/clamav/clamav.log
LogFileUnlock no
LogFileMaxSize 0
LogTime yes
LogClean no
LogSyslog yes
LogFacility LOG_LOCAL6
LogVerbose no
ExtendedDetectionInfo yes
PidFile /var/run/clamav/clamd.pid
LocalSocket /var/run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
FixStaleSocket yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 15
StreamMaxLength 25M
MaxThreads 12
ReadTimeout 180
CommandReadTimeout 30
SendBufTimeout 200
MaxQueue 100
IdleTimeout 30
ExcludePath ^/proc/
ExcludePath ^/sys/
ExcludePath ^/dev/
ExcludePath ^/run/
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly no
SelfCheck 3600
Foreground no
Debug no
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanMail yes
PhishingSignatures yes
PhishingScanURLs yes
HeuristicScanPrecedence no
StructuredDataDetection no
StructuredMinCreditCardCount 3
StructuredMinSSNCount 3
StructuredSSNFormatNormal yes
StructuredSSNFormatStripped no
ScanHTML yes
ScanArchive yes
ArchiveBlockEncrypted no
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
MaxEmbeddedPE 10M
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
MaxPartitions 50
MaxIconsPE 100
PCREMatchLimit 10000
PCRERecMatchLimit 5000
PCREMaxFileSize 25M
ScanOnAccess no
OnAccessMaxFileSize 5M
OnAccessIncludePath /home
OnAccessExcludePath /var/log/
OnAccessExcludeUID 0
DisableCertCheck no
AlgorithmicDetection yes
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 60000
EOF

# Create minimal freshclam config (for compatibility, but won't be used automatically)
cat << EOF > config/includes.chroot/etc/clamav/freshclam.conf
# Freshclam configuration (offline mode - use update_clamav_db.py instead)
DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose yes
LogSyslog yes
LogFacility LOG_LOCAL6
LogFileMaxSize 0
LogRotate yes
LogTime yes
Foreground no
Debug no
MaxAttempts 5
DatabaseOwner clamav
AllowSupplementaryGroups no
PidFile /var/run/clamav/freshclam.pid
ConnectTimeout 30
ReceiveTimeout 0
TestDatabases yes
ScriptedUpdates yes
CompressLocalDatabase no
Bytecode yes
# Database mirrors (for reference - use offline updater instead)
DatabaseMirror db.local.clamav.net
DatabaseMirror database.clamav.net
EOF

# Create ClamAV log directory structure
mkdir -p config/includes.chroot/var/log/clamav
mkdir -p config/includes.chroot/var/run/clamav
mkdir -p config/includes.chroot/var/lib/clamav
mkdir -p config/includes.chroot/usr/local/bin

# Set up ClamAV permissions script (without auto-update)
cat << EOF > config/includes.chroot/usr/local/bin/setup-clamav.sh
#!/bin/bash
# Setup ClamAV permissions for offline operation

# Create clamav user if it doesn't exist
if ! getent passwd clamav > /dev/null; then
    adduser --system --group --home /var/lib/clamav --shell /bin/false clamav
fi

# Set proper ownership and permissions
chown -R clamav:clamav /var/lib/clamav
chown -R clamav:clamav /var/log/clamav
chown -R clamav:clamav /var/run/clamav

chmod 755 /var/lib/clamav
chmod 755 /var/log/clamav
chmod 755 /var/run/clamav

# Set file permissions
chmod 644 /etc/clamav/freshclam.conf
chmod 644 /etc/clamav/clamd.conf

# Create database directory structure
mkdir -p /var/lib/clamav

# Create placeholder database files if they don't exist
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    touch /var/lib/clamav/main.cvd
fi

if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
    touch /var/lib/clamav/daily.cld
fi

if [ ! -f /var/lib/clamav/bytecode.cvd ] && [ ! -f /var/lib/clamav/bytecode.cld ]; then
    touch /var/lib/clamav/bytecode.cld
fi

chown clamav:clamav /var/lib/clamav/*

echo "ClamAV setup completed (offline mode)"
echo "Use update_clamav_db.py script to update virus database"
EOF

chmod +x config/includes.chroot/usr/local/bin/setup-clamav.sh

# Create systemd service to setup ClamAV on boot (without freshclam auto-start)
mkdir -p config/includes.chroot/etc/systemd/system/
cat << EOF > config/includes.chroot/etc/systemd/system/setup-clamav.service
[Unit]
Description=Setup ClamAV permissions and database for offline operation
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-clamav.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable only the setup service (not freshclam)
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
ln -sf /etc/systemd/system/setup-clamav.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/setup-clamav.service

# Copy all files from CODE_DIR to /usr/local/bin
echo "Copying all files from $CODE_DIR to /usr/local/bin..."
mkdir -p config/includes.chroot/usr/local/bin/
cp -r "$CODE_DIR"/* config/includes.chroot/usr/local/bin/
chmod +x config/includes.chroot/usr/local/bin/*

# Copy the ClamAV database updater script to USB root directory
echo "Copying ClamAV database updater script to USB root..."
if [ -f "$DATABASE_DIR/update_clamav_db.py" ]; then
    # Copy to the root of the live system (will appear at USB root when booted)
    cp "$DATABASE_DIR/update_clamav_db.py" config/includes.chroot/
    chmod +x config/includes.chroot/update_clamav_db.py
    echo "✅ ClamAV database updater script copied successfully"
else
    echo "❌ WARNING: ClamAV database updater script not found at $DATABASE_DIR/update_clamav_db.py"
    echo "   The script will not be available on the USB root directory"
    echo "   Expected path: $DATABASE_DIR/update_clamav_db.py"
fi

# Create a README file for the database updater in USB root
echo "Creating README for ClamAV database updater..."
cat << 'EOF' > config/includes.chroot/README_ClamAV_Update.txt
ClamAV Database Update Instructions
===================================

This bootable USB includes a ClamAV database updater script that allows you to
update the virus definitions while the USB is mounted on a computer with internet.

HOW TO UPDATE THE DATABASE:
--------------------------

1. Boot a computer with internet connection using this USB
2. Open a terminal
3. Navigate to the USB root directory (usually /cdrom or the mount point)
4. Run the updater script:
   
   python3 update_clamav_db.py

   OR if you're not in the USB root directory:
   
   python3 update_clamav_db.py /path/to/usb/root

WHAT THE SCRIPT DOES:
--------------------

- Downloads the latest ClamAV virus database files from official mirrors
- Installs them in the USB's /var/lib/clamav directory  
- Creates a backup of existing database files
- Verifies the integrity of downloaded files
- Creates an update log with timestamp and file information

REQUIREMENTS:
------------

- Internet connection
- Python 3 (included in this USB)
- Write access to the USB (automatic when booted from USB)

The updated database will be persistent and available for all future
virus scans performed with this bootable USB.

For troubleshooting, check the script output messages for detailed
information about any errors that may occur during the update process.
EOF

# Build the ISO
echo "Building the ISO..."
sudo lb build

# Move the ISO to the desired location
if [ -f "live-image-amd64.hybrid.iso" ]; then
    mv live-image-amd64.hybrid.iso "$ISO_NAME"
    echo "✅ ISO created successfully: $ISO_NAME"
elif [ -f "binary.hybrid.iso" ]; then
    mv binary.hybrid.iso "$ISO_NAME"
    echo "✅ ISO created successfully: $ISO_NAME"
else
    echo "❌ Error: ISO file not found after build"
    exit 1
fi

# Cleanup
echo "Cleaning up build environment..."
sudo lb clean

echo ""
echo "🎉 Build completed successfully!"
echo "📦 ISO file: $ISO_NAME"
echo ""
echo "Summary of included components:"
echo "- Main application files from: $CODE_DIR"
echo "- ClamAV database updater: update_clamav_db.py (from $DATABASE_DIR)"
echo "- ClamAV offline configuration with placeholder databases"
echo "- French AZERTY keyboard layout"
echo "- XFCE desktop environment"
echo "- Network connectivity tools"
echo ""
echo "The ISO is ready to use!"