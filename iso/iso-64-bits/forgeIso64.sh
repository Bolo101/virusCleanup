#!/usr/bin/env bash
# forgeIso64.sh — Debian Trixie amd64 — version corrigée v4
# Corrections incluses :
# - policykit-1 remplacé par polkitd/pkexec ;
# - groupe scanner déjà présent géré correctement ;
# - utils.py inclus ;
# - copie des PDF et des images dans l'ISO ;
# - session graphique LightDM/OpenBox robuste.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ISO_NAME="${ISO_NAME:-$PWD/bastion-antiviral-v1.0.iso}"
WORK_DIR="${WORK_DIR:-$PWD/debian-live-build}"
CODE_DIR="${CODE_DIR:-$PWD/../../code}"
PDF_DIR="${PDF_DIR:-$PWD/../../pdf}"
IMG_DIR="${IMG_DIR:-$PWD/../../img}"
BOOT_PARAMS="boot=live components quiet splash hostname=antivirus-usb username=scanner locales=fr_FR.UTF-8 keyboard-layouts=fr noeject nopersistent"

GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
ok(){ printf '%b\n' "${GREEN}✅ $*${RESET}"; }
warn(){ printf '%b\n' "${YELLOW}⚠ $*${RESET}"; }
step(){ printf '\n%b\n' "${YELLOW}▶▶ $*${RESET}"; }
die(){ printf '%b\n' "${RED}❌ $*${RESET}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die 'Lance ce script avec sudo/root.'

step 'Vérification des prérequis'
for cmd in lb wget curl python3 unzip rsync xorriso; do
  command -v "$cmd" >/dev/null 2>&1 || die "Commande manquante : $cmd"
done
[[ -d "$CODE_DIR" ]] || die "Répertoire code introuvable : $CODE_DIR"
for f in config.py log_handler.py admin_auth.py usb_manager.py db_manager.py scanner.py gui.py main.py pdf_viewer.py utils.py; do
  [[ -f "$CODE_DIR/$f" ]] || die "Fichier absent : $CODE_DIR/$f"
done
ok 'Prérequis OK'

step 'Vérification des ressources PDF et images'
if [[ -d "$PDF_DIR" ]]; then
  PDF_COUNT=$(find "$PDF_DIR" -maxdepth 1 -type f -iname '*.pdf' | wc -l)
  ok "$PDF_COUNT fichier(s) PDF trouvé(s) dans $PDF_DIR"
else
  PDF_COUNT=0
  warn "Dossier PDF absent : $PDF_DIR"
fi
if [[ -d "$IMG_DIR" ]]; then
  IMG_COUNT=$(find "$IMG_DIR" -maxdepth 1 -type f | wc -l)
  ok "$IMG_COUNT fichier(s) image trouvé(s) dans $IMG_DIR"
else
  IMG_COUNT=0
  warn "Dossier images absent : $IMG_DIR"
fi

step 'Installation des outils de build'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y live-build xorriso syslinux isolinux syslinux-utils wget curl \
  python3 unzip rsync ca-certificates git

step 'Préparation du répertoire de travail'
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
lb clean --purge >/dev/null 2>&1 || true

step 'Configuration live-build'
lb config \
  --distribution trixie \
  --architectures amd64 \
  --linux-packages linux-image \
  --debian-installer none \
  --bootappend-live "$BOOT_PARAMS" \
  --bootloaders 'syslinux,grub-efi' \
  --binary-images iso-hybrid \
  --apt-options '--yes'

mkdir -p config/archives config/package-lists config/hooks/normal
cat > config/archives/debian.list.chroot <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
EOF

cat > config/package-lists/custom.list.chroot <<'EOF'
coreutils
sudo
systemd
udev
live-boot
live-config
live-tools
locales
console-setup
keyboard-configuration
xorg
xserver-xorg-video-all
xserver-xorg-input-all
x11-xserver-utils
dbus
dbus-x11
polkitd
pkexec
openbox
lightdm
xfwm4
xfce4-session
xfce4-terminal
xterm
network-manager
wget
curl
ca-certificates
python3
python3-tk
python3-pip
python3-pil
python3-pil.imagetk
python3-fitz
yara
python3-yara
clamav
clamav-daemon
clamav-freshclam
parted
ntfs-3g
dosfstools
exfatprogs
util-linux
usbutils
pciutils
acpi
grub-common
grub-pc-bin
grub-efi-amd64-bin
grub-pc
os-prober
firmware-linux-free
firmware-linux-nonfree
xdotool
xbindkeys
unclutter
whiptail
rsync
unzip
squashfs-tools
EOF

step 'Copie du code applicatif'
mkdir -p config/includes.chroot/opt/usb-antivirus
cp -a "$CODE_DIR"/*.py config/includes.chroot/opt/usb-antivirus/
ok "$(find config/includes.chroot/opt/usb-antivirus -name '*.py' | wc -l) fichier(s) Python copié(s)"

# Les chemins sont /opt/pdf et /opt/img car pdf_viewer.py et gui.py utilisent
# des chemins relatifs au dossier /opt/usb-antivirus.
step 'Copie des PDF et des images'
mkdir -p config/includes.chroot/opt/pdf config/includes.chroot/opt/img

if [[ -d "$PDF_DIR" ]]; then
  find "$PDF_DIR" -maxdepth 1 -type f -iname '*.pdf' -exec cp -a {} config/includes.chroot/opt/pdf/ \;
  COPIED_PDF=$(find config/includes.chroot/opt/pdf -maxdepth 1 -type f -iname '*.pdf' | wc -l)
  ok "$COPIED_PDF PDF copié(s) dans /opt/pdf"
else
  warn 'Aucun PDF copié : dossier source absent.'
fi

if [[ -d "$IMG_DIR" ]]; then
  find "$IMG_DIR" -maxdepth 1 -type f -exec cp -a {} config/includes.chroot/opt/img/ \;
  COPIED_IMG=$(find config/includes.chroot/opt/img -maxdepth 1 -type f | wc -l)
  ok "$COPIED_IMG image(s) copiée(s) dans /opt/img"
else
  warn 'Aucune image copiée : dossier source absent.'
fi

cat > config/hooks/normal/0300-system-config.hook.chroot <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail

install -d -m 0755 /etc/X11/xorg.conf.d /etc/xdg/openbox /etc/lightdm/lightdm.conf.d
sed -i '/^fr_FR.UTF-8 UTF-8$/d' /etc/locale.gen || true
echo 'fr_FR.UTF-8 UTF-8' >> /etc/locale.gen
locale-gen fr_FR.UTF-8
update-locale LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8

# Le groupe scanner peut être précréé par live-build.
if ! getent group scanner >/dev/null 2>&1; then
  groupadd --system scanner
fi
if ! id scanner >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --gid scanner \
    --groups sudo,plugdev,cdrom,dialout scanner
  echo 'scanner:scanner' | chpasswd
else
  usermod --shell /bin/bash --gid scanner scanner
  usermod --append --groups sudo,plugdev,cdrom,dialout scanner
fi

echo 'scanner ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/scanner
chmod 0440 /etc/sudoers.d/scanner

install -d -m 0755 /opt/usb-antivirus /opt/pdf /opt/img /mnt/avscan_usb /var/log/usb-antivirus
chmod 0777 /mnt/avscan_usb
chown scanner:scanner /var/log/usb-antivirus

cat > /etc/xdg/openbox/rc.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <applications>
    <application class="*">
      <decor>no</decor>
      <fullscreen>yes</fullscreen>
      <maximized>true</maximized>
      <layer>above</layer>
      <focus>yes</focus>
    </application>
  </applications>
  <desktops><number>1</number></desktops>
</openbox_config>
XML
cat > /etc/xdg/openbox/autostart <<'EOF'
# Application lancée par la session LightDM.
EOF

cat > /etc/X11/xorg.conf.d/20-antivirus-display.conf <<'XORG'
Section "ServerFlags"
    Option "DontZap" "true"
    Option "BlankTime" "0"
    Option "StandbyTime" "0"
    Option "SuspendTime" "0"
    Option "OffTime" "0"
EndSection
Section "Monitor"
    Identifier "Monitor0"
    Option "DPMS" "false"
EndSection
XORG

cat > /usr/local/bin/usb-antivirus <<'WRAPPER'
#!/usr/bin/env bash
set -u
export DISPLAY="${DISPLAY:-:0}"
export XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"
if [[ $(id -u) -eq 0 ]]; then
  exec python3 /opt/usb-antivirus/main.py "$@"
fi
exec sudo --preserve-env=DISPLAY,XAUTHORITY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS \
  python3 /opt/usb-antivirus/main.py "$@"
WRAPPER
chmod 0755 /usr/local/bin/usb-antivirus

cat > /usr/local/bin/usb-antivirus-session.sh <<'SESSION'
#!/usr/bin/env bash
set -u
USER_NAME="$(id -un)"
export DISPLAY="${DISPLAY:-:0}"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"
install -d -m 0700 "$XDG_RUNTIME_DIR" 2>/dev/null || true
chown "$USER_NAME:$USER_NAME" "$XDG_RUNTIME_DIR" 2>/dev/null || true
exec >>/var/log/usb-antivirus/session.log 2>&1
printf '\n=== session start %s ===\n' "$(date -Is)"
printf 'USER=%s DISPLAY=%s XAUTHORITY=%s XDG_RUNTIME_DIR=%s\n' \
  "$USER_NAME" "$DISPLAY" "$XAUTHORITY" "$XDG_RUNTIME_DIR"
xset s off -dpms 2>/dev/null || true
xset s noblank 2>/dev/null || true
xsetroot -solid '#101018' 2>/dev/null || true
exec dbus-run-session -- bash -c '
  openbox --replace >/tmp/openbox-antivirus.log 2>&1 &
  OB_PID=$!
  sleep 2
  xsetroot -solid "#101018" 2>/dev/null || true
  if grep -q "installer=1" /proc/cmdline 2>/dev/null; then
    exec xterm -title "USB Antivirus Scanner - Installation" \
      -fa Monospace -fs 12 -bg "#0d0d1a" -fg "#e0e0e0" \
      -e sudo /usr/local/bin/install-to-disk.sh
  fi
  crashes=0
  while :; do
    start=$(date +%s)
    /usr/local/bin/usb-antivirus
    rc=$?
    end=$(date +%s)
    [[ $rc -eq 0 ]] && break
    if (( end - start < 5 )); then crashes=$((crashes + 1)); else crashes=0; fi
    if (( crashes >= 3 )); then
      xterm -title "USB Antivirus - erreur de démarrage" \
        -fa Monospace -fs 12 -bg "#3a0d0d" -fg "#f0f0f0" \
        -e bash -c "echo Application arrêtée avec le code $rc; echo; tail -n 80 /var/log/usb-antivirus/session.log; echo; read -r -p \"Entrée pour réessayer...\"" || true
      crashes=0
    fi
    sleep 1
  done
  kill "$OB_PID" 2>/dev/null || true
  exec xfce4-session
'
SESSION
chmod 0755 /usr/local/bin/usb-antivirus-session.sh

cat > /usr/share/xsessions/usb-antivirus-live.desktop <<'DESKTOP'
[Desktop Entry]
Name=USB Antivirus Live
Comment=Scanner antiviral USB
Exec=/usr/local/bin/usb-antivirus-session.sh
TryExec=/usr/local/bin/usb-antivirus-session.sh
Type=Application
DESKTOP

cat > /etc/lightdm/lightdm.conf.d/50-antivirus-autologin.conf <<'LIGHTDM'
[Seat:*]
autologin-user=scanner
autologin-session=usb-antivirus-live
autologin-user-timeout=0
allow-guest=false
user-session=usb-antivirus-live
LIGHTDM

systemctl enable lightdm.service >/dev/null 2>&1 || true
systemctl disable clamav-freshclam.service >/dev/null 2>&1 || true
systemctl disable clamav-daemon.service >/dev/null 2>&1 || true
HOOK
chmod 0755 config/hooks/normal/0300-system-config.hook.chroot

cat > config/hooks/normal/0400-permissions.hook.chroot <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
chmod 0644 /opt/usb-antivirus/*.py
chmod 0755 /opt/usb-antivirus /usr/local/bin/usb-antivirus /usr/local/bin/usb-antivirus-session.sh
chown -R scanner:scanner /home/scanner
chown -R scanner:scanner /opt/pdf /opt/img
install -d -o scanner -g scanner -m 0755 /var/log/usb-antivirus
python3 -m compileall -q /opt/usb-antivirus
HOOK
chmod 0755 config/hooks/normal/0400-permissions.hook.chroot

step 'Création des menus de démarrage'
mkdir -p config/includes.binary/isolinux config/includes.binary/boot/grub
cat > config/includes.binary/isolinux/isolinux.cfg <<EOF
UI vesamenu.c32
DEFAULT live
TIMEOUT 150
PROMPT 0
MENU TITLE USB Antivirus Scanner
LABEL live
  MENU LABEL Demarrer le scanner
  MENU DEFAULT
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS}
LABEL install
  MENU LABEL Installer sur le disque
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS} installer=1
LABEL safe
  MENU LABEL Demarrer sans acceleration graphique
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS} nomodeset
EOF
echo '# custom menu' > config/includes.binary/isolinux/live.cfg

cat > config/includes.binary/boot/grub/grub.cfg <<EOF
set default=0
set timeout=15
menuentry 'Demarrer le scanner' {
  linux /live/vmlinuz ${BOOT_PARAMS}
  initrd /live/initrd.img
}
menuentry 'Installer sur le disque' {
  linux /live/vmlinuz ${BOOT_PARAMS} installer=1
  initrd /live/initrd.img
}
menuentry 'Demarrer sans acceleration graphique' {
  linux /live/vmlinuz ${BOOT_PARAMS} nomodeset
  initrd /live/initrd.img
}
EOF

step "Construction de l'ISO"
lb build 2>&1 | tee /tmp/lb-build.log

ISO_FOUND=''
for candidate in live-image-amd64.hybrid.iso live-image-amd64.iso binary.hybrid.iso; do
  if [[ -f "$candidate" ]]; then ISO_FOUND="$candidate"; break; fi
done
[[ -n "$ISO_FOUND" ]] || die 'ISO introuvable. Consulte /tmp/lb-build.log'
mv -f "$ISO_FOUND" "$ISO_NAME"
sha256sum "$ISO_NAME" | tee "$ISO_NAME.sha256"
lb clean >/dev/null 2>&1 || true
ok "ISO créée : $ISO_NAME"
