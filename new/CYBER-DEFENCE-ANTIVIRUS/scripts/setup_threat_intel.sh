#!/usr/bin/env bash
set -euo pipefail

# CyberShield threat intelligence setup helper.
# Downloads/updates YARA sources and writes local custom rules.
# NOTE: Requires network access and optional root privileges for system paths.

RULES_DIR="${RULES_DIR:-/var/lib/cybershield/yara-rules}"
mkdir -p "${RULES_DIR}"

clone_or_pull() {
  local repo="$1"
  local dir="$2"
  if [[ -d "${dir}/.git" ]]; then
    git -C "${dir}" pull --ff-only
  else
    git clone --depth 1 "${repo}" "${dir}"
  fi
}

clone_or_pull "https://github.com/elastic/protections-artifacts.git" "${RULES_DIR}/elastic"
clone_or_pull "https://github.com/InQuest/awesome-yara.git" "${RULES_DIR}/awesome-yara"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "https://bazaar.abuse.ch/export/yara/" -o "${RULES_DIR}/malware_bazaar.yar" || true
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${RULES_DIR}/malware_bazaar.yar" "https://bazaar.abuse.ch/export/yara/" || true
fi

cat > "${RULES_DIR}/cybershield_custom.yar" <<'EOF'
rule Ransomware_Generic {
  meta:
    description = "Generic ransomware behavior detection"
    author = "CyberShield"
    severity = "critical"
  strings:
    $s1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
    $s2 = ".locked" nocase
    $s3 = "bitcoin" nocase
    $s4 = "ransom" nocase
    $f1 = "CryptEncrypt"
    $f2 = "DeleteShadowCopies"
  condition:
    2 of ($s*) or any of ($f*)
}

rule Backdoor_Common_Ports {
  meta:
    description = "Detects backdoor using common malware ports"
    severity = "high"
  strings:
    $p1 = "4444"
    $p2 = "1337"
    $p3 = "31337"
    $p4 = "6667"
  condition:
    any of them
}

rule Trojan_Downloader {
  meta:
    description = "Detects trojan downloader behavior"
    severity = "critical"
  strings:
    $d1 = "URLDownloadToFile"
    $d2 = "wget http"
    $d3 = "curl -O"
    $e1 = "ShellExecute"
    $e2 = "CreateProcess"
  condition:
    (any of ($d*)) and (any of ($e*))
}
EOF

echo "Threat intel setup complete at ${RULES_DIR}"
