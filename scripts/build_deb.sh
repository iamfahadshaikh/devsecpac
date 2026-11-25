#!/usr/bin/env bash
# Build Debian (.deb) package for devsecpac
set -euo pipefail

PACKAGE_NAME="devsecpac"
VERSION="3.0.0"
ARCHITECTURE="all"
# Build in Linux /tmp filesystem to satisfy dpkg-deb permission requirements (NTFS mounts default to 777)
BUILD_ROOT="/tmp/devsecpac_deb_build"
DEB_DIR="${BUILD_ROOT}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}"

echo "[*] Cleaning previous debian package workspace..."
rm -rf "${BUILD_ROOT}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/local/bin"
mkdir -p "${DEB_DIR}/usr/local/lib/python3/dist-packages"
mkdir -p "${DEB_DIR}/usr/share/man/man1"
mkdir -p "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}"
mkdir -p "dist"

echo "[*] Creating DEBIAN control metadata..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/control"
Package: devsecpac
Version: 3.0.0
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-pip, python3-rich, python3-yaml, python3-requests, git
Maintainer: Fahad Shaikh <iamfahadshaikh@users.noreply.github.com>
Description: Universal Autonomous DevSecOps Scanner Orchestrator
 DevSecPac inspects source code, container images, infrastructure-as-code manifests,
 and exposed APIs, unifies and deduplicates findings across 16 security engines,
 and pushes vulnerability assessments directly to DefectDojo ASPM and CI/CD pipelines.
EOF

echo "[*] Installing Python package into deb root..."
python3 -m pip install --no-deps --target "${DEB_DIR}/usr/local/lib/python3/dist-packages" .

echo "[*] Creating binary symlinks..."
cat << 'EOF' > "${DEB_DIR}/usr/local/bin/devsecpac"
#!/usr/bin/env python3
import sys
from devsec_cli.cli import main
if __name__ == '__main__':
    sys.exit(main())
EOF
chmod 755 "${DEB_DIR}/usr/local/bin/devsecpac"
ln -sf devsecpac "${DEB_DIR}/usr/local/bin/devsec"

echo "[*] Installing roff man pages..."
gzip -9c man/man1/devsecpac.1 > "${DEB_DIR}/usr/share/man/man1/devsecpac.1.gz"
ln -sf devsecpac.1.gz "${DEB_DIR}/usr/share/man/man1/devsec.1.gz"

echo "[*] Installing documentation..."
cp README.md "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}/README.md"

echo "[*] Setting directory permissions..."
chmod 755 "${DEB_DIR}/DEBIAN"
chmod 644 "${DEB_DIR}/DEBIAN/control"

echo "[*] Building Debian package..."
dpkg-deb --build --root-owner-group "${DEB_DIR}" "dist/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"

echo "[SUCCESS] Debian package built: dist/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"
