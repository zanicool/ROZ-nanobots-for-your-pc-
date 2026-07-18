# Maintainer: Zani <zanicool@github>
pkgname=roz-nanobots
pkgver=6.0.0
pkgrel=1
pkgdesc="Self-healing Linux daemon — like Iron Man's nanobots, but for your PC"
arch=('any')
url="https://github.com/zanicool/ROZ-nanobots-for-your-pc-"
license=('MIT')
depends=('python' 'systemd')
install=roz-nanobots.install
optdepends=(
    'smartmontools: SMART disk health monitoring'
    'docker: Docker container healing'
    'ufw: Firewall status checks'
)
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')
backup=('etc/nanobot/config.json')

package() {
    cd "ROZ-nanobots-for-your-pc--${pkgver}"

    # Install main script
    install -Dm755 nanobot.py "${pkgdir}/opt/nanobot/nanobot.py"

    # Install systemd service
    install -Dm644 nanobot.service "${pkgdir}/usr/lib/systemd/system/nanobot.service"

    # Install license
    install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"

    # Install docs
    install -Dm644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"

    # Create config directory
    install -dm755 "${pkgdir}/etc/nanobot"
}
