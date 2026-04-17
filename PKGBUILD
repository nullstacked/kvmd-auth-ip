pkgname=kvmd-auth-ip
pkgver=1.0.0
pkgrel=1
pkgdesc="IP-based auto-login for PiKVM - detects user by Tailscale or static IP mapping"
arch=('any')
url="https://github.com/nullstacked/kvmd-auth-ip"
license=('GPL3')
depends=('kvmd')
install=kvmd-auth-ip.install
source=()
md5sums=()

package() {
    install -Dm755 "$srcdir/../files/apply-patches.sh" "$pkgdir/usr/share/kvmd-auth-ip/apply-patches.sh"
    install -Dm644 "$srcdir/../kvmd-auth-ip.hook" "$pkgdir/etc/pacman.d/hooks/kvmd-auth-ip.hook"
}
