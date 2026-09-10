# Third-party notices

The Windows build bundles the following third-party runtime components.

## tun2socks

- Project: `xjasonlyu/tun2socks`
- Version bundled by CI: `v2.7.0`
- License: MIT
- Windows AMD64 archive SHA-256: `c5d46e9452f6c9cc7c15ab9158d6d6a0169ceecd6bca019ce476b49337d2be43`

Copyright and license terms are provided by the upstream project.

## Wintun

- Project: Wintun, by WireGuard LLC / Jason A. Donenfeld
- Version bundled by CI: `0.14.1`
- Official archive SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`

The official Wintun archive contains signed redistributable DLLs and the applicable license terms. The Windows build uses the signed `amd64/wintun.dll` from that archive.

## PyInstaller

- Version used to build the standalone executable: `6.22.2`
- PyInstaller is a build-time dependency and is not the VPN transport itself.
