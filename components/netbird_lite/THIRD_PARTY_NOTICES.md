# Third-party notices

netbird-lite itself is licensed under Apache-2.0 (see `LICENSE` and `NOTICE`). It contains or is derived from the
following third-party work. Each component keeps its own licence.

| Component | Where | Licence | Upstream |
|---|---|---|---|
| wireguard-lwip | `components/netbird_lite/vendor/wireguard-lwip/` | BSD-3-Clause | https://github.com/smartalock/wireguard-lwip (commit `c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d`) |
| &nbsp;&nbsp;BLAKE2s reference code | `.../crypto/refc/blake2s.*` | Simplified BSD (IETF Trust, RFC code component) | RFC 7693 |
| &nbsp;&nbsp;poly1305-donna | `.../crypto/refc/poly1305-donna*` | public domain or MIT | https://github.com/floodyberry/poly1305-donna |
| &nbsp;&nbsp;X25519 (STROBE) | `.../crypto/refc/x25519.*` | MIT (`x25519-license.txt`) | https://sourceforge.net/p/strobe |
| nanopb runtime 0.4.9.1 | `components/netbird_lite/vendor/nanopb/` | zlib | https://github.com/nanopb/nanopb |
| TweetNaCl 20140427 (unmodified) | `components/netbird_lite/vendor/tweetnacl/` | public domain | https://tweetnacl.cr.yp.to/ |
| HPACK Huffman code table | `components/netbird_lite/src/nbl_huff.inc` | MIT (generated from nghttp2's copy of the RFC 7541 table) | RFC 7541 Appendix B, https://github.com/nghttp2/nghttp2 |
| NetBird protocol definitions (subset) | `components/netbird_lite/proto/*.proto`, generated `proto_gen/` | BSD-3-Clause | https://github.com/netbirdio/netbird (`shared/management/proto`, `shared/signal/proto`, v0.80.0) |
| nghttp2 (optional, `CONFIG_NBL_H2_NGHTTP2` only) | fetched by the ESP-IDF component manager, not vendored | MIT | https://components.espressif.com/components/espressif/nghttp |

## wireguard-lwip

Vendored from the commit above. `wireguardif.c` and `wireguard-platform.h` are modified;
`NBL-PATCH.diff` in the same directory is the exact diff against upstream. All other files are
unmodified. The licence text is in `vendor/wireguard-lwip/LICENSE`:

> Copyright (c) 2021 Daniel Hope (www.floorsense.nz). All rights reserved.
> Redistribution and use in source and binary forms, with or without modification, are permitted
> provided that the conditions in `vendor/wireguard-lwip/LICENSE` are met.

## nanopb

> Copyright (c) 2011 Petteri Aimonen. Licensed under the zlib licence, see
> `vendor/nanopb/LICENSE.txt`.

## TweetNaCl

TweetNaCl by Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe
and Sjaak Smetsers is "a self-contained public-domain C library" (https://tweetnacl.cr.yp.to/).
Only the `randombytes()` hook is supplied by netbird-lite (`src/nbl_crypto.c`, backed by the ESP32
hardware RNG).

## NetBird protocol definitions

`proto/nbl_mgmt.proto` and `proto/nbl_signal.proto` restate the subset of messages this client
needs. Message names, field names and field numbers must match upstream for wire compatibility;
the files themselves were written for this project. Upstream licence for the referenced files:

```
BSD 3-Clause License

Copyright (c) 2022 NetBird GmbH & AUTHORS

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
   and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

NetBird's server components (`management/`, `signal/`, `relay/`, `combined/` in the upstream
repository) are AGPL-3.0. netbird-lite contains no code from them; it is an independent client
that speaks the same protocols.

## HPACK Huffman code table

`src/nbl_huff.inc` is the static Huffman code of RFC 7541, Appendix B, extracted from nghttp2's
table and re-encoded (right-aligned codes). nghttp2 licence:

```
The MIT License

Copyright (c) 2012, 2014, 2015, 2016 Tatsuhiro Tsujikawa
Copyright (c) 2012, 2014, 2015, 2016 nghttp2 contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Trademarks

NetBird is developed by NetBird GmbH. WireGuard and the WireGuard logo are registered trademarks
of Jason A. Donenfeld. netbird-lite is an independent project and is not affiliated with, endorsed
by or supported by NetBird GmbH or the WireGuard project; the names are used only to describe
compatibility.
