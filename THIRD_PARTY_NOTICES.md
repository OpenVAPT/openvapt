# Third-Party Notices

OpenVAPT has no third-party Go module dependencies (see `go.mod`). The compiled program statically includes the Go standard library and runtime.

## Go Standard Library

Copyright 2009 The Go Authors. Licensed under the BSD 3-Clause License:

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of Google LLC nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Referenced, Not Included

Check descriptions cite public documents (OWASP, NIST, FIRST, MITRE, RFCs, vendor manuals). Their text is not copied into OpenVAPT beyond short titles. CIS Benchmark topics are named only; no CIS text is included.

## Website Only (not part of the openvapt program)

The openvapt.com website self-hosts these files, vendored by `site/scripts/vendor.mjs`. Their licence texts are published at `assets/vendor/LICENSES/` and versions in `assets/vendor/VERSIONS.txt`.

| Package | Used For | Licence |
|---|---|---|
| AG Grid Community | Check catalogue data grid | MIT |
| Apache ECharts | Charts | Apache-2.0 |
| Lucide (lucide-static) | Icons, inlined as SVG at build time | ISC |
| IBM Plex Sans and IBM Plex Mono | Typography | SIL Open Font License 1.1 |
| Tailwind CSS | Build-time CSS generation (not shipped as code) | MIT |

The design follows the public design guidance of Ant Design (MIT) and IBM Carbon (Apache-2.0); no code from those libraries is shipped.
The IBM Plex npm packages contain an install-time telemetry configuration; the build installs with `--ignore-scripts`, so it never runs, and only the font files are copied.
