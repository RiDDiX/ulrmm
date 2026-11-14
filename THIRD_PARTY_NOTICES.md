# Third-party notices

This repository contains no third-party source code. The installer, the
container images and the running server install, download, build, pass on or
call the third-party software listed here. Each part keeps its own license
and copyright. UniversalLocal RMM's own code is licensed under FSL-1.1-ALv2,
see LICENSE.md. The dashboard and the agent have their own
THIRD_PARTY_NOTICES.md in their repositories. Every published image carries
LICENSE.md, NOTICE.md and this file under `/usr/share/doc/ulrmm/`.

## Installed or downloaded by the installer, contained in the images

- nginx (BSD-2-Clause), from the nginx.org packages; `ulrmm-nginx` image
  based on `nginx:1.28`
- PostgreSQL 18 (PostgreSQL License), from apt.postgresql.org; `postgres:18`
  image in Compose
- Redis from the distribution (BSD-3-Clause up to 7.2; RSALv2 OR SSPLv1
  for 7.4; AGPL-3.0 OR RSALv2 OR SSPLv1 from 8.0); `redis:8-alpine` image in
  Compose
- NATS server 2.14.4 (Apache-2.0), from its GitHub release with a pinned
  SHA-256; `nats:2.14.4-alpine` image in Compose
- Node.js 24 (MIT) from NodeSource; `node:24-bookworm-slim` in the
  `ulrmm-mesh` image
- MeshCentral 1.2.4 (Apache-2.0, https://github.com/Ylianst/MeshCentral) with
  archiver, otplib and pg (MIT), from npm; in the `ulrmm-mesh` image with their
  npm dependencies, whose license files stay in `node_modules`. MeshCentral
  itself contains mstsc.js (GPL-3.0), noVNC (MPL-2.0) and DOMPurify
  (Apache-2.0 OR MPL-2.0) as web clients.
- CPython 3.12 (PSF-2.0), built from the python.org source with a pinned
  SHA-256; `python:3.12-slim-bookworm` in the `ulrmm-api` image
- Go 1.27.3 toolchain (BSD-3-Clause), from go.dev with a pinned SHA-256
- RustDesk server hbbs/hbbr 1.1.16 (AGPL-3.0, https://github.com/rustdesk/rustdesk-server),
  optional, from its GitHub release
- NSIS (zlib/libpng license; its LZMA compression module CPL-1.0,
  https://nsis.sourceforge.io/), from the distribution packages and in the
  `ulrmm-api` image, to build the Windows agent installers
- Inno Setup 6.4.3 (Inno Setup License, https://jrsoftware.org/) under Wine
  (LGPL-2.1-or-later), Xvfb and xauth (MIT/X11), optional, as the fallback
  packer for the Windows agent installers
- osslsigncode (GPL-3.0), installed together with NSIS and in the
  `ulrmm-api` image, and rcodesign 0.29.0 (MPL-2.0), downloaded when macOS
  signing is set up; signing agents is optional. goversioninfo 1.4.1 (MIT)
  for the Windows version resource
- age (BSD-3-Clause) for encrypted backups, certbot (Apache-2.0) for Let's
  Encrypt certificates, and distribution tools such as git, curl, jq and
  openssl under their own licenses
- base images: `python:3.12-slim-bookworm`, `golang:1.27` (build stage only),
  `gcr.io/distroless/static-debian12`, `nginx:1.28`, `node:24-bookworm-slim`.
  Their Debian packages, some under GPL and LGPL, keep their copyright files
  in `/usr/share/doc`; the sources are at https://sources.debian.org and
  https://snapshot.debian.org.

## Passed on to managed devices

These are served by the RMM server or fetched by the agents. The server
operator passes them on and is bound by their licenses:

- the agent itself, see THIRD_PARTY_NOTICES.md of the agent repository; its
  Windows installer contains the NSIS runtime (the Inno Setup runtime when it
  was built with the fallback packer)
- MeshCentral agent (Apache-2.0), served by MeshCentral
- RustDesk client 1.4.9 (AGPL-3.0, source at https://github.com/rustdesk/rustdesk),
  mirrored unmodified under `/agentdist/rustdesk/`, next to a SOURCE.txt that
  names its license and source
- Python embeddable packages 3.8.7, 3.11.9 and 3.14.5 for Windows agents
  (Python Software Foundation License, plus the licenses of the libraries
  inside, see LICENSE.txt in each package)
- the Chocolatey install script (Apache-2.0), pinned by SHA-256
- driver packages from Snappy Driver Installer Origin
  (https://www.snappy-driver-installer.org); the server reads only the pack
  indexes, the agents download the packs from its web seed. The drivers
  belong to their vendors. No SDIO program code is used.
- operating system images built by the deployment builder from media the
  operator supplies or downloads; their publishers' licenses apply

## Documentation site

The GitHub Pages site that `riddix/scripts/docs_site.py` builds from README.md
uses the Just the Docs 0.12.0 theme (MIT,
https://github.com/just-the-docs/just-the-docs), fetched by the Pages build.
The published pages contain its stylesheets and scripts with lunr.js 2.3.9
(MIT) for the search, normalize.css 8.0.1 (MIT) and the github-light and
github-dark code colours of accessible-pygments (BSD-3-Clause).

## Python packages

Runtime dependencies from `api/ulrmm/requirements.txt` and what they pull in.
Each installed package keeps its license files in its `.dist-info` directory,
on installed servers and in the `ulrmm-api` image.

- aiohappyeyeballs 2.7.1: PSF-2.0
- aiohttp 3.14.4: Apache-2.0 AND MIT
- aiohttp-retry 2.9.1: MIT
- aiosignal 1.4.0: Apache-2.0
- amqp 5.4.1: BSD-3-Clause
- anyio 4.16.0: MIT
- asgiref 3.9.1: BSD-3-Clause
- attrs 26.1.0: MIT
- billiard 4.3.1: BSD-3-Clause
- brotli 1.2.1: MIT
- celery 5.6.3: BSD-3-Clause
- certifi 2026.10.19: MPL-2.0
- cffi 2.1.1: MIT-0
- channels 4.3.2: BSD-3-Clause
- channels_redis 4.3.0: BSD-3-Clause
- charset-normalizer 3.5.2: MIT
- choreographer 1.4.0: MIT
- click 8.5.0: BSD-3-Clause
- click-didyoumean 0.3.1: MIT
- click-plugins 1.1.1.2: BSD-3-Clause
- click-repl 0.4.1: MIT
- cryptography 50.0.0: Apache-2.0 OR BSD-3-Clause
- cssselect2 0.10.1: BSD-3-Clause
- Django 5.2.18: BSD-3-Clause
- django-allauth 65.21.1: MIT
- django-cors-headers 4.9.0: MIT
- django-filter 25.1: BSD-3-Clause
- django-rest-knox 4.2.0: MIT
- djangorestframework 3.18.3: BSD-3-Clause
- drf-spectacular 0.29.0: BSD-3-Clause
- filelock 4.2.1: MIT
- fonttools 4.68.0: MIT
- frozenlist 1.8.0: Apache-2.0
- h11 0.16.0: MIT
- hiredis 3.3.0: MIT
- httptools 0.9.0: MIT
- idna 3.20: BSD-3-Clause
- inflection 0.5.1: MIT
- iniconfig 2.3.1: MIT
- Jinja2 3.1.6: BSD-3-Clause
- jsonschema 4.26.0: MIT
- jsonschema-specifications 2025.9.1: MIT
- kaleido 1.2.0: MIT
- kombu 5.6.2: BSD-3-Clause
- logistro 2.0.1: MIT
- Markdown 3.10.2: BSD-3-Clause
- MarkupSafe 3.0.4: BSD-3-Clause
- msgpack 1.2.4: Apache-2.0
- multidict 6.9.1: Apache-2.0
- narwhals 2.28.0: MIT
- nats-py 2.15.0: Apache-2.0
- numpy 2.5.4: BSD-3-Clause
- oauthlib 4.0.1: BSD-3-Clause
- ocxsect 0.1.5: Apache-2.0
- orjson 3.13.0: MPL-2.0 AND (Apache-2.0 OR MIT)
- packaging 25.0: Apache-2.0 OR BSD-2-Clause
- pandas 2.3.3: BSD-3-Clause
- pillow 13.0.0: MIT-CMU
- platformdirs 4.14.3: MIT
- plotly 6.5.0: MIT
- pluggy 1.7.0: MIT
- prompt_toolkit 3.0.53: BSD-3-Clause
- propcache 0.5.4: Apache-2.0
- psutil 7.2.2: BSD-3-Clause
- psycopg 3.3.4: LGPL-3.0-only
- psycopg-binary 3.3.4: LGPL-3.0-only
- pyasn1 0.6.5: BSD-2-Clause
- pycdlib 1.22.0: LGPL-2.1-only
- pycparser 2.22: BSD-3-Clause
- pydyf 0.13.0: BSD-3-Clause
- Pygments 2.21.0: BSD-2-Clause
- PyJWT 2.15.1: MIT
- pyotp 2.9.0: MIT
- pyparsing 3.2.3: MIT
- pyphen 0.18.1: GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1
- pysnmp 7.1.29: BSD-2-Clause
- pytest 9.1.1: MIT
- pytest-timeout 2.4.0: MIT
- python-dateutil 4.0.0: Apache-2.0 AND BSD-3-Clause
- python-dotenv 1.2.4: BSD-3-Clause
- python-ipware 2.0.2: MIT
- pytz 2026.6: MIT
- PyYAML 6.0.3: MIT
- qrcode 8.2: BSD-3-Clause
- redis 6.4.0: MIT
- referencing 0.37.0: MIT
- regex 2026.9.10: Apache-2.0 AND CNRI-Python
- requests 2.34.2: Apache-2.0
- requests-file 3.0.1: Apache-2.0
- rpds-py 2026.9.1: MIT
- setuptools 84.2.1: MIT
- simplejson 4.2.0: MIT OR AFL-2.1
- six 1.17.0: MIT
- sqlparse 0.6.0: BSD-3-Clause
- tinycss2 1.5.1: BSD-3-Clause
- tinyhtml5 2.1.0: MIT
- tldextract 5.3.1: BSD-3-Clause
- twilio 8.13.0: MIT
- typing_extensions 4.16.0: PSF-2.0
- tzdata 2026.6: Apache-2.0
- tzlocal 5.4.5: MIT
- uritemplate 4.2.0: BSD-3-Clause OR Apache-2.0
- urllib3 2.8.0: MIT
- uvicorn 0.52.1: BSD-3-Clause
- uvloop 0.23.0: MIT OR Apache-2.0
- uWSGI 2.0.31: GPL-2.0-or-later WITH uWSGI linking exception
- validators 0.24.0: MIT
- vine 5.1.0: BSD-3-Clause
- watchfiles 1.3.0: MIT
- wcwidth 0.9.4: MIT
- weasyprint 70.0: BSD-3-Clause
- webencodings 0.6.1: BSD-3-Clause
- websockets 13.1: BSD-3-Clause
- yarl 1.25.1: Apache-2.0
- zipp 3.23.0: MIT
- zopfli 0.4.3: Apache-2.0

Some wheels bundle native libraries under their own licenses: numpy
(OpenBLAS BSD-3-Clause, libgfortran GPL-3.0-or-later WITH GCC-exception-3.1,
libquadmath LGPL-2.1-or-later), Pillow (FreeType, libjpeg, libpng, libtiff,
libwebp, HarfBuzz and others), psycopg-binary (libpq, OpenSSL and others).
Portions of this software are copyright (c) The FreeType Project
(https://freetype.org). All rights reserved. tldextract ships a copy of the
Public Suffix List (MPL-2.0). uWSGI is compiled from its source package on
PyPI (https://pypi.org/project/uWSGI/).

## Go modules compiled into nats-api

- github.com/jmoiron/sqlx v1.4.0: MIT
- github.com/klauspost/compress v1.18.7: BSD-3-Clause (the linked packages flate and internal/le)
- github.com/lib/pq v1.10.9: MIT
- github.com/nats-io/nats.go v1.45.0: Apache-2.0
- github.com/nats-io/nkeys v0.4.11: Apache-2.0
- github.com/nats-io/nuid v1.0.1: Apache-2.0
- github.com/sirupsen/logrus v1.9.3: MIT
- github.com/ugorji/go/codec v1.2.12: MIT
- golang.org/x/crypto v0.58.0: BSD-3-Clause
- golang.org/x/sys v0.49.0: BSD-3-Clause
- Go standard library and runtime go1.27.3: BSD-3-Clause, with the Go patent
  grant

## Services and data sources

Depending on the features in use, the server talks to outside services under
their providers' terms: GitHub (releases, repositories), git.riddix.de (only
when ULRMM_RELEASE_GITEA_TOKEN is set),
the RustDesk releases on GitHub, OSV.dev, the Microsoft Security Response
Center API, the Microsoft Update Catalog, the winget community index, the
NIST National Vulnerability Database, Dell TechDirect, the Lenovo warranty
lookup (not an official API), UniFi OS and OPNsense controllers, OpenAI,
Twilio, Telegram, ntfy, Matrix, Microsoft Teams, Slack, e-mail servers,
Let's Encrypt and the SDIO web seed.

This product uses data from the NVD API but is not endorsed or certified by
the NVD.

## License texts

Full texts for the Go code compiled into nats-api:

### github.com/jmoiron/sqlx v1.4.0

```text
 Copyright (c) 2013, Jason Moiron

 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:

 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
```

### github.com/klauspost/compress v1.18.7

```text
Copyright (c) 2012 The Go Authors. All rights reserved.
Copyright (c) 2019 Klaus Post. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

------------------

Files: gzhttp/*

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2016-2017 The New York Times Company

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

------------------

Files: s2/cmd/internal/readahead/*

The MIT License (MIT)

Copyright (c) 2015 Klaus Post

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---------------------
Files: snappy/*
Files: internal/snapref/*

Copyright (c) 2011 The Snappy-Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-----------------

Files: s2/cmd/internal/filepathx/*

Copyright 2016 The filepathx Authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### github.com/lib/pq v1.10.9

```text
Copyright (c) 2011-2013, 'pq' Contributors
Portions Copyright (C) 2011 Blake Mizerany

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### github.com/nats-io/nats.go v1.45.0

Same text for: github.com/nats-io/nkeys v0.4.11, github.com/nats-io/nuid v1.0.1.

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

### github.com/sirupsen/logrus v1.9.3

```text
The MIT License (MIT)

Copyright (c) 2014 Simon Eskildsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### github.com/ugorji/go/codec v1.2.12

```text
The MIT License (MIT)

Copyright (c) 2012-2020 Ugorji Nwoke.
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### golang.org/x/crypto v0.58.0

Same text for: golang.org/x/sys v0.49.0, Go standard library and runtime go1.27.3.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### golang.org/x/crypto v0.58.0

Same text for: golang.org/x/sys v0.49.0, Go standard library and runtime go1.27.3.

```text
Additional IP Rights Grant (Patents)

"This implementation" means the copyrightable works distributed by
Google as part of the Go project.

Google hereby grants to You a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable (except as stated in this section)
patent license to make, have made, use, offer to sell, sell, import,
transfer and otherwise run, modify and propagate the contents of this
implementation of Go, where such license applies only to those patent
claims, both currently owned or controlled by Google and acquired in
the future, licensable by Google that are necessarily infringed by this
implementation of Go.  This grant does not include claims that would be
infringed only as a consequence of further modification of this
implementation.  If you or your agent or exclusive licensee institute or
order or agree to the institution of patent litigation against any
entity (including a cross-claim or counterclaim in a lawsuit) alleging
that this implementation of Go or any code incorporated within this
implementation of Go constitutes direct or contributory patent
infringement, or inducement of patent infringement, then any patent
rights granted to you under this License for this implementation of Go
shall terminate as of the date such litigation is filed.
```
