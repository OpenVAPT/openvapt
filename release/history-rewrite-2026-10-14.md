# History Rewrite Record (2026-10-14)

On 2026-10-14 the owner approved, in chat, rewriting six merge commits on `main` whose author was the owner's personal GitHub identity. The author of those six commits is now `OpenVAPT AI <342329786+openvapt-ai@users.noreply.github.com>`. No file changed: every rewritten commit has exactly the same tree (source code and documents) as before. Commits after the first rewritten one received new IDs only because a commit ID includes its parent's ID.

Release tags `v0.1.0-alpha.3` and `v0.1.0-alpha.4` were moved to the rewritten commits; their published files, checksums and Sigstore bundles are unchanged. The build provenance attestations and `release/channels.json` were created before the rewrite and keep naming the original commit IDs, which this file maps to the current ones. Evidence entries are not edited (AGENTS.md section 5.6); this record explains them.

| Original commit | Current commit | Subject |
|---|---|---|
| `af3fb68130df2bf40140cb5ce04ba47ad0b65b50` | `fc5dfd32a2af628a38643ac8bf4a87b72aa1a3fc` | release: promote v0.1.0-alpha.4 to alpha |
| `12bdadd31748edf5590864464dd841f01f0bff2c` | `8ac336a6032987e62f1ee78b8554829c99bc093a` | Merge pull request #9 from OpenVAPT/round3 |
| `9c118293de6e3ac95b62d56505b3528efe641fc7` | `9f0a3a972be7450512462bdf7baa7b1f578368e3` | install: name OPENVAPT_ALLOW_FILE in the file:// refusal (test expects the hint on Linux) |
| `17738fdf61c0d8ef8b8300e0e4d29cbf0f2f6336` | `d85d2ce59b4581d0292e5e674f6278fe8fb6d01c` | test-install: plain if instead of A && B // C (shellcheck SC2015 in CI) |
| `168c03b2765665ce67db5bf742dcef4b4b1a32cf` | `ca6bca17cfbc09b145e4c6391d65db1290749202` | legal: reports folder ownership under sudo (fresh review) |
| `cf45adf5ea4e76dd21f010a0fe1816255968cf43` | `190eb92e752ddc6c95c8760fc9bd8ff18567aacf` | Fix round3 verification findings F1 to F9 |
| `67a29b7126ccb5536c81946a6d742f76cb4d5b52` | `fdd71e8f84fc66809977ed1a8565b4bee72f70ea` | legal: fifth fresh review (reports folder, --open, citation); PRIVACY s3 merged; download page wording; legal record rehashed |
| `b2d172c26934d4e0cba61c65fdfcd9e5c03f5a7b` | `c694457da575ecccf7cc3a227a40233c7c23d1cb` | readme: citation points to generated sources (openvapt cite, CITATION.cff, cite.html) instead of pinning a version that the release record moves |
| `fef173a5d56adfcf7adf5766eeff199a33becbdb` | `fb658fb37f618a699a1a7f232cabb27583c12d05` | Merge branch 'work/cite-handy' into round3 |
| `2a242029cd61650569499351c7d0e586e242f3be` | `1638ef3e842443d9e088b52fec4179af52309037` | Merge branch 'work/install-paths' into round3 |
| `bb6f873f11165dd255c3f4acbb5152c5bedf476b` | `abef004270c5844a93e5d5aaaff8b220f3a03f32` | Merge branch 'work/redesign' into round3 |
| `bbd06ea9d36f792c182e19d0b12cf762da28bcd0` | `6f9546e67ddde7f733c08afc224b9a27c4b4e0af` | README: Cite OpenVAPT section; changelog for the cite stream |
| `d7acb7860a956ddedb9afa0d42f409e8fd4b5bd5` | `ef868f99dbd01c129ad914dd106fd7e404c55345` | Website: handy Cite control in header and footer, polished cite page |
| `5007cd596ad2298629f0e491f7292c866c8537a2` | `e0986d6645c629354be6b035d09ed5bdb7536a10` | Citation: single-source internal/cite, openvapt cite and How to Cite in every report |
| `60746f567cfb1ddab1ea64f179d820bcf1f36ce7` | `96d4b420ff13d6507fca01d547e14e63301c1b44` | Website: Download Only and Download and Scan chooser |
| `e65c30b29fb7030ce4673eb4d9386b442a484aa5` | `05cfa7ceeb70c888bc6f29a62ec539132a230d53` | CLI: default scan reports folder, Reports block and --open |
| `7f44446e2bb60d9383a602229adcbe71e8aebcea` | `4b331c0d058a09b9eed359e4356cad521dbcf3f4` | Installer: channel fallback, Download Only and Download and Scan paths |
| `13bd78c51e22050c7673f7798216a5ca9f46c108` | `797cd989635e626364347db4b4b6e99f705f3ddb` | release: promote v0.1.0-alpha.3 to alpha |
| `d591674532994129ea6e4bdb2168d18e620274eb` | `eddb5ec0ed67e9d14a5bcba527958a3b19028423` | Merge remote-tracking branch 'origin/main' into work/redesign |
| `6955895a1f3529bb392baed59dbab59be0f369df` | `aea36910b6b3e5514bcf34e254288a13fbd6047a` | Website: calmer near-monochrome redesign and animated walkthrough |
| `67259ac74258822032dbef103cc7a9a201d2d152` | `368f641ec604c1d79d48af0f3e05b3c2a5b3d604` | Merge pull request #8 from OpenVAPT/fix/tests-real-snapshot |
| `460b3fd7b75b32751e3daa81562222f1f70f1b72` | `087061ec6122c42db5bf04009866752acdc0375a` | test: fixture-only tests no longer assume the embedded snapshot is the fixture (release builds embed real data) |
| `a36b2c735706232a4b502aa7b5cce4daf78bbe04` | `be91b47104994753eb35fe0307fd4be85b03cfad` | Merge pull request #7 from OpenVAPT/fix/vulndb-no-wordpress-feed |
| `812a5f311f9f0b5666ae214bc1081518fe2a2d09` | `3ff46cd53be34f15c8b2e753142deae80d361c4e` | vulndb: drop the WordPress export (OSV publishes none); correct coverage claims; test ecosystems against OSV's list |
| `eb92aa260671f506b79493184170828a9e574f27` | `b1ee6dd0af5d76acb0f7958ba867f7493b3a02de` | Merge pull request #6 from OpenVAPT/ci/record-deploy-key |
| `13aeda8d8395d46f827e0d452ef2e9fa06005ec5` | `8eb50f4499ae7e417724adb5f96451fd0207fb3c` | promote: record job pushes with the RECORD_DEPLOY_KEY deploy key; workflow token read-only (ADR 0010) |
| `c17d9bd8430d57783efa82abdbe59133e7d27185` | `a3115700bd6b0f593d77b91c9357e5707300f3e5` | Merge pull request #5 from OpenVAPT/round2-pr |
| `491eb8c901d12ec3bdb27ac7ad2b2c8329bfa801` | `12d488e93c9188200699ae4467d59c8dec9d4539` | redact: anchor the Slack webhook pattern at a token boundary (CodeQL go/regex/missing-regexp-anchor) |
| `214af89070d0f5333ebac34542fe6eda71194c89` | `e08fc0cde08805c31bf7e6722fc6bf3b7eba78e6` | Round 2 audit fixes and builds (2026-10-14) |
| `b7c8157263f20a2dd34f006d192865373f47f14a` | `72d74bd80e278ebbe7e251457c9b9ccb71807b13` | Merge pull request #2 from OpenVAPT/fix/asset-cache-busting |
| `c2fcca36281a5bc791ef5e68217ed0ac79921bfc` | `2846357edb8369f4126cd3340675cb864123bb7e` | site: content-hash asset URLs so cached CSS and JS never go stale after a deploy |
| `8587ec6f1c72adc981ceb8405882277cd9269829` | `c2d04ef0116c17a18852486226fe414f28988695` | Merge pull request #1 from OpenVAPT/integrate |
