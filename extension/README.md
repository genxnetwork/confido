# Confido browser extension

All evidence verification runs in a local Worker using packaged Rust/WASM.
There is no native messaging host, remote verifier, content script or chat client.

`src/index.html`, `src/style.css`, and `src/ui.js` form the page and its
file-input/Worker UI. `src/collection.js` retrieves live inputs with explicit
origin, size and time limits. `src/worker.js` checks the packaged runtime and
invokes the shared verifier; `src/background.js` opens the verifier page when
the extension action is clicked. `build.py` packages those sources with the
Rust/WASM binding and browser manifests.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100 --locked
python3 extension/build.py --browser chromium
python3 extension/build.py --browser firefox
python3 extension/build.py --browser safari
# Optional GENXT live-demo build, using application-owned host configuration:
python3 extension/build.py --browser chromium --origins-config ../confidential-ai-example/deploy/genxt-demo/extension-origins.json
```

Run from the repository root with clang installed. Outputs are under
`extension/dist/<browser>` and are ignored by Git. WASM and JS are bundled;
CSP permits WASM compilation and forbids remotely hosted scripts.

- Chromium: enable developer mode at `chrome://extensions`, choose **Load unpacked**.
- Firefox: `about:debugging` → **This Firefox** → **Load Temporary Add-on**, choose
  the generated manifest. Manifest targets Firefox 128+; test your release channel.
- Safari: on macOS run `xcrun safari-web-extension-converter extension/dist/safari`
  and build/sign the generated Xcode project. Native packaging is required by
  Safari; the verifier itself remains WASM. Safari acceptance is pending macOS.

Without `--origins-config`, the extension supports local historical replay.
For live collection, supply an approved origin list at build time and select
a caller-owned verifier policy, such as the adjacent
`confidential-ai-example/profiles/verifier-match.json`. The build places only
those configured origins in the optional host permissions and runtime
allowlist. The extension does not infer trust policy from the service.
Replay requires a v2 archive and an explicit evaluation timestamp; old embedded
results are ignored and all raw inputs are reverified. Convert v1 archives with
the CLI's `migrate-archive` command. Imported policies are explicitly user-selected
trust configuration and are not obtained from the service.

Live collection requests optional permission only for the selected configured hostname,
AMD KDS and GitHub. Credentials/cookies are omitted; redirects, oversized inputs
and expired requests are rejected. A closed/restarted page loses pending challenges.
The configured endpoints must have HTTPS certificates accepted by the browser.
No certificate-error bypass is implemented. Private GitHub references need a
separate explicit credential design; the initial extension uses public references.

The UI displays evidence status, checks and limitations. It does not say a TLS peer
was matched or an application was admitted. Saving/reopening a result creates a
historical replay, never a fresh live challenge.

## Tests

```sh
python -m pip install playwright
python -m playwright install --with-deps chromium firefox
python scripts/browser_checks.py
# Optional privately retained real hardware corpus:
python scripts/browser_checks.py --bundle /private/archive-v1.json --at UNIX_SECONDS
```

The harness compares Python and worker results in Chromium/Firefox and loads the
actual Chromium MV3 extension to verify CSP and archive UI. Real Safari and public
HTTPS delivery require separate environment acceptance. Linux Firefox worker
coverage alone is not a claim of signed Firefox store-package acceptance.

The GENXT example owns the opt-in public integration test at
`confidential-ai-example/scripts/browser_live_checks.py`. It
pregrants exactly the four declared optional hosts in a temporary test package;
production permissions remain optional. It checks live match/mismatch without
credentials, prompts, or certificate-error bypass. This tests delivery and local
verification, not evidence-to-connection binding.

## Runtime identity

The bundle includes `runtime-manifest.json` with pipeline revision 2, source
fingerprints and SHA-256 values for its page, JS, CSS and WASM assets. The Worker verifies these
and checks the loaded WASM build metadata before inspecting or verifying evidence.
A mixed bundle fails with a rebuild message; installing a new JS caller alongside
an old WASM artifact is not supported. Metadata is separate from the result JSON.
