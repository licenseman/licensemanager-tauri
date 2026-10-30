# tauri-plugin-licensemanager

Tauri v2 SDK for [licensemanager.dev](https://licensemanager.dev): the
`tauri-plugin-licensemanager` crate and its JS bindings, `@licenseman/tauri`.

It is the Tauri version of [`@licenseman/electron`](https://github.com/licenseman/licensemanager-electron),
with the same behavior and the same storage: an app moving from Electron to
Tauri keeps its activations. Full docs: [licensemanager.dev/docs/tauri](https://licensemanager.dev/docs/tauri).

## Install

[Docs](https://licensemanager.dev/docs/tauri#install)

```sh
cargo add tauri-plugin-licensemanager   # in src-tauri/
npm add @licenseman/tauri               # or pnpm / yarn
```

Allow the plugin in your capability (`src-tauri/capabilities/default.json`):

```json
{
  "permissions": ["core:default", "licensemanager:default"]
}
```

Requires Tauri 2 and Rust 1.90 or later. Desktop only (macOS, Windows, Linux):
on iOS and Android the plugin fails the app setup.

## Usage

[Docs](https://licensemanager.dev/docs/tauri#usage)

Register the plugin in Rust:

```rust
use std::time::Duration;

// Ed25519 public key from the Security page. Hard-code it: never load it from
// a file or fetch it at runtime.
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n…";

fn main() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_licensemanager::Builder::new("your-product-id", PUBLIC_KEY)
                .min_offline_duration(Duration::from_secs(14 * 86_400))
                // .fingerprint(…).machine_name(…).platform(…).version(…)
                .build(),
        )
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

Configuration is in code only. An empty product id or an invalid public key
fails the app setup. The plugin disposes the license manager when the app
exits.

### Activation screen (JS)

```ts
import { LicenseError, setLicenseKey, watchLicense } from "@licenseman/tauri";

// Called with the current license, then on every change.
await watchLicense(({ state, offline }) => render(state, offline));

// When the user types their key:
try {
  await setLicenseKey(input);
} catch (error) {
  if (error instanceof LicenseError) showError(error.code);
}
```

`watchLicense` subscribes before reading the current snapshot, so a window
opened after a state change never misses it. `onStateChange(listener)` only
reports changes. Both return a function that unsubscribes.

### Gating features (Rust)

The webview can be modified by a determined user: check the license in Rust
for anything that must stay locked.

```rust
use tauri_plugin_licensemanager::{LicenseState, LicensemanagerExt};

#[tauri::command]
fn export_pdf(app: tauri::AppHandle) -> Result<(), String> {
    if app.license().state() != LicenseState::Active {
        return Err("A license is required".into());
    }
    // …
    Ok(())
}
```

`app.license()` works on any `App`, `AppHandle`, `Window` or `Webview` and
returns the `LicenseManager`: `state()`, `ready().await`, `set_license_key()`,
`refresh()`, `offline_state()`, `latest_allowed_version()`, `portal_url()`,
`fingerprint().await`, `is_clock_tampered()`, `on_state_change()` (returns a
`Subscription` that unsubscribes when dropped) and `subscribe()` (a
`tokio::sync::watch::Receiver`).

### JS API

| Function | Returns |
| --- | --- |
| `getState()` | `LicenseState` |
| `ready()` | `LicenseState`, once startup validation has completed |
| `getLicense()` | `{ state, offline, latestAllowedVersion }` |
| `setLicenseKey(key)` | `LicenseState`; throws a `LicenseError` |
| `refresh()` | `LicenseState` |
| `getOfflineState()` | `{ mode: "online" }` or `{ mode: "offline", validUntil: Date \| null, remainingMs }` |
| `getLatestAllowedVersion()` | `string \| null \| undefined` |
| `getPortalUrl()` | link to the customer portal |
| `isClockTampered()` | `boolean` |
| `getLicenseKeyHint()` | last 5 characters of the key, or `null` |
| `getLicenseKey()` | full key, or `null` (needs `licensemanager:allow-get-license-key`) |
| `getFingerprint()` | fingerprint (needs `licensemanager:allow-get-fingerprint`) |
| `onStateChange(fn)` / `watchLicense(fn)` | `Promise<UnlistenFn>` |

`licensemanager:default` allows everything except the full key and the
fingerprint: only expose what your windows need. The plugin also emits
`licensemanager://state-changed` with the snapshot on every state change.

Open the portal with [`@tauri-apps/plugin-opener`](https://v2.tauri.app/plugin/opener/):
`openUrl(await getPortalUrl())`.

### License state

[Docs](https://licensemanager.dev/docs/tauri#license-state)

| State | Meaning |
| --- | --- |
| `LOADING` | Startup validation in progress. |
| `MISSING_KEY` | No key stored yet: ask the user for one. |
| `ACTIVE` | Valid license, verified online or with the stored token. |
| `INVALID_KEY` | The key doesn't exist for this product (`not_found`). |
| `EXPIRED` | The license expired (`license_expired`). |
| `VERSION_NOT_ALLOWED` | The license doesn't include this version. `getLatestAllowedVersion()` returns the latest allowed version, or null. |
| `MACHINE_LIMIT_REACHED` | The license is active on its maximum number of machines. |
| `OFFLINE_EXPIRED` | The server can't be reached and there is no valid stored token. |
| `CLOCK_TAMPERED` | The server can't be reached and the system clock was moved back. |

In Rust these are `LicenseState::Active` etc.; they serialize to the same
strings.

## Validation

[Docs](https://licensemanager.dev/docs/tauri#validation)

The stored key is validated online on every launch. The token the server
returns is a JWT, verified like an offline token (EdDSA signature, product,
key, machine fingerprint and expiry) and stored in the OS secret store.

When the stored token is valid, `ready()` resolves with `ACTIVE` right away
and the online validation runs in the background; a refused license then
switches the state. Otherwise `ready()` waits for the server.

`setLicenseKey(key)` validates a key the user typed (trimmed, case kept) and
stores it only on success. On failure it throws a `LicenseError` whose `code`
is a server code (`not_found`, `license_expired`, `version_not_allowed`,
`machine_limit_reached`, `plan_limit_exceeded`, `validation_error`,
`internal_error`) or `network_error` / `invalid_response`, with `status` and
`latestAllowedVersion` when the server sent them. The current license is left
untouched. Branch on `code` (or `isLocking`), never on `message`.

Only the four license errors lock the app. When the server can't be reached,
times out, or answers another error, the SDK falls back to the stored token
until it expires.

The key is re-validated in the background at 2/3 of the token lifetime. Set
`min_offline_duration` to re-validate earlier, so that at least that much
offline time remains; it never moves re-validation within 1 day of the last
one. While offline, retries back off from 5 minutes to 1 hour. Timers re-check
the wall clock at least hourly, so system sleep can't delay a validation by
more than an hour. Call `refresh()` to re-validate on demand, e.g. after the
customer renewed.

Each validation retries transient failures (network errors, timeouts, 408,
429 and 5xx) with exponential backoff and jitter: for up to 30 seconds when a
caller is waiting (startup without a valid stored token, `setLicenseKey()`,
`refresh()`), and up to 5 minutes for background validations. Answers about
the key are never retried.

`version` (defaults to the version in `tauri.conf.json`), `platform` (macOS,
Windows or Linux by default) and `machine_name` (the hostname by default) are
sent with every validation. While offline, `version` is also checked against
the token's max version (`mv`): a stored token for 2.x refuses 3.0 with
`VERSION_NOT_ALLOWED` until the server can be reached, since online the
server's answer is authoritative.

## Device fingerprint

[Docs](https://licensemanager.dev/docs/tauri#device-fingerprint)

The fingerprint is a stable identifier unique to the machine, installation and
product: `{sha256 of the machine id}:{random install id}:{product id}`. The
install id is stored in the OS secret store (see below), so it survives
uninstall/reinstall.

The machine id defaults to the native machine GUID (`IOPlatformUUID` on macOS,
`MachineGuid` on Windows, `/etc/machine-id` on Linux), falling back to a
hardware MAC address or the hostname. Override it with a fixed string or a
function (still hashed):

```rust
use tauri_plugin_licensemanager::{Builder, MachineFingerprint};

Builder::new(PRODUCT_ID, PUBLIC_KEY)
    .fingerprint(MachineFingerprint::from_fn(|| async { my_machine_id().await }));
```

## Persistence

[Docs](https://licensemanager.dev/docs/tauri#persistence)

The install id, last-seen timestamp, license key and token are stored in the
OS secret store (macOS Keychain, Windows Credential Manager, Linux Secret
Service, else the kernel keyring), namespaced by product id, and mirrored to
redundant, non-obvious files. When no keyring is available (e.g. headless
Linux), the files are used alone.

Entries and files are the same as the Electron SDK's. On macOS, a keychain
item created by an Electron build of the app is owned by its code signature:
the Tauri build gets a one-time "allow access" prompt, and if the user denies
it, the file copy still holds the values.

## Clock-tamper detection

[Docs](https://licensemanager.dev/docs/tauri#clock-tamper-detection)

On startup and every hour, the SDK compares the system clock with the `Date`
header of `https://google.com`: more than 5 minutes apart means the clock was
moved. Offline, it records the newest time it has seen, and an earlier time
later means the clock was rolled back. `is_clock_tampered()` /
`isClockTampered()` then return `true`, and while offline the stored token is
refused with `CLOCK_TAMPERED`. Checks never fail and never block the app.

## Development

[Docs](https://licensemanager.dev/docs/tauri#development)

```sh
pnpm install
cargo test --workspace --all-features   # Rust unit, plugin and integration tests
pnpm test                               # JS bindings (Vitest)
pnpm lint && pnpm typecheck             # Biome, tsc
cargo clippy --workspace --all-targets --all-features
pnpm build                              # tsup: ESM + CJS + types to dist-js/
```

`src/core` holds the licensing logic and must not import `tauri`, so it can
become its own crate later. `examples/tauri-app` is a minimal app with
activation, locked and licensed views and a Rust command gated on `ACTIVE`:

```sh
cd examples/tauri-app
LICENSEMANAGER_PRODUCT_ID=… LICENSEMANAGER_PUBLIC_KEY="$(cat key.pem)" pnpm tauri dev
```

Slower checks:

```sh
cargo test --all-features -- --ignored keyring        # real OS keychain
node scripts/compat/electron-store.mjs                # then:
COMPAT_DIR=… cargo test --all-features -- --ignored compat_with_electron
```

The compat test checks that both SDKs read each other's stored install id and
compute the same fingerprint.

## Releasing

[Docs](https://licensemanager.dev/docs/tauri#releasing)

The crate and the npm package share one version and are released together,
with [Changesets](https://github.com/changesets/changesets):

1. Run `pnpm changeset` and commit the generated file with your change (Rust
   changes included; `pnpm changeset --empty` for none).
2. On merge to `main`, the release workflow opens a "Version Packages" PR, which
   bumps `package.json`, `Cargo.toml` and `Cargo.lock`.
3. Merging that PR publishes the crate to crates.io (skipped if that version is
   already there), then the npm package with provenance, and creates the tag
   and GitHub release.

Publishing uses trusted publishing (OIDC) on both crates.io and npm: no token
secrets.

## License

[MIT](LICENSE)
