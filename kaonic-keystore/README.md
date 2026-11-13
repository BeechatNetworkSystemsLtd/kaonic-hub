# kaonic-keystore

An encrypted store for Kaonic secrets: the node identity, the mesh key, Wi-Fi passwords.
Secrets are named like paths (`mesh/identity`, `wifi/home`) and kept in one encrypted
file plus a mirror copy.

```rust
use kaonic_keystore::{DeviceKey, Keystore};

kaonic_keystore::harden_process()?;
let kek = DeviceKey::for_this_device(&app_token)?;
let mut ks = Keystore::open_or_create("/usr/local/kaonic-hub/keystore", &kek)?;

let identity = ks.get_or_generate("mesh/identity", 64)?;
ks.set("wifi/home", "correct horse battery staple")?;
let password = ks.get("wifi/home");
```

## How it works

**Two keys.** The secrets are encrypted with a random *data key*. The data key itself is
encrypted ("wrapped") by a *key provider* and stored in the file header. `rekey` switches
to a new provider and a fresh data key; the old provider stops working.

Key providers:

| Provider | Key comes from | Use |
|---|---|---|
| `DeviceKey` | the device's unique ID + an application token, through Argon2id | the hub on a board |
| `Passphrase` | a passphrase, through Argon2id | tools, manual unlock |
| `RawKey` | a 32-byte key, e.g. a file kept elsewhere | tests, development |

The Argon2id providers are slow on purpose: opening takes about a second.

**Encryption.** XChaCha20-Poly1305. The whole file is authenticated, header included, so
any change to it is detected.

**Two copies.** Every write rewrites the whole store, first to `<path>`, then to
`<path>.mirror`. Each is written to a temp file, synced and renamed into place, so a power
cut leaves at least one complete copy. Each copy has a generation number that grows with
every write. On open, the newest good copy is used and repairs the other one;
`recovery()` says what was repaired. If only the mirror write fails, the write still
succeeds and `degraded()` says so.

**Files.**

```text
<path>          the store
<path>.mirror   the second copy
<path>.lock     held while the store is open (a second open gets Error::Locked)
<path>*.tmp     staging files for writes
```

All files must be mode 0600 and owned by the user. Symlinks are not followed.

**In memory.** Opening decrypts every entry, and they stay in memory until the store is
dropped. Values are `Secret`s: wiped on drop and hidden in `Debug` output.
`harden_process()` turns off core dumps and debugger access for the process.

## Names

`/`-separated segments of `a-z 0-9 . _ -`, at most 128 bytes: `wifi/home`, `mesh/identity`.
`names_under("wifi")` lists one group.

## On the device

- Keep the store on `/usr/local` (userfs), not the root filesystem, so updates keep it.
- After an upgrade the previous release may open it again (a rollback): a new release
  must not write a format the previous one cannot read until it is confirmed.
- The hub service needs `RequiresMountsFor=/usr/local`. Otherwise, if userfs fails to
  mount, `open_or_create` makes a fresh store with a new identity.

## What it does not protect against

- Someone who has both the storage card and the application token.
- Code running as the hub, or root.
- Rolling both copies back to an older version together.
- A stolen device, unless the token is held by secure boot / a trusted execution
  environment.

## Tests

```sh
cargo test -p kaonic-keystore
```
