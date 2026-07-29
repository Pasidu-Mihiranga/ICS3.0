# The Seventh Encore — Writeup

## Scenario

Lyra Vey has been dead for 11 years. Her memorial hologram performance was approved for **6 acts** from source commit `7e4c9fd4`. Production rendered **7 acts** — source commit unchanged.

## What Entered the Build

`@orpheus/stage-linux-x64@4.2.3` — a **malicious npm package** published using Kalen Dorr's **unrevoked legacy CI token**.

### Attack Chain

1. **Kalen Dorr** (original stage architect) died in 2023, his account was retired but his `legacy-ci-token` was **never revoked** (`legacyTokenRevoked: null`).

2. On `2026-05-03T02:17:08Z`, an attacker used the token to publish `@orpheus/stage-linux-x64@4.2.3` to the internal npm registry.

3. The registry metadata was updated so `latest_compatible=4.2.3` for the `^4.2.0` range.

4. The CI pipeline ran `npm install --package-lock=false` — no lockfile pinning meant npm resolved `^4.2.0` → `4.2.3` automatically.

5. The malicious package's `postinstall.cjs` hijacked the build by:
   - Reading the clean `six-act-manifest.json`
   - Injecting a 7th act referencing `calibration.dat`
   - Writing `corrupted-manifest.json` with `compiled_act_count: 7`

### Why Windows Was Clean

The Windows rehearsal (`director-laptop`) installed `@orpheus/stage-win32-x64@4.2.2` — the attacker only compromised the **Linux** native package. The Windows package was skipped on Linux by npm's `os` filtering.

### Malicious Package Contents (v4.2.3)

| File | Purpose |
|---|---|
| `postinstall.cjs` | Injects the 7th act into the manifest during `npm install` |
| `index.js` | Modified to include `loadCalibration()` — decrypts the message |
| `calibration.dat` | AES-256-CTR encrypted payload with the hidden message |
| `README.md` | Camouflage: "Platform calibration hotfix for kernel 6.x render nodes" |

### Decryption

The `calibration.dat` format:

```
[14 bytes: "ORPHEUS-CAL-V1\0"] [16 bytes: AES IV] [encrypted data]
```

- **Cipher**: AES-256-CTR
- **Key derivation**: `SHA256(trusted_integrity_string)` where `trusted_integrity` is the npm integrity hash of the **legitimate** v4.2.2 package from the provenance attestation:
  `sha512-NgcsiI4YMhRDtXH2phJaxed4PtfJmjSadYpjNd5dghy/GpLy9n+SPsQqKNrfnje2OIBmm+nnelheFvzYepOc+Q==`

## Flag

```
ICS{th3_53v3nth_3nc0r3_w45_n3v3r_h3r5}
```

## Key Takeaways

- Always revoke credentials when team members leave (or pass away)
- Use lockfiles (`package-lock.json`) in CI — `--package-lock=false` is dangerous
- Verify provenance attestations against installed packages at build time
- Pin exact versions in production builds, not semver ranges
