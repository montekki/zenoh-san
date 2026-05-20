# zenoh-san

Small Rust demo that shows how Zenoh access control can authorize peers by the certificate common name (CN) from an mTLS connection, even when TLS hostname verification is disabled.

## What it does

The binary:

- generates a local CA plus two leaf certificates for `host-a` and `host-b`
- starts two Zenoh peer pairs over TLS
- runs an **allowed** case where ACL `cert_common_names` matches the peer certificates and a `put` reaches the subscriber
- runs a **denied** case where ACL `cert_common_names` does not match and delivery is blocked

The demo uses the key expression `demo/mtls-cn-acl` and logs the result of both cases.

## Prerequisites

- Rust toolchain with Cargo

## Run

```bash
cargo run
```

Generated certificates are written to `run/zenoh-san/certs`.

## Validate

```bash
cargo test
```

## Repository layout

- `src/main.rs` — demo logic, certificate generation, and scenario execution
- `src/configs/allowed-cn-acl` — Zenoh configs where `host-a` and `host-b` are allowed by CN
- `src/configs/denied-cn-acl` — Zenoh configs where the CNs do not match and ACL denies traffic

## Expected outcome

When the demo succeeds, logs show:

- the allowed case receives `hello over zenoh mtls with CN ACL`
- the denied case times out without delivery
- certificate material was generated under `run/zenoh-san/certs`

## Notes

- TLS server name verification is intentionally disabled in the sample configs with `verify_name_on_connect: false`
- Peer authentication still relies on mTLS and the generated local CA
- Authorization is driven by Zenoh ACL `subjects[].cert_common_names`
