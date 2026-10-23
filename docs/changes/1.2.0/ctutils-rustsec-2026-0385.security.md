The `ctutils` crate moves from 0.4.2 to 0.4.5 (RUSTSEC-2026-0385): 0.4.2
generated its masks and compared `u128` values in non-constant time. Forge
uses it through the AES-GCM encryption of stored secrets and the hash crates.
