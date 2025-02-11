# VOLERust
Reimplement VOLE in Rust

## References
1. Wolverine: https://github.com/emp-toolkit/emp-zk.git
2. RB-OKVS: https://github.com/felicityin/rb-okvs.git

## TODO: 
1. Currently I use very slow block operation that is implemented by hand. I have plan to revamp it using RustCrypto cipher library that implemented blocks later soon. (not urgent)
2. The index hash function in okvs does not have randomness (Resolved)
3. Seeds for LPN are not random (URGENT)