# cbridge-cowa
CosmWasm Rust smart contracts for cbridge

Folders:
- contracts: deployable cowa contracts, like cbridge, vault
- cowa-tmpl: template to generate a new deployable contract
- utils: helper func like abi encodePacked, kv helpers like owner, interfaces like verifySigs

## Create a new deployable contract
1. download cargo-generate from https://github.com/cargo-generate/cargo-generate/releases or compile locally
`cargo install cargo-generate --features vendored-openssl`
2. generate using contract template. xxx-yyy will be the folder and cargo name, use single word to avoid dash if possible. then move the folder under contracts/. (I can't figure out how to generate into the contracts folder directly)
```bash
cargo generate --path $PWD/cowa-tmpl --name xxx-yyy
mv xxx-yyy contracts/
```
