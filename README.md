# cbridge-cowa
CosmWasm Rust smart contracts for cbridge

Folders:
- contracts: template and deployable cowa contracts
- packages: controllers/utils, interfaces

## Create a new contract
1. download cargo-generate from https://github.com/cargo-generate/cargo-generate/releases or compile locally
`cargo install cargo-generate --features vendored-openssl`
2. generate using contract template. xxx-yyy will be the folder and cargo name, must be kebab-case per rust convention. then move the folder under contracts/. (I can't figure out how to generate into contracts folder directly)
```bash
cargo generate --path $PWD/cowa-tmpl --name xxx-yyy
mv xxx-yyy contracts/
```