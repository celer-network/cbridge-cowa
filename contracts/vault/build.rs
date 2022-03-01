use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/vault.proto"], &["src/"])?;
    Ok(())
}