use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    // Die Header-Datei soll direkt im Projektordner landen
    let output_file = PathBuf::from(&crate_dir).join("lxpc.h");

    // cbindgen starten und die Datei generieren
    cbindgen::Builder::new()
      .with_crate(crate_dir)
      .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap())
      .generate()
      .expect("Fehler beim Generieren der C-Header!")
      .write_to_file(output_file);
}