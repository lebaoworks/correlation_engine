fn main() {
    // Vendored protoc: no system install needed, builds stay offline-capable
    // once the crate cache is warm.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    let mut cfg = prost_build::Config::new();
    // BTreeMap for map<> fields so Event.attrs encodes in sorted key order —
    // keeps encoding deterministic (same record ⇒ same bytes), which the
    // golden-byte contract test relies on.
    cfg.btree_map(["."]);
    cfg.compile_protos(&["wire.proto"], &["."]).unwrap();
    println!("cargo:rerun-if-changed=wire.proto");
}
