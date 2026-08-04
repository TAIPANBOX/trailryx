//! Generate the wire types from `proto/federation.proto`.
//!
//! The generated code lands in `OUT_DIR` rather than in the tree: a checked-in
//! copy is a second source of truth for the wire, and the first time somebody
//! edits the `.proto` without regenerating, the two disagree silently.

fn main() {
    println!("cargo:rerun-if-changed=proto/federation.proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/federation.proto"], &["proto"])
        .expect("the federation proto compiles");
}
