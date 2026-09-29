use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-env-changed=KATAGRAPHO_GIT_COMMIT");

    // A pre-set value wins. Nix builds from a source tree with no .git, so the
    // git call below always failed there and every manifest a Nix-built
    // katagrapho signed carried katagrapho_commit = "unknown" — no provenance
    // in exactly the artifact that exists to prove provenance. The flake sets
    // this from self.shortRev.
    if let Some(commit) = std::env::var("KATAGRAPHO_GIT_COMMIT")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        println!("cargo:rustc-env=KATAGRAPHO_GIT_COMMIT={commit}");
        return;
    }

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=KATAGRAPHO_GIT_COMMIT={commit}");
}
