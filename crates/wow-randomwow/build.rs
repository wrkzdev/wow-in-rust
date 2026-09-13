//! Build the pinned RandomWOW library and a small shim that exposes its
//! compile-time configuration.
//!
//! `specs/00-overview.md` §8: "The RandomWOW submodule MUST be built with the
//! pinned WOW configuration, never with upstream RandomX defaults." The shim
//! exists so that requirement is *checkable at runtime* rather than assumed —
//! `specs/15-testing-and-conformance.md` §2.4 asks for exactly that, calling it
//! "the single most likely build mistake".

use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/randomwow")
        .canonicalize()
        .map(strip_unc_prefix)
        .unwrap_or_else(|_| {
            panic!(
                "third_party/randomwow is missing. Initialise it with:\n\
                 \n\
                 git submodule update --init third_party/randomwow\n"
            )
        });

    let config = root.join("src/configuration.h");
    if !config.exists() {
        panic!(
            "{} not found -- the submodule is present but empty. Run:\n\
             \n\
             git submodule update --init third_party/randomwow\n",
            config.display()
        );
    }

    // Fail the build, not a test, if the checked-out configuration is upstream
    // RandomX rather than RandomWOW. A wrong library produces valid-looking
    // hashes that fail every difficulty check on the real chain.
    assert_salt_is_wownero(&config);

    println!("cargo:rerun-if-changed={}", config.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("CMakeLists.txt").display()
    );
    println!("cargo:rerun-if-changed=src/shim.c");

    let mut cfg = cmake::Config::new(&root);
    cfg.define("CMAKE_BUILD_TYPE", "Release")
        // The benchmark binary is not needed and pulls in a thread dependency.
        .build_target("randomx");

    // Prefer Ninja where it is available.
    //
    // The "MinGW Makefiles" generator fails outright when any component of the
    // build path contains a space: GNU make splits the dependency list on
    // whitespace and reports "target pattern contains no '%'". Ninja quotes its
    // paths properly. Set `WOW_CMAKE_GENERATOR` to override.
    if let Ok(gen) = std::env::var("WOW_CMAKE_GENERATOR") {
        cfg.generator(gen);
    } else if have_ninja() {
        cfg.generator("Ninja");
    } else if cfg!(windows) && build_path_has_space() {
        panic!(
            "The build path contains a space and Ninja was not found.\n\
             CMake's \"MinGW Makefiles\" generator cannot handle that.\n\
             Install Ninja (winget install Ninja-build.Ninja), or set\n\
             WOW_CMAKE_GENERATOR, or move the checkout to a path without spaces."
        );
    }

    let dst = cfg.build();

    // CMake puts the static library under build/ or build/Release/ depending on
    // the generator; probe both.
    let build = dst.join("build");
    for dir in [build.clone(), build.join("Release"), build.join("Debug")] {
        if dir.exists() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }
    println!("cargo:rustc-link-lib=static=randomx");

    // RandomWOW is C++; link the standard library the host toolchain uses.
    let target = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match (os.as_str(), target.as_str()) {
        ("macos", _) | ("ios", _) => println!("cargo:rustc-link-lib=c++"),
        (_, "msvc") => {} // the MSVC runtime links itself
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }
    if os == "windows" {
        // `virtual_memory.c` acquires SeLockMemoryPrivilege for large pages via
        // OpenProcessToken / LookupPrivilegeValue / AdjustTokenPrivileges.
        println!("cargo:rustc-link-lib=advapi32");
    }

    // The configuration shim.
    cc::Build::new()
        .file("src/shim.c")
        .include(root.join("src"))
        .warnings(true)
        .compile("wow_randomwow_shim");
}

/// Read `RANDOMX_ARGON_SALT` out of the header and check it is Wownero's.
///
/// Upstream RandomX uses `"RandomX\x03"`; RandomWOW uses `"RandomWOW\x01"`
/// (`specs/03-pow.md` §3.1). Nothing else about the two builds differs
/// visibly, so this is the cheapest possible guard against linking the wrong
/// one.
fn assert_salt_is_wownero(config: &Path) {
    let text = std::fs::read_to_string(config).expect("read configuration.h");
    let line = text
        .lines()
        .find(|l| l.contains("#define RANDOMX_ARGON_SALT"))
        .expect("configuration.h has no RANDOMX_ARGON_SALT");
    assert!(
        line.contains(r#""RandomWOW\x01""#),
        "third_party/randomwow is not the WOW configuration.\n\
         RANDOMX_ARGON_SALT is: {}\n\
         Expected: #define RANDOMX_ARGON_SALT \"RandomWOW\\x01\"\n\
         Check out the pinned commit:\n\
         \n\
         git -C third_party/randomwow checkout 27b099b6dd6fef6e17f58c6dfe00009e9c5df587\n",
        line.trim()
    );
}

/// Is a `ninja` executable on PATH?
fn have_ninja() -> bool {
    std::process::Command::new("ninja")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Does the build directory path contain a space?
fn build_path_has_space() -> bool {
    std::env::var("OUT_DIR")
        .map(|d| d.contains(' '))
        .unwrap_or(false)
}

/// Drop Windows' extended-length path prefix from a canonicalised path.
///
/// `Path::canonicalize` returns one on Windows. CMake passes it straight
/// through to the compiler, which sees `//?/E:/...`, resolves it to `//`, and
/// fails with "No such file or directory". Every path here is well under
/// `MAX_PATH`, so the prefix buys nothing.
fn strip_unc_prefix(p: PathBuf) -> PathBuf {
    const VERBATIM: &str = r#"\\?\"#;
    let s = p.to_string_lossy();
    match s.strip_prefix(VERBATIM) {
        Some(rest) => PathBuf::from(rest),
        None => p,
    }
}
