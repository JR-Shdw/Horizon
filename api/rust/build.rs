// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Make `cargo test` work out of the box.
//
// PyO3 with `extension-module` does NOT link libpython (CPython provides
// the symbols at runtime when it loads our wheel). For `cargo test` the
// test binary is a standalone executable that does need libpython, and
// rust-lld fails on PyExc_TypeError / PyErr_SetString / PyGILState_Ensure
// etc. otherwise.
//
// This script :
//   1. asks `pyo3-build-config` for the active Python interpreter
//   2. adds the libpython shared object and the linker search path, but ONLY
//      when the build is not producing an extension module.
//
// That last condition has TWO spellings and both must be honoured, which is
// the bug this file shipped until 2026-08-13 :
//
//   - `CARGO_FEATURE_EXTENSION_MODULE`, set by cargo when THIS crate's own
//     `extension-module` feature is on. `--features pyo3/extension-module`
//     does NOT set it: that activates the feature on the pyo3 crate, and a
//     dependency's features are invisible to our build script. Maturin used
//     to be configured with exactly that spelling, so this script emitted the
//     libpython link args into the wheel build and the manylinux check
//     rejected the result ("Your library links libpython"). See a644b72,
//     which papered over it by making the feature a default;
//   - `PYO3_BUILD_EXTENSION_MODULE`, which maturin exports for every build it
//     drives and which pyo3-build-config itself treats as equivalent to the
//     feature (`is_extension_module()`, pyo3-build-config 0.29 impl_.rs).
//     Honouring it means a wheel built with the other feature spelling is
//     still correct.
//
// pyo3-build-config exposes `is_extension_module()` and
// `is_linking_libpython_for_target()`, which is exactly this logic, but only
// through `pyo3_build_script_impl` -- documented "Please don't use these -
// they could change at any time". The env var is public, documented
// behaviour, so it is the one we read.
//
// Reference : https://pyo3.rs/main/building-and-distribution/multiple-python-versions
// and pyo3-build-config docs.

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PYO3_BUILD_EXTENSION_MODULE");

    // CPython provides these symbols at runtime when it loads the wheel, so
    // an extension module must not link libpython. Anything else -- cargo
    // test, the fuzz harnesses, a bare cargo build -- is a standalone binary
    // that does need it.
    if env::var_os("CARGO_FEATURE_EXTENSION_MODULE").is_some()
        || env::var_os("PYO3_BUILD_EXTENSION_MODULE").is_some()
    {
        return;
    }

    // pyo3-build-config exposes the same auto-detection chain pyo3 uses
    // internally (PYO3_PYTHON, PYO3_CONFIG_FILE, $PATH probing). The
    // returned `InterpreterConfig` carries `lib_dir` + `lib_name` when
    // the interpreter exposes a shared libpython we can link against.
    let cfg = pyo3_build_config::get();
    // pyo3 0.29 deprecated the public InterpreterConfig fields in favour of
    // getters (.lib_dir() / .lib_name()).
    if let Some(lib_dir) = cfg.lib_dir() {
        let p = Path::new(lib_dir);
        if p.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
    }
    if let Some(lib_name) = cfg.lib_name() {
        println!("cargo:rustc-link-lib=dylib={}", lib_name);
    }
}
