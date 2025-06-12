// build.rs for openfhe-rs
use cmake::Config;
use std::process::Command;
use std::str;

fn main() {
    // =========================================================================
    // CONFIGURATION
    // =========================================================================
    // Define the name of the C++ submodule directory.
    // This should match the directory name in your project.
    let submodule_dir = "openfhe-development-v1.2.4.0.0.2";

    // =========================================================================
    // PART 1: Build the C++ OpenFHE library from the submodule
    // =========================================================================
    println!("cargo:rerun-if-changed={}/", submodule_dir);

    let mut config = Config::new(submodule_dir);
    config
        .define("BUILD_STATIC", "ON")
        .define("BUILD_SHARED", "OFF")
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_TESTING", "OFF")
        .define("WITH_OPENMP", "ON")
        // Enable only the BFV scheme
        .define("WITH_BE", "OFF") // Disable BinFHE
        .define("WITH_CKKS", "OFF") // Disable CKKS
        .define("WITH_BGV", "OFF") // Disable BGV
        .define("WITH_BFV", "ON") // Enable BFV
        .define("BUILD_UNITTESTS", "OFF") // Ensure unit tests are off
        .define("BUILD_STATIC_DEPENDENCIES", "ON"); // Use static dependencies for BFV

    if cfg!(target_os = "macos") {
        config.define("RUN_HAVE_STD_REGEX", "0");
        config.define("RUN_HAVE_POSIX_REGEX", "0");
    }

    // `dst` is the path to the installed library artifacts (e.g., target/debug/build/openfhe-rs-xxxx/out)
    let dst = config.build();

    let core_include_path = dst.join("include/openfhe/core");
    let pke_include_path = dst.join("include/openfhe/pke");
    let binfhe_include_path = dst.join("include/openfhe/binfhe");
    let openfhe_include_path = dst.join("include/openfhe");

    // =========================================================================
    // PART 2: Build the CXX FFI bridge
    // =========================================================================
    let include_path = dst.join("include");
    let build_path = dst.join("build"); // Path to the temporary build directory

    cxx_build::bridge("src/lib.rs")
        .file("src/AssociativeContainers.cc")
        .file("src/Ciphertext.cc")
        .file("src/CryptoContext.cc")
        .file("src/CryptoParametersBase.cc")
        .file("src/DCRTPoly.cc")
        .file("src/DecryptResult.cc")
        .file("src/EncodingParams.cc")
        .file("src/EvalKey.cc")
        .file("src/KeyPair.cc")
        .file("src/LWEPrivateKey.cc")
        .file("src/Params.cc")
        .file("src/Plaintext.cc")
        .file("src/PrivateKey.cc")
        .file("src/PublicKey.cc")
        .file("src/SchemeBase.cc")
        .file("src/SequenceContainers.cc")
        .file("src/SerialDeserial.cc")
        .file("src/Trapdoor.cc")
        .file("src/EqualityUtils.cc")
        // 1. Include the public API headers from the "install" directory
        .include(&include_path)
        // 2. Include the source directories to find private source headers
        .include(&core_include_path)
        .include(&pke_include_path)
        .include(&binfhe_include_path)
        .include(&openfhe_include_path)
        // 3. Include the temporary build directory to find generated headers (like config_core.h)
        .include(&build_path)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-Wall")
        .flag_if_supported("-O3")
        .flag_if_supported("-Wno-parentheses")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-missing-field-initializers")
        .flag_if_supported("-Wno-unused-function")
        .compile("openfhe-rs-cxx");

    // =========================================================================
    // PART 3: Link all the libraries
    // =========================================================================
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-search=native={}/lib64", dst.display());

    println!("cargo:rustc-link-lib=static=OPENFHEpke_static");
    println!("cargo:rustc-link-lib=static=OPENFHEbinfhe_static");
    println!("cargo:rustc-link-lib=static=OPENFHEcore_static");

    if cfg!(target_os = "macos") {
        let gmp_prefix = get_brew_prefix("gmp");
        println!("cargo:rustc-link-search=native={}/lib", gmp_prefix);

        let omp_prefix = get_brew_prefix("libomp");
        println!("cargo:rustc-link-search=native={}/lib", omp_prefix);
    }

    println!("cargo:rustc-link-lib=static=gmp");

    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=gomp");
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=dylib=omp");
    }
    // =========================================================================
    // PART 4: Rerun-if-changed directives
    // =========================================================================

    println!("cargo::rerun-if-changed=src/lib.rs");
    println!("cargo::rerun-if-changed=src/AssociativeContainers.h");
    println!("cargo::rerun-if-changed=src/AssociativeContainers.cc");
    println!("cargo::rerun-if-changed=src/Ciphertext.h");
    println!("cargo::rerun-if-changed=src/Ciphertext.cc");
    println!("cargo::rerun-if-changed=src/CryptoContext.h");
    println!("cargo::rerun-if-changed=src/CryptoContext.cc");
    println!("cargo::rerun-if-changed=src/CryptoParametersBase.h");
    println!("cargo::rerun-if-changed=src/CryptoParametersBase.cc");
    println!("cargo::rerun-if-changed=src/DCRTPoly.h");
    println!("cargo::rerun-if-changed=src/DCRTPoly.cc");
    println!("cargo::rerun-if-changed=src/DecryptResult.h");
    println!("cargo::rerun-if-changed=src/DecryptResult.cc");
    println!("cargo::rerun-if-changed=src/EncodingParams.h");
    println!("cargo::rerun-if-changed=src/EncodingParams.cc");
    println!("cargo::rerun-if-changed=src/EvalKey.h");
    println!("cargo::rerun-if-changed=src/EvalKey.cc");
    println!("cargo::rerun-if-changed=src/KeyPair.h");
    println!("cargo::rerun-if-changed=src/KeyPair.cc");
    println!("cargo::rerun-if-changed=src/LWEPrivateKey.h");
    println!("cargo::rerun-if-changed=src/LWEPrivateKey.cc");
    println!("cargo::rerun-if-changed=src/Params.h");
    println!("cargo::rerun-if-changed=src/Params.cc");
    println!("cargo::rerun-if-changed=src/Plaintext.h");
    println!("cargo::rerun-if-changed=src/Plaintext.cc");
    println!("cargo::rerun-if-changed=src/PrivateKey.h");
    println!("cargo::rerun-if-changed=src/PrivateKey.cc");
    println!("cargo::rerun-if-changed=src/PublicKey.h");
    println!("cargo::rerun-if-changed=src/PublicKey.cc");
    println!("cargo::rerun-if-changed=src/SchemeBase.h");
    println!("cargo::rerun-if-changed=src/SchemeBase.cc");
    println!("cargo::rerun-if-changed=src/SequenceContainers.h");
    println!("cargo::rerun-if-changed=src/SequenceContainers.cc");
    println!("cargo::rerun-if-changed=src/SerialDeserial.h");
    println!("cargo::rerun-if-changed=src/SerialDeserial.cc");
    println!("cargo::rerun-if-changed=src/EqualityUtils.h");
    println!("cargo::rerun-if-changed=src/EqualityUtils.cc");
}

// Helper function to get the Homebrew prefix for a given package
fn get_brew_prefix(package_name: &str) -> String {
    let output = Command::new("brew")
        .arg("--prefix")
        .arg(package_name)
        .output()
        .unwrap_or_else(|_| panic!("Failed to execute 'brew --prefix {}'. Is Homebrew installed and is {} installed via brew?", package_name, package_name));

    if output.status.success() {
        str::from_utf8(&output.stdout).unwrap().trim().to_string()
    } else {
        let error_msg = str::from_utf8(&output.stderr).unwrap();
        panic!("'brew --prefix {}' failed: {}", package_name, error_msg);
    }
}
