fn main() {
    cc::Build::new()
        .cpp(true)
        .file("src/cpp/crypto.cpp")
        .flag_if_supported("-O3")
        .compile("wallet_crypto");
}