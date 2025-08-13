mod ffi;
mod wallet;

use anyhow::Result;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🦀 Initializing wallet…");
    let w = wallet::Wallet::new();

    println!("ED25519 addr: {}", w.address_from_ed25519());
    println!("SECP256K1 addr: {}", w.address_from_secp256k1());

    // Sign & verify demo
    let msg = b"hello from rust+cpp";
    let sig = w.sign_ed25519(msg);
    let ok = w.verify_ed25519(msg, &sig);
    println!("Sign/verify: {}", if ok { "OK" } else { "FAILED" });

    // Async networking placeholder: pretend price fetch loop
    println!("(async) polling price every second (fake) …");
    for i in 1..=3 {
        sleep(Duration::from_secs(1)).await;
        // here you would call a real HTTP client; we just print
        println!("tick #{i} - price: {}", 42_000 + i); // stub
    }

    println!("Done.");
    Ok(())
}
