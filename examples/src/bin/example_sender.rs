use std::io::{self, Write};
use std::time::Duration;

use lxmf_core::application::DeliveryIdentity;
use rns_identity::identity::Identity;

#[tokio::main]
async fn main() -> lxmf_examples::ExampleResult {
    let mut args = std::env::args().skip(1);
    let recipient = match args.next() {
        Some(value) => value,
        None => {
            print!("Recipient: ");
            io::stdout().flush()?;
            let mut value = String::new();
            io::stdin().read_line(&mut value)?;
            value
        }
    };
    let config_dir = args.next();
    let recipient = lxmf_examples::parse_destination_hash(&recipient)?;
    let (runtime, shutdown) = lxmf_examples::start_reticulum(config_dir.as_deref()).await?;
    let mut source = DeliveryIdentity::new(Identity::new(), Some("Rust Sender".into()), Some(8))?;
    lxmf_examples::announce(&runtime, &mut source).await?;
    println!(
        "Source announced: <{}>",
        hex::encode(source.destination_hash())
    );

    let public_key =
        lxmf_examples::wait_for_destination(&runtime, recipient, Duration::from_secs(60)).await?;
    let receipt = lxmf_examples::send_direct(
        &runtime,
        &source,
        recipient,
        public_key,
        "Hi there",
        "This is an LXMF message from the Rust sender example.",
    )
    .await?;
    println!("Delivered to <{}>: {receipt:?}", hex::encode(recipient));
    shutdown.trigger();
    Ok(())
}
