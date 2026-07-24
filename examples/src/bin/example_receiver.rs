use lxmf_core::application::DeliveryIdentity;
use rns_identity::identity::Identity;

#[tokio::main]
async fn main() -> lxmf_examples::ExampleResult {
    let config_dir = std::env::args().nth(1);
    let (runtime, shutdown) = lxmf_examples::start_reticulum(config_dir.as_deref()).await?;
    let mut signals = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());
    let local = DeliveryIdentity::new(Identity::new(), Some("Anonymous Peer".into()), Some(8))?;
    let receiver = lxmf_examples::run_receiver(runtime, local);
    tokio::select! {
        result = receiver => result?,
        _ = signals.recv() => {}
    }
    shutdown.trigger();
    Ok(())
}
