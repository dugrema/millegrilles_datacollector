mod setup_builder;
mod domain_manager;
mod constants;
mod setup_queues;
mod messages_requests;
mod messages_commands;
mod transactions;
mod messages_events;
mod setup_mongodb;
mod maintenance;
mod messages_ticker;

use log::{info};
use millegrilles_common_rust::tokio as tokio;
// use crate::domaines_grosfichiers::run;
use crate::setup_builder::run;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
