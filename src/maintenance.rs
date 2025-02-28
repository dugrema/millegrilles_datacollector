use millegrilles_common_rust::tokio;
use millegrilles_common_rust::middleware::Middleware;
use crate::domain_manager::DataCollectorDomainManager;

pub async fn maintenance_thread<M>(_manager: &DataCollectorDomainManager, _middleware: &M)
    where M: Middleware
{

    // Attendre 5 secondes pour init bus
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    loop {
        // Do local maintenance
        // ...

        // Sleep
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    }
}
