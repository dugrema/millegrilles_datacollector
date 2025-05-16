use millegrilles_common_rust::constantes::{Securite, DEFAULT_Q_TTL};
use millegrilles_common_rust::domaines_traits::GestionnaireBusMillegrilles;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};

use crate::constants::*;
use crate::domain_manager::DataCollectorDomainManager;

pub fn setup_queues(manager: &DataCollectorDomainManager) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 1.public
    let requetes_publiques: Vec<&str> = vec![
        REQUEST_GET_FEEDS_FOR_SCRAPER,
        REQUEST_CHECK_EXISTING_DATA_IDS,
        REQUEST_GET_FUUIDS_VOLATILE,
    ];
    for req in requetes_publiques {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L1Public});
    }

    // RK 2.prive
    let requetes_privees: Vec<&str> = vec![
        REQUEST_GET_FEEDS,
        REQUEST_GET_FEED_VIEWS,
        REQUEST_GET_DATA_ITEMS_MOST_RECENT,
        REQUEST_GET_DATA_ITEMS_DATE_RANGE,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L2Prive});
    }

    // RK 2.prive
    let requetes_protegees: Vec<&str> = vec![
        REQUEST_GET_FEED_DATA,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L3Protege});
    }

    let commands_public: Vec<&str> = vec![
        TRANSACTION_SAVE_DATA_ITEM,
        TRANSACTION_SAVE_DATA_ITEM_V2,
        COMMAND_ADD_FUUIDS_VOLATILE,
    ];
    for cmd in commands_public {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, cmd), exchange: Securite::L1Public});
    }

    let commandes_privees: Vec<&str> = vec![
        TRANSACTION_CREATE_FEED,
        TRANSACTION_UPDATE_FEED,
        TRANSACTION_DELETE_FEED,
        TRANSACTION_CREATE_FEED_VIEW,
        TRANSACTION_UPDATE_FEED_VIEW,
        COMMAND_PROCESS_VIEW,
    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, cmd), exchange: Securite::L2Prive});
    }

    let commandes_protegees: Vec<&str> = vec![
        COMMAND_INSERT_VIEW_DATA,
    ];
    for cmd in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, cmd), exchange: Securite::L3Protege});
    }

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: manager.get_q_volatils(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Trigger Q
    queues.push(QueueType::Triggers (DOMAIN_NAME.into(), Securite::L3Protege));

    queues
}
