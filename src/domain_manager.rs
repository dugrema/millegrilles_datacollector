use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::QueueType;
use millegrilles_common_rust::recepteur_messages::MessageValide;

use crate::constants::*;
use crate::messages_commands::consume_command;
use crate::messages_events::consume_event;
use crate::messages_requests::consume_request;
use crate::messages_ticker::consume_ticker;
use crate::setup_queues::setup_queues;
use crate::transactions::consume_transaction;

#[derive(Clone)]
pub struct DataCollectorDomainManager {}

impl DataCollectorDomainManager {
    pub fn new() -> DataCollectorDomainManager {
        DataCollectorDomainManager {}
    }
}

impl GestionnaireDomaineV2 for DataCollectorDomainManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            // String::from(NOM_COLLECTION_VERSIONS),
        ])
    }

    fn reclame_fuuids(&self) -> bool {
        true
    }
}


impl GestionnaireBusMillegrilles for DataCollectorDomainManager {
    fn get_nom_domaine(&self) -> String {
        DOMAIN_NAME.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAIN_NAME)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAIN_NAME)
    }

    fn preparer_queues(&self) -> Vec<QueueType> { setup_queues(self) }
}

#[async_trait]
impl ConsommateurMessagesBus for DataCollectorDomainManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consume_request(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consume_command(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consume_event(middleware, message, self).await
    }
}

#[async_trait]
impl AiguillageTransactions for DataCollectorDomainManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        consume_transaction(self, middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for DataCollectorDomainManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        if ! middleware.get_mode_regeneration() {  // Only when not rebuilding
            consume_ticker(self, middleware, trigger).await?;
        }
        Ok(())
    }
}
