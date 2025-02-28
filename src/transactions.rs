use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::error::Error as CommonError;

use crate::domain_manager::DataCollectorDomainManager;

pub async fn consume_transaction<M, T>(_gestionnaire: &DataCollectorDomainManager, middleware: &M, transaction: T, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TryInto<TransactionValide> + Send
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(CommonError::Str("aiguillage_transaction Erreur try_into TransactionValide"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.aiguillage_transaction Transaction sans action : {}", transaction.transaction.id))?
        },
        None => Err(format!("transactions.aiguillage_transaction Transaction sans routage : {}", transaction.transaction.id))?
    };

    match action.as_str() {
        // TRANSACTION_CHAT_EXCHANGE => transaction_chat_exchange(middleware, transaction, session).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}
