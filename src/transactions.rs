use log::debug;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::serde_json;

use crate::constants::*;
use crate::data_mongodb::DataFeedRow;
use crate::domain_manager::DataCollectorDomainManager;
use crate::transactions_struct::CreateFeedTransaction;

pub async fn consume_transaction<M, T>(_gestionnaire: &DataCollectorDomainManager, middleware: &M, transaction: T, session: &mut ClientSession)
    -> Result<(), CommonError>
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
        TRANSACTION_CREATE_FEED => transaction_create_feed(middleware, transaction, session).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

async fn transaction_create_feed<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    let transaction_id = transaction.transaction.id.clone();
    let transaction_create_feed: CreateFeedTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err(format!("grosfichiers.transaction_nouvelle_version User_id absent du certificat"))?
        },
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur get_user_id() : {:?}", e))?
    };

    let data_row = DataFeedRow {
        feed_id: transaction_id,
        feed_type: transaction_create_feed.feed_type,
        security_level: transaction_create_feed.security_level,
        domain: transaction_create_feed.domain,
        poll_rate: transaction_create_feed.poll_rate,
        active: transaction_create_feed.active,
        decrypt_in_database: transaction_create_feed.decrypt_in_database,
        encrypted_feed_information: transaction_create_feed.encrypted_feed_information,
    };

    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    collection.insert_one_with_session(data_row, None, session).await?;

    Ok(())
}
