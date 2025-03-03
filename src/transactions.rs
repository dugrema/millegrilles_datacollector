use log::debug;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::DELEGATION_GLOBALE_PROPRIETAIRE;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::serde_json;

use crate::constants::*;
use crate::data_mongodb::DataFeedRow;
use crate::domain_manager::DataCollectorDomainManager;
use crate::transactions_struct::{CreateFeedTransaction, DeleteFeedTransaction, UpdateFeedTransaction};

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
        TRANSACTION_UPDATE_FEED => transaction_update_feed(middleware, transaction, session).await,
        TRANSACTION_DELETE_FEED => transaction_delete_feed(middleware, transaction, session).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

async fn transaction_create_feed<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    let transaction_id = transaction.transaction.id.clone();
    let estampille = transaction.transaction.estampille;
    let transaction_create_feed: CreateFeedTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err("transaction_create_feed User_id missing from certificate")?
        },
        Err(e) => Err(format!("transaction_create_feed Error getting user_id: {:?}", e))?
    };

    let is_admin = transaction.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    let feed_user_id = match is_admin {
        true => None,                   // System feed
        false => Some(user_id.clone())  // User feed
    };

    let now = Utc::now();

    let data_row = DataFeedRow {
        feed_id: transaction_id,
        feed_type: transaction_create_feed.feed_type,
        security_level: transaction_create_feed.security_level,
        domain: transaction_create_feed.domain,
        poll_rate: transaction_create_feed.poll_rate,
        active: transaction_create_feed.active,
        decrypt_in_database: transaction_create_feed.decrypt_in_database,
        encrypted_feed_information: transaction_create_feed.encrypted_feed_information,
        user_id: feed_user_id,
        created_at: estampille,
        modified_at: now,
        deleted: false,
        deleted_at: None,
    };

    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    collection.insert_one_with_session(data_row, None, session).await?;

    Ok(())
}

async fn transaction_update_feed<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let transaction_update_feed: UpdateFeedTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err("transaction_update_feed User_id missing from certificate")?
        },
        Err(e) => Err(format!("transaction_update_feed Error getting user_id: {:?}", e))?
    };

    let is_admin = transaction.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    let poll_rate = match transaction_update_feed.poll_rate {Some(inner) => Some(inner as i64), None => None};
    let encrypted_feed_information = convertir_to_bson(transaction_update_feed.encrypted_feed_information)?;
    let set_ops = doc! {
        "security_level": transaction_update_feed.security_level,
        "poll_rate": poll_rate,
        "active": transaction_update_feed.active,
        "decrypt_in_database": transaction_update_feed.decrypt_in_database,
        "encrypted_feed_information": encrypted_feed_information,
    };
    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {"modified_at": true}
    };

    let filtre = match is_admin {
        true => doc!{"feed_id": &transaction_update_feed.feed_id, "user_id": null},     // System feed
        false => doc!{"feed_id": &transaction_update_feed.feed_id, "user_id": &user_id} // User feed
    };

    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    collection.update_one_with_session(filtre, ops, None, session).await?;

    Ok(())
}

async fn transaction_delete_feed<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let transaction_delete_feed: DeleteFeedTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err("transaction_delete_feed User_id missing from certificate")?
        },
        Err(e) => Err(format!("transaction_delete_feed Error getting user_id: {:?}", e))?
    };
    let is_admin = transaction.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // When admin, operate on system feeds (user_id is null)
    let filtre = match is_admin {
        true => doc!{"feed_id": &transaction_delete_feed.feed_id, "user_id": null},
        false => doc!{"feed_id": &transaction_delete_feed.feed_id, "user_id": &user_id},
    };

    let ops = doc! {
        "$set": {"deleted": true},
        "$currentDate": {"deleted_at": true}
    };

    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    // collection.delete_one_with_session(filtre, None, session).await?;
    collection.update_one_with_session(filtre, ops, None, session).await?;

    Ok(())
}
