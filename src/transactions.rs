use log::debug;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::serde_json;

use crate::constants::*;
use crate::data_mongodb::{DataCollectorFilesRow, DataCollectorRow, DataCollectorRowIds, DataFeedRow, FeedViewRow};
use crate::domain_manager::DataCollectorDomainManager;
use crate::transactions_struct::{CreateFeedTransaction, CreateFeedViewTransaction, DeleteFeedTransaction, SaveDataItemTransaction, SaveDataItemTransactionV2, UpdateFeedTransaction, UpdateFeedViewTransaction};

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
        TRANSACTION_RESTORE_FEED => transaction_restore_feed(middleware, transaction, session).await,
        TRANSACTION_SAVE_DATA_ITEM => transaction_save_data_item(middleware, transaction, session).await,
        TRANSACTION_SAVE_DATA_ITEM_V2 => transaction_save_data_item_v2(middleware, transaction, session).await,
        TRANSACTION_CREATE_FEED_VIEW => transaction_create_feed_view(middleware, transaction, session).await,
        TRANSACTION_UPDATE_FEED_VIEW => transaction_update_feed_view(middleware, transaction, session).await,
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

async fn transaction_save_data_item<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    if ! transaction.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        Err("transaction_save_data_itemasync Invalid role")?;
    } else if ! transaction.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        Err("transaction_save_data_itemasync Invalid security")?;
    }

    let transaction_save_data_item: SaveDataItemTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let data_item: DataCollectorRow = transaction_save_data_item.into();

    let collection = middleware.get_collection_typed::<DataCollectorRow>(COLLECTION_NAME_DATA_DATACOLLECTOR)?;
    collection.insert_one_with_session(data_item, None, session).await?;

    Ok(())
}

async fn transaction_save_data_item_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                       -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    if ! transaction.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        Err("transaction_save_data_itemasync Invalid role")?;
    } else if ! transaction.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        Err("transaction_save_data_itemasync Invalid security")?;
    }

    let transaction_save_data_item: SaveDataItemTransactionV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let data_item: DataCollectorFilesRow = transaction_save_data_item.into();

    let collection = middleware.get_collection_typed::<DataCollectorFilesRow>(COLLECTION_NAME_SRC_DATAFILES)?;
    collection.insert_one_with_session(data_item, None, session).await?;

    Ok(())
}

async fn transaction_create_feed_view<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let transaction_id = transaction.transaction.id.clone();
    let estampille = transaction.transaction.estampille;
    let transaction_create_feed_view: CreateFeedViewTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let now = Utc::now();

    let data_row = FeedViewRow {
        feed_view_id: transaction_id,
        feed_id: transaction_create_feed_view.feed_id,
        encrypted_data: transaction_create_feed_view.encrypted_data,
        name: transaction_create_feed_view.name,
        active: transaction_create_feed_view.active,
        decrypted: transaction_create_feed_view.decrypted,
        data_type: None,
        mapping_code: transaction_create_feed_view.mapping_code,
        creation_date: estampille,
        modification_date: now,
        deleted: false,
        ready: false,
    };

    let collection = middleware.get_collection_typed::<FeedViewRow>(COLLECTION_NAME_FEED_VIEWS)?;
    collection.insert_one_with_session(data_row, None, session).await?;

    Ok(())
}

async fn transaction_update_feed_view<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let transaction_update_feed_view: UpdateFeedViewTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let filtre = doc! {
        "feed_view_id": transaction_update_feed_view.feed_view_id,
        "feed_id": transaction_update_feed_view.feed_id,  // For safety (access rules)
    };
    let ops = doc!{
        "$set": {
            "encrypted_data": convertir_to_bson(transaction_update_feed_view.encrypted_data)?,
            "name": transaction_update_feed_view.name,
            "active": transaction_update_feed_view.active,
            "decrypted": transaction_update_feed_view.decrypted,
            "mapping_code": transaction_update_feed_view.mapping_code,
        },
        "$currentDate": {"modification_date": true},
    };

    let collection = middleware.get_collection_typed::<FeedViewRow>(COLLECTION_NAME_FEED_VIEWS)?;
    let result = collection.update_one_with_session(filtre, ops, None, session).await?;

    if result.matched_count != 1 {
        Err("transaction_update_feed_view Update had no effect (no match)")?;
    }

    Ok(())
}

async fn transaction_restore_feed<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let transaction_delete_feed: DeleteFeedTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err("transaction_restore_feed User_id missing from certificate")?
        },
        Err(e) => Err(format!("transaction_restore_feed Error getting user_id: {:?}", e))?
    };
    let is_admin = transaction.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // When admin, operate on system feeds (user_id is null)
    let filtre = match is_admin {
        true => doc!{"feed_id": &transaction_delete_feed.feed_id, "user_id": null},
        false => doc!{"feed_id": &transaction_delete_feed.feed_id, "user_id": &user_id},
    };

    let ops = doc! {
        "$set": {"deleted": false},
        "$unset": {"deleted_at": true},
    };

    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    collection.update_one_with_session(filtre, ops, None, session).await?;

    Ok(())
}
