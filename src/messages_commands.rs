use std::collections::HashSet;
use log::{debug, error, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::{parse_confirmation_response, verifier_reponse_ok, RequeteDechiffrageMessage};
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, optionepochseconds, RoutageMessage};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, verifier_erreur_duplication_mongo, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::{chrono, serde_json};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use crate::domain_manager::DataCollectorDomainManager;
use crate::constants::*;
use crate::data_mongodb::{DataCollectorRowIds, DataFeedRow, FeedViewGroupedDatedRow, FeedViewRow};
use crate::file_maintenance::{claim_and_visit_files, claim_files};
use crate::keymaster::{fetch_decryption_keys, transmit_attached_key};
use crate::transactions_struct::{CreateFeedTransaction, CreateFeedViewTransaction, DeleteFeedTransaction, FeedViewGroupedDatedItem, FileItem, SaveDataItemTransaction, SaveDataItemTransactionV2, UpdateFeedTransaction, UpdateFeedViewTransaction};

pub async fn consume_command<M>(middleware: &M, message: MessageValide, manager: &DataCollectorDomainManager)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    if middleware.get_mode_regeneration() {
        return Ok(Some(middleware.reponse_err(Some(503), None, Some("System rebuild in progress"))?))
    }

    debug!("Consume command: {:?}", &message.type_message);

    let user_id = message.certificat.get_user_id()?;
    let is_private_user_account = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if is_private_user_account && user_id.is_some() {
        // Ok, private user
    } else {
        match message.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
            true => Ok(()), // Ok, system module
            false => {
                match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                    true => Ok(()), // Ok, admin (delegation_globale)
                    false => Err(format!("commands: Invalide command authorization for {:?}", message.type_message)),
                }
            }
        }?;
    }

    let action = match &message.type_message {
        TypeMessageOut::Commande(r) => r.action.clone(),
        _ => Err(CommonError::Str("grosfichiers.consommer_commande Mauvais type message, doit etre Commande"))?
    };

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        // Commandes standard
        TRANSACTION_CREATE_FEED => command_create_feed(middleware, message, manager, &mut session).await,
        TRANSACTION_UPDATE_FEED => command_update_feed(middleware, message, manager, &mut session).await,
        TRANSACTION_DELETE_FEED => command_delete_feed(middleware, message, manager, &mut session).await,
        TRANSACTION_RESTORE_FEED => command_restore_feed(middleware, message, manager, &mut session).await,
        TRANSACTION_SAVE_DATA_ITEM => command_save_data_item(middleware, message, manager, &mut session).await,
        TRANSACTION_SAVE_DATA_ITEM_V2 => command_save_data_item_v2(middleware, message, manager, &mut session).await,
        TRANSACTION_CREATE_FEED_VIEW => command_create_feed_view(middleware, message, manager, &mut session).await,
        TRANSACTION_UPDATE_FEED_VIEW => command_update_feed_view(middleware, message, manager, &mut session).await,
        COMMAND_ADD_FUUIDS_VOLATILE => command_add_fuuids_volatile(middleware, message).await,
        COMMAND_PROCESS_VIEW => command_process_view(middleware, message, &mut session).await,
        COMMAND_INSERT_VIEW_DATA => command_insert_feed_view_data(middleware, message, &mut session).await,
        // Unknown command
        _ => {
            Ok(Some(middleware.reponse_err(Some(99), None, Some("Unknown command"))?))
            // Err(format!("commands: Command {} is unknown : {}, message dropped", DOMAIN_NAME, action))?
        },
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        },
        Err(e) => {
            warn!("commands Command DB session aborted");
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn command_create_feed<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let _user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_create_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_create_feed Erreur get_user_id() : {:?}", e))?
    };

    // Deserialize to validate the format
    let _command: CreateFeedTransaction = message_owned.deserialize()?;

    // Save the key
    let key_command = match message_owned.attachements {
        Some(mut inner) => inner.remove("key"),
        None => None
    };

    match key_command {
        Some(key) => {
            match transmit_attached_key(middleware, key).await {
                Ok(Some(error)) => {
                    error!("command_create_feed Invalid key content - command rejected");
                    return Ok(Some(error));
                },
                Err(e) => {
                    error!("command_create_feed Error {:?} - command rejected", e);
                    return Ok(Some(middleware.reponse_err(Some(1), None, Some(format!("Error: {:?}", e).as_str()))?));
                },
                Ok(None) => ()  // Key saved successfully
            }
        },
        None => {
            warn!("command_create_feed Encryption key is missing - command rejected");
            return Ok(Some(middleware.reponse_err(Some(1), None, Some("Encryption key is missing"))?));
        }
    };

    // Save and run new transaction
    sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_update_feed<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_update_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_update_feed Error getting user id: {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: UpdateFeedTransaction = message_owned.deserialize()?;

    // Check if the user is allowed to delete the feed
    let filtre = doc!{"feed_id": &command.feed_id};
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection.find_one(filtre, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_update_feed Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_update_feed Deleteing feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save and run new transaction
    sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_delete_feed<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_delete_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_delete_feed Erreur get_user_id() : {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: DeleteFeedTransaction = message_owned.deserialize()?;

    // Check if the user is allowed to delete the feed
    let filtre = doc!{"feed_id": &command.feed_id};
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection.find_one(filtre, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_delete_feed Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_delete_feed Deleteing feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save and run new transaction
    sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_save_data_item<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! message.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    } else if ! message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let mut message_owned = message.message.parse_to_owned()?;
    let transaction: SaveDataItemTransaction = message_owned.deserialize()?;

    let fuuids = match transaction.files.as_ref() {
        Some(files) => {
            let mut fuuids = Vec::with_capacity(files.len());
            for file in files {
                fuuids.push(file.fuuid.clone());
            }
            Some(fuuids)
        }
        None => None
    };

    // Check if the data item already exists
    let collection = middleware.get_collection_typed::<DataCollectorRowIds>(COLLECTION_NAME_DATA_DATACOLLECTOR)?;
    let filtre = doc!{"feed_id": &transaction.feed_id, "data_id": &transaction.data_id};
    let mut cursor = collection.find(filtre, None).await?;
    if cursor.advance().await? {
        return Ok(Some(middleware.reponse_err(Some(409), None, Some("Data item already exists"))?));
    }

    let key_command = match message_owned.attachements {
        Some(mut inner) => inner.remove("key"),
        None => None
    };

    if let Some(key) = key_command {
        match transmit_attached_key(middleware, key).await {
            Ok(Some(error)) => {
                error!("command_save_data_item Invalid key content - command rejected");
                return Ok(Some(error));
            },
            Err(e) => {
                error!("command_save_data_item Error {:?} - command rejected", e);
                return Ok(Some(middleware.reponse_err(Some(1), None, Some(format!("Error: {:?}", e).as_str()))?));
            },
            Ok(None) => ()  // Key saved successfully
        }
    };

    if let Err(e) = sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await {
        error!("command_save_data_item Error processing transaction - command rejected : {:?}", e);
        return Ok(Some(middleware.reponse_err(Some(500), None, Some(format!("Error: {:?}", e).as_str()))?));
    }

    if let Some(fuuids) = fuuids {
        // Emit file claims
        debug!("command_save_data_item Claiming fuuids {:?}", fuuids);
        claim_and_visit_files(middleware, fuuids).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Serialize)]
struct DataFeedUpdatedEvent {
    feed_id: String,
}

async fn command_save_data_item_v2<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! message.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    } else if ! message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let mut message_owned = message.message.parse_to_owned()?;
    let transaction: SaveDataItemTransactionV2 = message_owned.deserialize()?;
    let feed_id = transaction.feed_id.clone();

    // Collect all fuuids, including for the data file and attached files.
    let mut fuuids_to_claim = vec![transaction.data_fuuid.clone()];
    if let Some(files) = transaction.attached_fuuids.as_ref() {
        for file in files {
            fuuids_to_claim.push(file.clone());
        }
    }

    // Check if the data item already exists
    let collection = middleware.get_collection_typed::<DataCollectorRowIds>(COLLECTION_NAME_SRC_DATAFILES)?;
    let filtre = doc!{"feed_id": &transaction.feed_id, "data_id": &transaction.data_id};
    let mut cursor = collection.find(filtre, None).await?;
    if cursor.advance().await? {
        return Ok(Some(middleware.reponse_err(Some(409), None, Some("Data item already exists"))?));
    }

    let key_command = match message_owned.attachements {
        Some(mut inner) => inner.remove("key"),
        None => None
    };

    if let Some(key) = key_command {
        match transmit_attached_key(middleware, key).await {
            Ok(Some(error)) => {
                error!("command_save_data_item Invalid key content - command rejected");
                return Ok(Some(error));
            },
            Err(e) => {
                error!("command_save_data_item Error {:?} - command rejected", e);
                return Ok(Some(middleware.reponse_err(Some(1), None, Some(format!("Error: {:?}", e).as_str()))?));
            },
            Ok(None) => ()  // Key saved successfully
        }
    };

    if let Err(e) = sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await {
        error!("command_save_data_item Error processing transaction - command rejected : {:?}", e);
        return Ok(Some(middleware.reponse_err(Some(500), None, Some(format!("Error: {:?}", e).as_str()))?));
    }

    // Emit file claims
    debug!("command_save_data_item Claiming fuuids {:?}", fuuids_to_claim);
    claim_and_visit_files(middleware, fuuids_to_claim).await?;

    let routage = RoutageMessageAction::builder(DOMAIN_NAME, "feedDataUpdated", vec![Securite::L3Protege]).build();
    middleware.emettre_evenement(routage, DataFeedUpdatedEvent {feed_id} ).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Serialize, Deserialize)]
pub struct FuuidVolatile {
    pub correlation: String,
    pub fuuid: String,
    pub format: String,
    pub cle_id: String,
    pub nonce: Option<String>,
    pub compression: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CommandAddFuuidsVolatile {
    files: Vec<FuuidVolatile>,
    #[serde(default, with="optionepochseconds")]
    expiration: Option<DateTime<Utc>>,
}

async fn command_add_fuuids_volatile<M>(middleware: &M, mut message: MessageValide)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if !message.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    } else if !message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let mut message_owned = message.message.parse_to_owned()?;
    let command: CommandAddFuuidsVolatile = message_owned.deserialize()?;

    let expiration = command.expiration.unwrap_or(Utc::now() + chrono::Duration::days(7));
    for file in command.files {
        let filtre = doc!{"correlation": &file.correlation};
        let mut set_on_insert = convertir_to_bson(file)?;
        set_on_insert.insert("expiration", &expiration);
        set_on_insert.insert("created", Utc::now());
        let ops = doc!{
            "$setOnInsert": set_on_insert,
            "$currentDate": {"modified": true}
        };
        let collection = middleware.get_collection(COLLECTION_NAME_SRC_FILES_VOLATILE)?;
        let options = UpdateOptions::builder().upsert(true).build();
        collection.update_one(filtre, ops, options).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_create_feed_view<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_create_feed_view Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_create_feed_view Erreur get_user_id() : {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: CreateFeedViewTransaction = message_owned.deserialize()?;

    // Check if the user is allowed to create a feed view on this feed
    let filtre = doc!{"feed_id": &command.feed_id};
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection.find_one(filtre, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_create_feed_view Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_create_feed_view Feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save the key
    let key_command = match message_owned.attachements {
        Some(mut inner) => inner.remove("key"),
        None => None
    };

    match key_command {
        Some(key) => {
            match transmit_attached_key(middleware, key).await {
                Ok(Some(error)) => {
                    error!("command_create_feed Invalid key content - command rejected");
                    return Ok(Some(error));
                },
                Err(e) => {
                    error!("command_create_feed Error {:?} - command rejected", e);
                    return Ok(Some(middleware.reponse_err(Some(1), None, Some(format!("Error: {:?}", e).as_str()))?));
                },
                Ok(None) => ()  // Key saved successfully
            }
        },
        None => {
            warn!("command_create_feed Encryption key is missing - command rejected");
            return Ok(Some(middleware.reponse_err(Some(1), None, Some("Encryption key is missing"))?));
        }
    };

    // Save and run new transaction
    if let Err(e) = sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await {
        warn!("command_create_feed Error in transaction processing - command rejected: {:?}", e);
        return Ok(Some(middleware.reponse_err(Some(1), None, Some(e.to_string().as_str()))?));
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_update_feed_view<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_update_feed_view Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_update_feed_view Erreur get_user_id() : {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: UpdateFeedViewTransaction = message_owned.deserialize()?;

    // Check if the user is allowed to create a feed view on this feed
    let filtre = doc!{"feed_id": &command.feed_id};
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection.find_one(filtre, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_update_feed_view Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_update_feed_view Feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save and run new transaction
    if let Err(e) = sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await {
        warn!("command_update_feed_view Error in transaction processing - command rejected: {:?}", e);
        return Ok(Some(middleware.reponse_err(Some(1), None, Some(e.to_string().as_str()))?));
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Deserialize)]
struct ProcessViewRequest {
    feed_view_id: String,
}

#[derive(Serialize)]
struct ProcessStartEvent {
    feed_id: String,
    feed_view_id: String,
}

async fn command_process_view<M>(middleware: &M, mut message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_process_view Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_update_feed_view Erreur get_user_id() : {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: ProcessViewRequest = message_owned.deserialize()?;

    // Check if the user is allowed to create a feed view on this feed
    let filtre_view = doc!{"feed_view_id": &command.feed_view_id};
    let collection_feed_view = middleware.get_collection_typed::<FeedViewRow>(COLLECTION_NAME_FEED_VIEWS)?;
    let feed_view = match collection_feed_view.find_one(filtre_view.clone(), None).await? {
        Some(inner) => inner,
        None => {
            error!("command_process_view No feed view with the provided Id");
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("No such feed view"))?));
        }
    };

    let feed_id = &feed_view.feed_id;
    let filtre_feed = doc!{"feed_id": feed_id};
    let collection_feed = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection_feed.find_one(filtre_feed, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_process_view Unknown feed_id {} - command rejected", feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_process_view Feed_id {} - user not authorized", feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // User is authorized. Start the process.
    let ops = doc!{
        "$set": {"ready": false},
        "$currentDate": {"modification_date": true, "processing_start_date": true},
    };
    collection_feed_view.update_one_with_session(filtre_view, ops, None, session).await?;

    // Emit command to request start of processing of this feed view.
    let process_event = ProcessStartEvent {
        feed_id: feed_view.feed_id.to_owned(),
        feed_view_id: feed_view.feed_view_id.to_owned()
    };
    let routage = RoutageMessageAction::builder(DOMAIN_DATASOURCEMAPPER, "processFeedView", vec![Securite::L3Protege])
        .timeout_blocking(5_000)
        .build();
    match middleware.transmettre_commande(routage, process_event).await? {
        Some(message) => {
            match parse_confirmation_response(&message) {
                Some(confirmation) => {
                    if Some(true) != confirmation.ok {
                        error!("command_process_view Error starting feed processing: {:?}", message);
                        let err = match confirmation.err.as_ref() { Some(inner) => Some(inner.as_str()), None => None};
                        return Ok(Some(middleware.reponse_err(confirmation.code, None, err)?));
                    }
                }
                None => {
                    error!("command_process_view Error starting feed processing: {:?}", message);
                    return Ok(Some(middleware.reponse_err(Some(500), None, Some("Error in response"))?))
                }
            }
        },
        None => {
            error!("command_process_view No response when starting process");
            return Ok(Some(middleware.reponse_err(Some(500), None, Some("No response when starting process"))?));
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Deserialize)]
struct InsertFeedViewGroupedDatedRequest {
    feed_view_id: String,
    feed_id: String,
    data: Vec<FeedViewGroupedDatedItem>,
    truncate: Option<bool>,
    deduplicate: Option<bool>,
}

async fn command_insert_feed_view_data<M>(middleware: &M, mut message: MessageValide, session: &mut ClientSession)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    // Access check
    if !message.certificat.verifier_roles_string(vec!["datasource_mapper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    }
    if !message.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let command: InsertFeedViewGroupedDatedRequest = {
        let message_ref = message.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Check feed (must not be deleted)
    let filtre_feed = doc!{"feed_id": &command.feed_id, "deleted": false};
    let collection_feeds = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    if collection_feeds.find_one(filtre_feed, None).await?.is_none() {
        error!("command_insert_feed_view_grouped_dated Unknown feed_id");
        return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed_id"))?));
    };

    // Check feed view (must not be deleted)
    let filtre_feed_view = doc!{"feed_view_id": &command.feed_view_id, "deleted": false};
    let collection_feed_views = middleware.get_collection_typed::<FeedViewRow>(COLLECTION_NAME_FEED_VIEWS)?;
    let feed_view = match collection_feed_views.find_one(filtre_feed_view, None).await? {
        Some(inner) => inner,
        None => {
            error!("command_insert_feed_view_grouped_dated Unknown feed_view_id");
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed_view_id"))?));
        }
    };

    let data_type = match feed_view.data_type.as_ref() {
        Some(data_type) => ViewDataType::try_from(data_type.as_str())?,
        None => ViewDataType::GroupedDated,  // Default to grouped-dated
    };
    let data_collection_name = match data_type {
        ViewDataType::Dated => COLLECTION_NAME_FEED_VIEW_DATED,
        ViewDataType::GroupedDated => COLLECTION_NAME_FEED_VIEW_GROUPED_DATED,
    };
    
    let collection_feed_view_data =
        middleware.get_collection_typed::<FeedViewGroupedDatedRow>(data_collection_name)?;
    if Some(true) == command.truncate {
        let delete_filtre = doc!{"feed_id": &command.feed_id, "feed_view_id": &command.feed_view_id};
        collection_feed_view_data.delete_many(delete_filtre, None).await?;
    }

    // Convert all items into FeedViewDataRow type
    let mut batch: Vec<FeedViewGroupedDatedRow> = Vec::with_capacity(command.data.len());
    for item in command.data {
        batch.push(item.into());
    }
    
    if let Some(true) = command.deduplicate {
        for item in batch {
            let filtre = doc! {"data_id": &item.data_id, "feed_view_id": &item.feed_view_id};
            let item = convertir_to_bson(item)?;
            let ops = doc! {"$setOnInsert": item};
            let options = UpdateOptions::builder().upsert(true).build();
            collection_feed_view_data.update_one(filtre, ops, options).await?;
        }
    } else {
        if let Err(e) = collection_feed_view_data.insert_many(&batch, None).await {
            if verifier_erreur_duplication_mongo(&e.kind) {
                // Duplicate found. Insert missing items.
                for item in batch {
                    let filtre = doc!{"data_id": &item.data_id, "feed_view_id": &item.feed_view_id};
                    let item = convertir_to_bson(item)?;
                    let ops = doc!{"$setOnInsert": item};
                    let options = UpdateOptions::builder().upsert(true).build();
                    collection_feed_view_data.update_one(filtre, ops, options).await?;
                }
            } else {
                Err(e)?  // Re-throw
            }
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_restore_feed<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_restore_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_restore_feed Erreur get_user_id() : {:?}", e))?
    };
    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    // Deserialize to validate the format
    let command: DeleteFeedTransaction = message_owned.deserialize()?;

    // Check if the user is allowed to delete the feed
    let filtre = doc!{"feed_id": &command.feed_id};
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let feed = match collection.find_one(filtre, None).await? {
        Some(feed) => feed,
        None => {
            error!("command_restore_feed Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_restore_feed Restoring feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save and run new transaction
    sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}
