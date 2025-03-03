use std::collections::HashSet;
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};

use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::ResponseRequestDechiffrageV2Cle;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;

use crate::constants::*;
use crate::data_mongodb::{DataCollectorRowIds, DataFeedRow};
use crate::domain_manager::DataCollectorDomainManager;
use crate::keymaster::{get_decrypted_keys, get_encrypted_keys};
use crate::transactions_struct::CreateFeedTransaction;

pub async fn consume_request<M>(middleware: &M, message: MessageValide, _manager: &DataCollectorDomainManager)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consume request: {:?}", &message.type_message);

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
                    false => Err(format!("requests: Invalide command authorization for {:?}", message.type_message)),
                }
            }
        }?;
    }

    let action = match &message.type_message {
        TypeMessageOut::Requete(r) => r.action.clone(),
        _ => Err(CommonError::Str("requests Bad message type, must be request"))?
    };

    match action.as_str() {
        // Commandes standard
        REQUEST_GET_FEEDS => request_get_feeds(middleware, message).await,
        REQUEST_GET_FEEDS_FOR_SCRAPER => request_get_feeds_for_scraper(middleware, message).await,
        REQUEST_CHECK_EXISTING_DATA_IDS => request_check_existing_data_ids(middleware, message).await,
        // Unknown request
        _ => Ok(Some(middleware.reponse_err(Some(99), None, Some("Unknown request"))?))
    }
}

#[derive(Serialize, Deserialize)]
struct FeedResponse {
    pub feed_id: String,
    pub feed_type: String,
    pub security_level: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_rate: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypt_in_database: Option<bool>,
    pub encrypted_feed_information: EncryptedDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub deleted: bool,
}

impl From<DataFeedRow> for FeedResponse {
    fn from(value: DataFeedRow) -> Self {
        Self {
            feed_id: value.feed_id,
            feed_type: value.feed_type,
            security_level: value.security_level,
            domain: value.domain,
            poll_rate: value.poll_rate,
            active: value.active,
            decrypt_in_database: value.decrypt_in_database,
            encrypted_feed_information: value.encrypted_feed_information,
            user_id: value.user_id,
            deleted: value.deleted,
        }
    }
}

#[derive(Deserialize)]
struct RequestGetFeeds {
    feed_ids: Option<Vec<String>>,
}

#[derive(Serialize)]
struct RequestGetFeedsResponse {
    ok: bool,
    feeds: Vec<FeedResponse>,
    keys: MessageMilleGrillesOwned,
}

async fn request_get_feeds<M>(middleware: &M, mut message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_create_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_create_feed Error get_user_id() : {:?}", e))?
    };

    let is_admin = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    let filtre = {
        let mut filtre = if is_admin {
            doc! {"user_id": null, "deleted": false}  // Only fetch system feeds
        } else {
            // Regular private user, only load user feeds.
            doc!("user_id": &user_id, "deleted": false)
        };

        let request: RequestGetFeeds = {
            let message_ref = message.message.parse()?;
            message_ref.contenu()?.deserialize()?
        };

        if let Some(feed_ids) = request.feed_ids {
            filtre.insert("feed_id", doc!{"$in": feed_ids});
        }

        filtre
    };

    let response_message = get_feeds(middleware, &mut message, filtre).await?;

    // let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    // let mut cursor = collection.find(filtre, None).await?;
    //
    // let mut key_ids = HashSet::new();
    // let mut feeds: Vec<FeedResponse> = Vec::new();
    //
    // while cursor.advance().await? {
    //     let row = match cursor.deserialize_current() {
    //         Ok(row) => row,
    //         Err(e) => {
    //             warn!("request_get_feeds Deserialization error in collection Feeds: {:?}", e);
    //             continue
    //         }
    //     };
    //     if let Some(cle_id) = row.encrypted_feed_information.cle_id.clone() {
    //         key_ids.insert(cle_id);
    //     }
    //     feeds.push(row.into());
    // }
    //
    // // Recover all decryption keys, re-encrypt them for the client
    // let key_ids = key_ids.into_iter().collect::<Vec<String>>();
    // let client_certificate = message.certificat.chaine_pem()?;
    // let recrypted_keys = get_encrypted_keys(middleware, &key_ids, Some(client_certificate)).await?;
    //
    // let response_message = RequestGetFeedsResponse {ok: true, feeds, keys: recrypted_keys};

    Ok(Some(middleware.build_reponse(response_message)?.0))
}

async fn request_get_feeds_for_scraper<M>(middleware: &M, mut message: MessageValide)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! message.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    } else if ! message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let filtre = doc! {"deleted": false};
    let response_message = get_feeds(middleware, &mut message, filtre).await?;

    Ok(Some(middleware.build_reponse(response_message)?.0))
}

async fn get_feeds<M>(middleware: &M, message: &mut MessageValide, filtre: Document) -> Result<RequestGetFeedsResponse, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection_typed::<DataFeedRow>(COLLECTION_NAME_FEEDS)?;
    let mut cursor = collection.find(filtre, None).await?;
    let mut key_ids = HashSet::new();
    let mut feeds: Vec<FeedResponse> = Vec::new();

    while cursor.advance().await? {
        let row = match cursor.deserialize_current() {
            Ok(row) => row,
            Err(e) => {
                warn!("request_get_feeds Deserialization error in collection Feeds: {:?}", e);
                continue
            }
        };
        if let Some(cle_id) = row.encrypted_feed_information.cle_id.clone() {
            key_ids.insert(cle_id);
        }
        feeds.push(row.into());
    }

    // Recover all decryption keys, re-encrypt them for the client
    let key_ids = key_ids.into_iter().collect::<Vec<String>>();
    let client_certificate = message.certificat.chaine_pem()?;
    let recrypted_keys = get_encrypted_keys(middleware, &key_ids, Some(client_certificate)).await?;

    let response_message = RequestGetFeedsResponse { ok: true, feeds, keys: recrypted_keys };
    Ok(response_message)
}

#[derive(Deserialize)]
struct CheckExistingDataIdsRequest {
    feed_id: String,
    data_ids: Vec<String>,
}

#[derive(Serialize)]
struct CheckExistingDataIdsResponse {
    existing_ids: Vec<String>,
    missing_ids: Vec<String>,
}

async fn request_check_existing_data_ids<M>(middleware: &M, mut message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! message.certificat.verifier_roles_string(vec!["web_scraper".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid role"))?));
    } else if ! message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Access denied - invalid security level"))?));
    }

    let message_ref = message.message.parse()?;
    let request: CheckExistingDataIdsRequest = message_ref.contenu()?.deserialize()?;

    let filtre = doc! {"feed_id": &request.feed_id, "data_id": {"$in": &request.data_ids}};
    let collection = middleware.get_collection_typed::<DataCollectorRowIds>(COLLECTION_NAME_DATA_DATACOLLECTOR)?;
    let mut cursor = collection.find(filtre, None).await?;

    let mut present_ids = Vec::with_capacity(request.data_ids.len());
    let mut missing_ids = HashSet::with_capacity(request.data_ids.len());
    missing_ids.extend(request.data_ids);
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let data_id = row.data_id.to_string();
        if missing_ids.remove(&data_id) {
            present_ids.push(data_id);
        }
    }

    let response_message = CheckExistingDataIdsResponse {
        existing_ids: present_ids,
        missing_ids: missing_ids.into_iter().collect(),
    };

    Ok(Some(middleware.build_reponse(response_message)?.0))
}
