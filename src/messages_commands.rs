use log::{debug, error, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::RequeteDechiffrageMessage;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::serde_json;
use crate::domain_manager::DataCollectorDomainManager;
use crate::constants::*;
use crate::data_mongodb::DataFeedRow;
use crate::keymaster::transmit_attached_key;
use crate::transactions_struct::{CreateFeedTransaction, DeleteFeedTransaction};

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
        TRANSACTION_DELETE_FEED => command_delete_feed(middleware, message, manager, &mut session).await,
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

async fn command_delete_feed<M>(middleware: &M, mut message: MessageValide, manager: &DataCollectorDomainManager, session: &mut ClientSession)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = message.message.parse_to_owned()?;

    let user_id = match message.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => {
                error!("command_create_feed Invalid certificate, no user_id - command rejected");
                return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid certificate"))?));
            }
        },
        Err(e) => Err(format!("command_create_feed Erreur get_user_id() : {:?}", e))?
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
            error!("command_create_feed Unknown feed_id {} - command rejected", command.feed_id);
            return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown feed"))?));
        }
    };

    if feed.user_id == Some(user_id) {
        // Ok, feed belongs to user
    } else if is_admin && feed.user_id.is_none() {
        // Ok, system feed managed by admin
    }  else {
        error!("command_create_feed Deleteing feed_id {} - user not authorized", command.feed_id);
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Unauthorized"))?));
    }

    // Save and run new transaction
    sauvegarder_traiter_transaction_v2(middleware, message, manager, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}
