use std::collections::HashSet;
use log::{debug, error};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::{Securite, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::reqwest::Certificate;
use crate::constants::DOMAIN_NAME;

pub const DOMAINE_NOM_MAITREDESCLES: &str = "MaitreDesCles";
pub const COMMANDE_AJOUTER_CLE_DOMAINES: &str = "ajouterCleDomaines";

pub async fn transmit_attached_key<M>(middleware: &M, attached_key_message: Value)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut key_message: MessageMilleGrillesOwned = serde_json::from_value(attached_key_message)?;

    let mut routage_builder = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public]
    )
        .correlation_id(&key_message.id);

    let routage = routage_builder
        .timeout_blocking(3_000)
        .build();
    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = key_message.try_into()?;
    let reponse = match middleware.emettre_message(type_message, buffer_message).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("transmit_attached_key Error saving key : {:?}", e);
            return Ok(Some(middleware.reponse_err(4, None, Some(format!("Error: {:?}", e).as_str()))?))
        }
    };

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("transmit_attached_key Key saved properly");
                    Ok(None)
                } else {
                    error!("transmit_attached_key Error saving key : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("transmit_attached_key Error saving key : Bad response type");
                Ok(Some(middleware.reponse_err(2, None, Some("Error saving key"))?))
            }
        },
        None => {
            error!("transmit_attached_key Error saving key : Timeout");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}

pub async fn get_encrypted_keys<M>(middleware: &M, cle_ids: &Vec<String>, certificate: Option<Vec<String>>)
                                   -> Result<MessageMilleGrillesOwned, CommonError>
where M: GenerateurMessages + MongoDao
{
    // Request decrypted keys from keymaster.
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
        .timeout_blocking(3_000)  // Short wait
        .build();
    let key_request = RequeteDechiffrage {
        domaine: DOMAIN_NAME.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(cle_ids.into_iter().map(|s| s.to_string()).collect()),
        certificat_rechiffrage: certificate,
        inclure_signature: None,
    };
    if let Some(TypeMessage::Valide(response)) = middleware.transmettre_requete(routage, key_request).await? {
        let mut message = response.message.parse_to_owned()?;
        message.certificat = None;  // Remove certificate, just keep key decryption info
        Ok(message)
    } else {
        Err("request_sync_directory Unable to get decryption keys - wrong response type")?
    }
}

pub async fn get_decrypted_keys<M>(middleware: &M, cle_ids: &Vec<String>)
    -> Result<Vec<ResponseRequestDechiffrageV2Cle>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    // Request decrypted keys from keymaster.
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
        .timeout_blocking(3_000)  // Short wait
        .build();
    let key_request = RequeteDechiffrage {
        domaine: DOMAIN_NAME.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(cle_ids.into_iter().map(|s| s.to_string()).collect()),
        certificat_rechiffrage: None,
        inclure_signature: None,
    };
    if let Some(TypeMessage::Valide(response)) = middleware.transmettre_requete(routage, key_request).await? {
        let message_ref = response.message.parse()?;
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let mut reponse_dechiffrage: ReponseRequeteDechiffrageV2 = message_ref.dechiffrer(enveloppe_privee.as_ref())?;
        if !reponse_dechiffrage.ok {
            error!("request_sync_directory Error loading keys: {:?}", reponse_dechiffrage.err);
            Err("Error fetching decryption keys")?;
        }
        match reponse_dechiffrage.cles.take() {
            Some(inner) => Ok(inner),
            None => Err("request_sync_directory No keys received")?
        }
    } else {
        Err("request_sync_directory Unable to get decryption keys - wrong response type")?
    }
}


pub async fn fetch_decryption_keys<M>(middleware: &M, message: &MessageValide, key_ids: HashSet<String>)
                                  -> Result<Option<MessageMilleGrillesOwned>, CommonError>
where M: GenerateurMessages + MongoDao
{
    if !key_ids.is_empty() {
        debug!("Fetch decryption keys");
        let key_ids = key_ids.into_iter().collect::<Vec<String>>();
        let client_certificate = message.certificat.chaine_pem()?;
        let recrypted_keys = get_encrypted_keys(middleware, &key_ids, Some(client_certificate)).await?;
        Ok(Some(recrypted_keys))
    } else {
        Ok(None)
    }
}
