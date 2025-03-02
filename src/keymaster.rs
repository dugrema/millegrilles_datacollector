use log::{debug, error};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::Value;

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
