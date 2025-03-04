use std::collections::HashMap;
use millegrilles_common_rust::constantes::{Securite, DOMAINE_TOPOLOGIE};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct RequeteFuuidsVisites<'a> {
    fuuids: &'a Vec<&'a str>,
    batch_no: Option<usize>,
    done: Option<bool>,
}

#[derive(Deserialize)]
pub struct RequeteGetVisitesFuuidsResponse {
    pub ok: bool,
    pub err: Option<String>,
    pub visits: Option<Vec<RowFuuidVisit>>,
    pub unknown: Option<Vec<String>>
}

#[derive(Deserialize)]
pub struct RowFuuidVisit {
    pub fuuid: String,
    pub visits: HashMap<String, i64>,
}

pub async fn claim_and_visit_files<M,S,I>(middleware: &M, fuuids: I) -> Result<RequeteGetVisitesFuuidsResponse, CommonError>
where M: GenerateurMessages, S: AsRef<str>, I: IntoIterator<Item=S>
{
    let fuuids_1 = fuuids.into_iter().collect::<Vec<_>>();  // Copy S reference for ownership
    let fuuids_2 = fuuids_1.iter().map(|f| f.as_ref()).collect::<Vec<_>>(); // Extract &str
    let requete = RequeteFuuidsVisites { fuuids: &fuuids_2, batch_no: None, done: None };

    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "claimAndFilehostVisits", vec![Securite::L3Protege]).build();
    if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_commande(routage, &requete).await? {
        let reponse: RequeteGetVisitesFuuidsResponse = deser_message_buffer!(reponse.message);
        if ! reponse.ok {
            Err("claim_and_visit_files Error in CoreTopologie response for claimAndFilehostVisits")?;
        }
        Ok(reponse)
    } else {
        Err("claim_and_visit_files Bad response type for claimAndFilehostVisits")?
    }
}

pub async fn claim_files<M,S,I>(middleware: &M, batch_no: Option<usize>, done: Option<bool>, fuuids: I)
    -> Result<RequeteGetVisitesFuuidsResponse, CommonError>
where M: GenerateurMessages, S: AsRef<str>, I: IntoIterator<Item=S>
{
    let fuuids_1 = fuuids.into_iter().collect::<Vec<_>>();  // Copy S reference for ownership
    let fuuids_2 = fuuids_1.iter().map(|f| f.as_ref()).collect::<Vec<_>>(); // Extract &str
    let requete = RequeteFuuidsVisites { fuuids: &fuuids_2, batch_no, done };

    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "claimFiles", vec![Securite::L3Protege]).build();
    if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_commande(routage, &requete).await? {
        let reponse: RequeteGetVisitesFuuidsResponse = deser_message_buffer!(reponse.message);
        if ! reponse.ok {
            Err("claim_files Error in CoreTopologie response for claimFiles")?;
        }
        Ok(reponse)
    } else {
        Err("claim_files Bad response type for claimFiles")?
    }
}
