use log::debug;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error as CommonError;

use crate::domain_manager::DataCollectorDomainManager;

pub async fn consume_request<M>(middleware: &M, message: MessageValide, manager: &DataCollectorDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consume request: {:?}", &message.type_message);
    todo!()
}
