use log::{debug, error};

use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::chrono::{Duration, Timelike, Utc};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::error::Error as CommonError;

use crate::constants::*;
use crate::domain_manager::DataCollectorDomainManager;
use crate::file_maintenance::claim_all_files;

pub async fn consume_ticker<M>(gestionnaire: &DataCollectorDomainManager, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), CommonError>
where M: MiddlewareMessages + BackupStarter + MongoDao
{
    if middleware.get_mode_regeneration() == true {
        debug!("consume_ticker Regeneration mode, skip");
        return Ok(());
    }

    let date_epoch = trigger.get_date();

    if date_epoch < Utc::now() - Duration::seconds(90) {
        return Ok(())  // Trigger too old, ignore
    }

    let minutes = date_epoch.minute();
    let hours = date_epoch.hour();

    if hours == 9 && minutes == 39 {
        if let Err(e) = claim_all_files(middleware).await {
            error!("consume_ticker Error during claim all files: {:?}", e);
        }
    }

    Ok(())
}
