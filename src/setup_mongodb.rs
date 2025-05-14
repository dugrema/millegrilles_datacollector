use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::constants::{COLLECTION_NAME_DATA_DATACOLLECTOR, COLLECTION_NAME_FEEDS, COLLECTION_NAME_SRC_DATAFILES, COLLECTION_NAME_SRC_FILES_VOLATILE};

pub async fn prepare_mongodb_index<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    let options_feeds_id = IndexOptions {
        nom_index: Some(String::from("feed_id_uniq")),
        unique: true,
    };
    let champs_index_feed_id = vec!(
        ChampIndex {nom_champ: String::from("feed_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_NAME_FEEDS,
        champs_index_feed_id,
        Some(options_feeds_id)
    ).await?;

    let options_datacollector_data_id = IndexOptions {
        nom_index: Some(String::from("datacollector_data_id_uniq")),
        unique: true,
    };
    let champs_datacollector_data_id = vec!(
        ChampIndex {nom_champ: String::from("data_id"), direction: 1},
        ChampIndex {nom_champ: String::from("feed_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_NAME_DATA_DATACOLLECTOR,
        champs_datacollector_data_id,
        Some(options_datacollector_data_id)
    ).await?;

    let options_volatile_files_id = IndexOptions {
        nom_index: Some(String::from("correlation_id_uniq")),
        unique: true,
    };
    let champs_volatile_files_id = vec!(
        ChampIndex {nom_champ: String::from("correlation"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_NAME_SRC_FILES_VOLATILE,
        champs_volatile_files_id,
        Some(options_volatile_files_id)
    ).await?;

    let options_datafiles_id = IndexOptions {
        nom_index: Some(String::from("data_id_uniq")),
        unique: true,
    };
    let champs_datafiles_id = vec!(
        ChampIndex {nom_champ: String::from("data_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_NAME_SRC_DATAFILES,
        champs_datafiles_id,
        Some(options_datafiles_id)
    ).await?;

    let options_datafiles_feed_date = IndexOptions {
        nom_index: Some(String::from("date_feed")),
        unique: false,
    };
    let champs_datafiles_feed_date = vec!(
        ChampIndex {nom_champ: String::from("save_date"), direction: 1},
        ChampIndex {nom_champ: String::from("feed_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_NAME_SRC_DATAFILES,
        champs_datafiles_feed_date,
        Some(options_datafiles_feed_date)
    ).await?;
    
    Ok(())
}
