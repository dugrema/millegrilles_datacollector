use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;

pub async fn prepare_mongodb_index<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    // let options_conversation_id = IndexOptions {
    //     nom_index: Some(String::from("conversation_id_idx")),
    //     unique: true,
    // };
    // let champs_index_conversation_id = vec!(
    //     ChampIndex {nom_champ: String::from("conversation_id"), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     COLLECTION_NAME_CHAT_CONVERSATIONS,
    //     champs_index_conversation_id,
    //     Some(options_conversation_id)
    // ).await?;

    Ok(())
}
