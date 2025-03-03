use serde::{Deserialize, Serialize};

use millegrilles_common_rust::bson;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::DechiffrageInterMillegrilleOwned;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use crate::data_mongodb::DataCollectorRow;

#[derive(Serialize, Deserialize)]
pub struct FileItem {
    /// File unique identifier on filehosts
    fuuid: String,
    /// File decryption information
    #[serde(skip_serializing_if = "Option::is_none")]
    decryption: Option<DechiffrageInterMillegrilleOwned>,
}

#[derive(Serialize, Deserialize)]
pub struct SaveDataItemTransaction {
    /// Unique data item identifier for this feed
    pub data_id: String,
    /// Source of the data item
    pub feed_id: String,
    /// Item publication or content date
    #[serde(with="epochseconds")]
    pub pub_date: DateTime<Utc>,
    /// Encrypted content of the data item. Structure depends on the feed type.
    pub encrypted_data: EncryptedDocument,
    /// Files associated with this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileItem>>,
}

impl Into<DataCollectorRow> for SaveDataItemTransaction {
    fn into(self) -> DataCollectorRow {
        DataCollectorRow {
            data_id: self.data_id,
            feed_id: self.feed_id,
            pub_date: self.pub_date,
            encrypted_data: self.encrypted_data,
            files: self.files,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct UpdateDataItem {
    /// Unique data item identifier for this feed
    id: String,
    /// Source of the data item
    feed_id: String,
    /// Item publication or content date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub_date: Option<DateTime<Utc>>,
    /// Updated encrypted content of the data item. Structure depends on the feed type.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_content: Option<EncryptedDocument>,
    /// Add new files associated with this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    add_files: Option<Vec<FileItem>>,
    /// Fuuids of files to remove from this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_files: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct DeleteDataItem {
    /// Feed to delete items from
    feed_id: String,
    /// Data ids to delete
    ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FeedInformation {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_password: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateFeedTransaction {
    /// Type of feed (implies data type). Used by processors, aggregators, displays.
    pub feed_type: String,
    /// Security level of the feed
    pub security_level: String,
    /// Domain that owns the data for this feed
    pub domain: String,
    /// Refresh rate in seconds when polling. No effect on live/push feeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_rate: Option<usize>,
    /// If false, the feed is not activated on creation to produce data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// If true, the data will be decrypted in a decrypted_feed_information field in the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypt_in_database: Option<bool>,
    /// Private information on the feed, including name/description, url, auth, etc.
    pub encrypted_feed_information: EncryptedDocument,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateFeedTransaction {
    /// Id of the feed to update.
    pub feed_id: String,
    /// Security level of the feed
    pub security_level: Option<String>,
    /// Refresh rate in seconds when polling. No effect on live/push feeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_rate: Option<usize>,
    /// If false, the feed will not be producing data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// If true, the data will be decrypted in a decrypted_feed_information field in the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypt_in_database: Option<bool>,
    /// Private information on the feed, including name/description, url, auth, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_feed_information: Option<EncryptedDocument>,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteFeedTransaction {
    pub feed_id: String,
    /// If true, deletes the feed permanently and purges the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct RestoreFeedTransaction {
    pub feed_id: String,
}
