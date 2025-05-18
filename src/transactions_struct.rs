use serde::{Deserialize, Serialize};

use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::DechiffrageInterMillegrilleOwned;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, epochmilliseconds, optionepochmilliseconds};
use crate::data_mongodb::{DataCollectorFilesRow, DataCollectorRow};

#[derive(Serialize, Deserialize)]
pub struct FileItem {
    /// File unique identifier on filehosts
    pub fuuid: String,
    /// File decryption information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption: Option<DechiffrageInterMillegrilleOwned>,
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
pub struct SaveDataItemTransactionV2 {
    /// Unique data item identifier for this feed
    pub data_id: String,
    /// Source of the data item
    pub feed_id: String,
    /// Item publication or content date
    #[serde(with="epochmilliseconds")]
    pub save_date: DateTime<Utc>,
    pub data_fuuid: String,
    pub key_ids: Vec<String>,
    /// Item publication or content date
    #[serde(default, with="optionepochmilliseconds")]
    pub pub_date_start: Option<DateTime<Utc>>,
    /// Item publication or content date
    #[serde(default, with="optionepochmilliseconds")]
    pub pub_date_end: Option<DateTime<Utc>>,
    /// Files associated with this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_fuuids: Option<Vec<String>>,
}

impl Into<DataCollectorFilesRow> for SaveDataItemTransactionV2 {
    fn into(self) -> DataCollectorFilesRow {
        DataCollectorFilesRow {
            data_id: self.data_id,
            feed_id: self.feed_id,
            save_date: self.save_date,
            data_fuuid: self.data_fuuid,
            key_ids: self.key_ids,
            pub_date_start: self.pub_date_start,
            pub_date_end: self.pub_date_end,
            attached_fuuids: self.attached_fuuids,
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

#[derive(Serialize, Deserialize)]
pub struct FileItemV2 {
    /// File unique identifier on filehosts
    pub fuuid: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateFeedViewTransaction {
    pub feed_id: String,
    pub encrypted_data: EncryptedDocument,
    pub name: Option<String>,
    pub active: bool,
    pub decrypted: bool,
    pub mapping_code: String,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateFeedViewTransaction {
    pub feed_id: String,
    pub feed_view_id: String,
    pub encrypted_data: EncryptedDocument,
    pub name: Option<String>,
    pub active: bool,
    pub decrypted: bool,
    pub mapping_code: String,
}

#[derive(Serialize, Deserialize)]
pub struct FeedViewGroupedDatedItem {
    /// Unique data item identifier for this feed view
    pub data_id: String,
    pub feed_view_id: String,
    /// Source data of the data item
    pub feed_id: String,
    /// Item publication or content date
    #[serde(with="optionepochmilliseconds")]
    pub pub_date: Option<DateTime<Utc>>,
    /// Encrypted content of the data item. Structure depends on the feed type.
    pub encrypted_data: EncryptedDocument,
    pub group_id: Option<String>,
    /// Files associated with this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileItem>>,
}