// Data struct used for transaction content

use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::DechiffrageInterMillegrilleOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct AddFileItem {
    /// File unique identifier on filehosts
    fuuid: String,
    /// File decryption information
    #[serde(skip_serializing_if = "Option::is_none")]
    decryption: Option<DechiffrageInterMillegrilleOwned>,
}

#[derive(Serialize, Deserialize)]
struct AddDataItem {
    /// Unique data item identifier for this feed
    id: String,
    /// Source of the data item
    feed_id: String,
    /// Item publication or content date
    pub_date: DateTime<Utc>,
    /// Encrypted content of the data item. Structure depends on the feed type.
    encrypted_content: EncryptedDocument,
    /// Files associated with this data item
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<Vec<AddFileItem>>,
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
    add_files: Option<Vec<AddFileItem>>,
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
struct AddFeed {
    /// Type of feed (implies data type). Used by processors, aggregators, displays.
    feed_type: String,
    /// Domain that owns the data for this feed
    domain: String,
    /// Refresh rate in seconds when polling. No effect on live/push feeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_rate: Option<usize>,
    /// If false, the feed is not activated on creation to produce data
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    /// If true, the data will be decrypted in a decrypted_feed_information field in the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypt_in_database: Option<bool>,
    /// Private information on the feed, including name/description, url, auth, etc.
    encrypted_feed_information: EncryptedDocument,
}

#[derive(Serialize, Deserialize)]
struct UpdateFeed {
    /// Id of the feed to update.
    feed_id: String,
    /// Refresh rate in seconds when polling. No effect on live/push feeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_rate: Option<usize>,
    /// If false, the feed will not be producing data
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    /// If true, the data will be decrypted in a decrypted_feed_information field in the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypt_in_database: Option<bool>,
    /// Private information on the feed, including name/description, url, auth, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_feed_information: Option<EncryptedDocument>,
}

#[derive(Serialize, Deserialize)]
struct DeleteFeed {
    feed_id: String,
    /// If true, deletes the feed permanently and purges the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    purge: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct RestoreFeed {
    feed_id: String,
}
