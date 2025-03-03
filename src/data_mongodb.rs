use serde::{Deserialize, Serialize};

use millegrilles_common_rust::bson;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use crate::transactions_struct::FileItem;

#[derive(Serialize, Deserialize)]
pub struct DataFeedRow {
    pub feed_id: String,
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
    /// Owner of the feed or None for system feeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub modified_at: DateTime<Utc>,
    /// True if feed is logically deleted but can be recovered
    pub deleted: bool,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
pub struct DataCollectorRowIds<'a> {
    pub data_id: &'a str,
    pub feed_id: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct DataCollectorRow {
    pub data_id: String,
    pub feed_id: String,
    #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub pub_date: DateTime<Utc>,
    pub encrypted_data: EncryptedDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileItem>>,
}
