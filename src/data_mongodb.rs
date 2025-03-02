use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use serde::{Deserialize, Serialize};

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
}
