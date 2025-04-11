pub const DOMAIN_NAME: &str = "DataCollector";

pub const COLLECTION_NAME_TRANSACTIONS: &str = DOMAIN_NAME;
pub const COLLECTION_NAME_FEEDS: &str = "DataCollector/feeds";
pub const COLLECTION_NAME_DATA_DATACOLLECTOR: &str = "DataCollector/data/DataCollector";
pub const COLLECTION_NAME_SRC_DATAFILES: &str = "DataCollector/source/DataFiles";

pub const REQUEST_GET_FEEDS: &str = "getFeeds";
pub const REQUEST_GET_FEEDS_FOR_SCRAPER: &str = "getFeedsForScraper";
pub const REQUEST_CHECK_EXISTING_DATA_IDS: &str = "checkExistingDataIds";
pub const REQUEST_GET_DATA_ITEMS_MOST_RECENT: &str = "getDataItemsMostRecent";
pub const REQUEST_GET_DATA_ITEMS_DATE_RANGE: &str = "getDataItemsDateRange";


pub const TRANSACTION_CREATE_FEED: &str = "createFeed";
pub const TRANSACTION_UPDATE_FEED: &str = "updateFeed";
pub const TRANSACTION_DELETE_FEED: &str = "deleteFeed";
pub const TRANSACTION_SAVE_DATA_ITEM: &str = "saveDataItem";
pub const TRANSACTION_SAVE_DATA_ITEM_V2: &str = "saveDataItemV2";
