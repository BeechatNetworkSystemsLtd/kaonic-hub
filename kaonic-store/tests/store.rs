use kaonic_store::{Store, account, audit, plugin_store, sessions, settings, wifi};

fn temp_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kaonic-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("hub.db")
}

#[tokio::test]
async fn creates_a_private_file_and_keeps_data_across_opens() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_db("reopen");
    let store = Store::open(&path).unwrap();
    store.call(|c| account::set_password_hash(c, "$argon2id$x", 10)).await.unwrap();
    drop(store);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

    let store = Store::open(&path).unwrap();
    assert!(store.call(|c| account::is_set_up(c)).await.unwrap());
    let version: i64 = store.call(|c| c.query_row("PRAGMA user_version", [], |row| row.get(0))).await.unwrap();
    assert_eq!(version as usize, kaonic_store::SCHEMA_VERSION);
}

fn user_version(path: &std::path::Path) -> i64 {
    let connection = kaonic_store::Connection::open(path).unwrap();
    connection.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap()
}

#[tokio::test]
async fn upgrades_a_database_from_before_schema_info() {
    let path = temp_db("v1");
    drop(Store::open(&path).unwrap());
    {
        // What the first release left: schema 1, no `schema_info`.
        let connection = kaonic_store::Connection::open(&path).unwrap();
        connection.execute_batch("DROP TABLE schema_info; DROP TABLE plugin_store; PRAGMA user_version = 1;").unwrap();
    }
    let store = Store::open(&path).unwrap();
    let min_reader: i64 = store.call(|c| c.query_row("SELECT min_reader FROM schema_info", [], |row| row.get(0))).await.unwrap();
    assert_eq!(min_reader, 1);
    drop(store);
    assert_eq!(user_version(&path) as usize, kaonic_store::SCHEMA_VERSION);
}

#[tokio::test]
async fn opens_a_newer_database_that_still_allows_this_release() {
    let path = temp_db("newer-compatible");
    drop(Store::open(&path).unwrap());
    {
        // A newer release added things only: the file still says release 1 can use it.
        let connection = kaonic_store::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE later (x INTEGER); PRAGMA user_version = 9;").unwrap();
    }
    let store = Store::open(&path).unwrap();
    store.call(|c| settings::set_bool(c, "wifi.client", false)).await.unwrap();
    drop(store);
    // Left as the newer release wrote it.
    assert_eq!(user_version(&path), 9);
}

#[tokio::test]
async fn refuses_a_newer_database_that_this_release_cannot_use() {
    let path = temp_db("newer-breaking");
    drop(Store::open(&path).unwrap());
    {
        let connection = kaonic_store::Connection::open(&path).unwrap();
        connection.execute_batch("UPDATE schema_info SET min_reader = 9; PRAGMA user_version = 9;").unwrap();
    }
    assert!(matches!(Store::open(&path), Err(kaonic_store::Error::TooNew { found: 9, needs: 9, .. })));
}

#[tokio::test]
async fn refuses_a_newer_database_without_schema_info() {
    let path = temp_db("newer-unknown");
    {
        let connection = kaonic_store::Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
    }
    assert!(matches!(Store::open(&path), Err(kaonic_store::Error::TooNew { found: 99, needs: 99, .. })));
}

#[tokio::test]
async fn sessions_expire_when_idle_or_old() {
    let store = Store::open_in_memory().unwrap();
    store.call(|c| sessions::create(c, b"hash-a", "csrf-a", "admin", 1000)).await.unwrap();

    let found = store.call(|c| sessions::find_and_touch(c, b"hash-a", 1000 + 3600)).await.unwrap().unwrap();
    assert_eq!((found.csrf_token.as_str(), found.role.as_str()), ("csrf-a", "admin"));
    // Used an hour later, so idle time counts from there.
    assert!(store.call(|c| sessions::find_and_touch(c, b"hash-a", 1000 + 3600 + sessions::IDLE_SECS)).await.unwrap().is_some());
    // Unused for longer than the idle limit: gone, and deleted.
    let late = 1000 + 3600 + 2 * sessions::IDLE_SECS + 1;
    assert!(store.call(move |c| sessions::find_and_touch(c, b"hash-a", late)).await.unwrap().is_none());
    assert!(store.call(|c| sessions::find_and_touch(c, b"hash-a", 1000)).await.unwrap().is_none());

    // However busy, a session lasts at most a week.
    store.call(|c| sessions::create(c, b"hash-b", "csrf-b", "viewer", 0)).await.unwrap();
    let mut now = 0;
    while now < sessions::MAX_SECS {
        now += 3600;
        let at = now;
        let alive = store.call(move |c| sessions::find_and_touch(c, b"hash-b", at)).await.unwrap().is_some();
        assert_eq!(alive, at <= sessions::MAX_SECS);
    }
}

#[tokio::test]
async fn wifi_list_keeps_its_order() {
    let store = Store::open_in_memory().unwrap();
    let networks = vec![
        wifi::SavedNetwork { ssid: "b".into(), secured: true, hidden: false, auto_connect: true, last_connected_ts: Some(5) },
        wifi::SavedNetwork { ssid: "a".into(), secured: false, hidden: true, auto_connect: false, last_connected_ts: None },
    ];
    let saved = networks.clone();
    store.call(move |c| wifi::replace_all(c, &saved)).await.unwrap();
    assert_eq!(store.call(|c| wifi::list(c)).await.unwrap(), networks);
}

#[tokio::test]
async fn settings_and_audit() {
    let store = Store::open_in_memory().unwrap();
    assert!(store.call(|c| settings::get_bool(c, "wifi.client", true)).await.unwrap());
    store.call(|c| settings::set_bool(c, "wifi.client", false)).await.unwrap();
    assert!(!store.call(|c| settings::get_bool(c, "wifi.client", true)).await.unwrap());

    store.call(|c| audit::record(c, 1, "admin", "wifi.join", "Office")).await.unwrap();
    store.call(|c| audit::record(c, 2, "admin", "wifi.forget", "Office")).await.unwrap();
    let recent = store.call(|c| audit::recent(c, 10)).await.unwrap();
    assert_eq!(recent.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), vec!["wifi.forget", "wifi.join"]);
}

#[tokio::test]
async fn plugin_stores_are_separate_and_limited() {
    use plugin_store::{MAX_BYTES, MAX_KEYS, MAX_VALUE, Put};
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.call(|c| plugin_store::put(c, "a", "k", b"from a")).await.unwrap(), Put::Stored);
    assert_eq!(store.call(|c| plugin_store::put(c, "b", "k", b"from b")).await.unwrap(), Put::Stored);
    // The same key, two plugins: each reads only its own.
    assert_eq!(store.call(|c| plugin_store::get(c, "a", "k")).await.unwrap().as_deref(), Some(&b"from a"[..]));
    assert_eq!(store.call(|c| plugin_store::get(c, "b", "k")).await.unwrap().as_deref(), Some(&b"from b"[..]));
    assert!(store.call(|c| plugin_store::delete(c, "a", "k")).await.unwrap());
    assert!(store.call(|c| plugin_store::get(c, "a", "k")).await.unwrap().is_none());
    assert_eq!(store.call(|c| plugin_store::keys(c, "b")).await.unwrap(), vec!["k".to_owned()]);

    let big = vec![7u8; MAX_VALUE + 1];
    assert_eq!(store.call(move |c| plugin_store::put(c, "a", "big", &big)).await.unwrap(), Put::TooLarge);
    // Up to the byte budget, and no further; replacing a value counts only the new one.
    let full = vec![1u8; MAX_VALUE];
    let fits = MAX_BYTES / (MAX_VALUE + 2);
    for n in 0..fits {
        let value = full.clone();
        assert_eq!(store.call(move |c| plugin_store::put(c, "a", &format!("{n:02}"), &value)).await.unwrap(), Put::Stored);
    }
    let value = full.clone();
    assert_eq!(store.call(move |c| plugin_store::put(c, "a", "xx", &value)).await.unwrap(), Put::Full);
    let value = full.clone();
    assert_eq!(store.call(move |c| plugin_store::put(c, "a", "00", &value)).await.unwrap(), Put::Stored);
    // Plugin b is not affected by a's use.
    assert_eq!(store.call(|c| plugin_store::put(c, "b", "more", b"x")).await.unwrap(), Put::Stored);
    // At most so many keys.
    for n in 0..MAX_KEYS - 2 {
        assert_eq!(store.call(move |c| plugin_store::put(c, "b", &format!("key{n}"), b"v")).await.unwrap(), Put::Stored);
    }
    assert_eq!(store.call(|c| plugin_store::put(c, "b", "one-too-many", b"v")).await.unwrap(), Put::Full);
    assert_eq!(store.call(|c| plugin_store::delete_all(c, "b")).await.unwrap(), MAX_KEYS);
}
