CREATE TABLE IF NOT EXISTS fs_scan_result (
                                              id INTEGER PRIMARY KEY AUTOINCREMENT,

                                              path TEXT NOT NULL,
                                              path_hash TEXT NOT NULL UNIQUE,

                                              file_name TEXT,
                                              extension TEXT,

                                              size_bytes INTEGER,
                                              modified_time_utc INTEGER,

                                              product_name TEXT,
                                              product_version TEXT,
                                              vendor_name TEXT,

                                              classification_status TEXT NOT NULL DEFAULT 'pending',

                                              first_seen_utc INTEGER NOT NULL,
                                              last_seen_utc INTEGER NOT NULL,

                                              scan_run_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_fs_scan_result_last_seen
    ON fs_scan_result(last_seen_utc);

CREATE INDEX IF NOT EXISTS idx_fs_scan_result_classification_status
    ON fs_scan_result(classification_status);