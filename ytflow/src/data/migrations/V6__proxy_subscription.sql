CREATE TABLE `yt_proxy_subscriptions` (
    `id` INTEGER PRIMARY KEY,
    `proxy_group_id` INTEGER NOT NULL REFERENCES `yt_proxy_groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `format` VARCHAR(63) NOT NULL,
    `url` TEXT NOT NULL,
    `update_frequency` VARCHAR(63),
    `upload_bytes_used` INTEGER,
    `download_bytes_used` INTEGER,
    `bytes_remaining` INTEGER,
    `expires_at` TEXT,
    `additional_info` TEXT,
    `retrieved_at` TEXT
);
