CREATE TABLE `yt_plugin_cache` (
    `id` INTEGER PRIMARY KEY,
    `plugin_id` INTEGER NOT NULL REFERENCES `yt_plugins`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `key` VARCHAR(255) NOT NULL,
    `value` TEXT NOT NULL,
    UNIQUE (`plugin_id`, `key`)
);
