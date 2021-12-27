CREATE TABLE `yt_profiles` (
    `id` INTEGER PRIMARY KEY,
    `permanent_id` BLOB(16) NOT NULL UNIQUE DEFAULT (randomblob(16)),
    `name` VARCHAR(255) NOT NULL UNIQUE,
    `locale` VARCHAR(64) NOT NULL DEFAULT 'en-US',
    `last_used_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    `created_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TABLE `yt_plugins` (
    `id` INTEGER PRIMARY KEY,
    `profile_id` INTEGER NOT NULL REFERENCES `yt_profiles`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `name` VARCHAR(255) NOT NULL,
    `desc` TEXT NOT NULL DEFAULT '',
    `plugin` VARCHAR(255) NOT NULL,
    `plugin_version` INT(4) NOT NULL DEFAULT '0',
    `param` TEXT NOT NULL,
    `updated_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    UNIQUE (`profile_id`, `name`)
);

CREATE TABLE `yt_profile_entry_plugin` (
    `profile_id` INTEGER NOT NULL REFERENCES `yt_profiles`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `plugin_id` INTEGER NOT NULL REFERENCES `yt_plugins`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    PRIMARY KEY (`profile_id`,`plugin_id`)
);

CREATE TRIGGER [yt_plugins_updated]
AFTER UPDATE ON `yt_plugins`
FOR EACH ROW
BEGIN
UPDATE `yt_plugins` SET `updated_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now')) WHERE `id` = old.`id`;
END
