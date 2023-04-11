CREATE TABLE `yt_proxy_groups` (
    `id` INTEGER PRIMARY KEY,
    `name` VARCHAR(255) NOT NULL,
    `type` VARCHAR(63) NOT NULL,
    `created_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TABLE `yt_proxies` (
    `id` INTEGER PRIMARY KEY,
    `group_id` INTEGER NOT NULL REFERENCES `yt_proxy_groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `name` VARCHAR(255) NOT NULL,
    `order_num` INTEGER NOT NULL,
    `proxy` BLOB NOT NULL,
    `proxy_version` INT(4) NOT NULL DEFAULT '0',
    `updated_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TRIGGER [yt_proxies_updated]
AFTER UPDATE ON `yt_proxies`
FOR EACH ROW
BEGIN
UPDATE `yt_proxies` SET `updated_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now')) WHERE `id` = old.`id`;
END
