CREATE TABLE `yt_resources` (
    `id` INTEGER PRIMARY KEY,
    `key` VARCHAR(255) NOT NULL UNIQUE,
    `type` VARCHAR(255) NOT NULL,
    `local_file` TEXT NOT NULL,
    `remote_type` VARCHAR(255) NOT NULL,
    `created_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    `updated_at` TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TABLE `yt_resources_url` (
    `id` INTEGER PRIMARY KEY,
    `resource_id` INTEGER NOT NULL UNIQUE REFERENCES `yt_plugin_resource`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `url` TEXT NOT NULL,
    `etag` VARCHAR(255),
    `last_modified` VARCHAR(255),
    `retrieved_at` TEXT
);

CREATE TABLE `yt_resources_github_release` (
    `id` INTEGER PRIMARY KEY,
    `resource_id` INTEGER NOT NULL UNIQUE REFERENCES `yt_plugin_resource`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    `github_username` VARCHAR(255) NOT NULL,
    `github_repo` VARCHAR(255) NOT NULL,
    `asset_name` VARCHAR(255) NOT NULL,
    `git_tag` VARCHAR(255),
    `release_title` TEXT,
    `retrieved_at` TEXT
);
