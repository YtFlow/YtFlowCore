CREATE TRIGGER [yt_resources_updated]
AFTER UPDATE ON `yt_resources`
FOR EACH ROW
BEGIN
UPDATE `yt_resources` SET `updated_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now')) WHERE `id` = old.`id`;
END
