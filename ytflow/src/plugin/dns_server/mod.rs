mod datagram;
mod map_back;

use std::sync::Arc;

pub use datagram::DnsServer;
pub use map_back::{MapBackDatagramSessionHandler, MapBackStreamHandler};

pub async fn cache_writer(plugin: Arc<DnsServer>) {
    let (plugin, notify) = {
        let notify = plugin.new_notify.clone();
        let weak = Arc::downgrade(&plugin);
        drop(plugin);
        (weak, notify)
    };
    if plugin.strong_count() == 0 {
        panic!("dns-server has no strong reference left for cache_writer");
    }

    use tokio::select;
    use tokio::time::{sleep, Duration};
    loop {
        let mut notified_fut = notify.notified();
        let mut sleep_fut = sleep(Duration::from_secs(3600));
        'debounce: loop {
            select! {
                _ = notified_fut => {
                    notified_fut = notify.notified();
                    sleep_fut = sleep(Duration::from_secs(3));
                }
                _ = sleep_fut => {
                    break 'debounce;
                }
            }
        }
        match plugin.upgrade() {
            Some(plugin) => plugin.save_cache(),
            None => break,
        }
    }
}
