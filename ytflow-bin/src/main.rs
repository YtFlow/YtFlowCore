use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{arg, value_parser, ArgMatches};
use log::{error, info, warn};

mod fs_resource_loader;

fn main() -> Result<()> {
    let args = get_args();
    init_log(&args);
    try_main(&args)
}

fn get_args() -> ArgMatches {
    clap::command!()
        .arg(
            arg!(--"db-path" <PATH> "Path to the database file. If the file does not exist, an empty database will be created. If missing, an in-memory database will be used")
                .value_parser(value_parser!(PathBuf))
                .required(false)
        )
        .arg(
            arg!(--"resource-root" <PATH> "Path to the root of the resource directory. Defaults to the current working directory")
                .value_parser(value_parser!(PathBuf))
                .required(false)
        )
        .arg(arg!([PROFILE] "Specify the name of the profile to use"))
        // .arg(arg!(-l --"from-link" <LINK> "Generate a new profile using the provided share link as outbound, and save to the database").required(false))
        .arg(arg!(--"skip-grace" "Start immediately. Do not wait for 3 seconds before YtFlow starts running").required(false))
        .arg(arg!(-v --verbose "Turn on verbose logging").required(false))
        .get_matches()
}

fn init_log(args: &ArgMatches) {
    let is_verbose = args.get_flag("verbose");
    let colors = fern::colors::ColoredLevelConfig::new();
    let default_level;
    #[cfg(debug_assertions)]
    {
        default_level = log::LevelFilter::Debug;
    }
    #[cfg(not(debug_assertions))]
    {
        default_level = log::LevelFilter::Info;
    }
    let level = if is_verbose {
        log::LevelFilter::Debug
    } else {
        default_level
    };

    let mut dispatch = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S%.3f]"),
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(level);
    #[cfg(not(debug_assertions))]
    if !is_verbose() {
        dispatch = dispatch.filter(|meta| meta.target().starts_with("ytflow_core"));
    }
    // To keep the `mut` on `dispatch`
    dispatch = dispatch.filter(|meta| !meta.target().starts_with("maxminddb::decoder"));
    dispatch
        .chain(std::io::stdout())
        .apply()
        .expect("Cannot set up logger");
}

fn init_resource_loader(args: &ArgMatches) -> Result<fs_resource_loader::FsResourceLoader> {
    let resource_root = args
        .get_one::<PathBuf>("resource-root")
        .cloned()
        .unwrap_or_else(|| {
            std::env::current_dir().expect("Cannot get working directory for resources")
        });
    let loader = fs_resource_loader::FsResourceLoader::new(resource_root)
        .context("Failed to initialize resource loader")?;
    info!("Using resource root: {}", loader.root().display());
    Ok(loader)
}

fn try_main(args: &ArgMatches) -> Result<()> {
    let db = args
        .get_one::<PathBuf>("db-path")
        .map(AsRef::<Path>::as_ref)
        .map(Path::canonicalize)
        .transpose()
        .context("Failed to load database path")?
        .map(|path| {
            info!("Connecting to database: {}", path.display());
            ytflow::data::Database::open(path)
        })
        .transpose()
        .context("Failed to open database")?;

    let conn = if let Some(db) = &db {
        db.connect().context("Failed to connect to database")?
    } else {
        info!("Connecting to database: in-memory");
        ytflow::data::Database::connect_temp().expect("Could not open in-memory database")
    };

    let profile_name = args
        .get_one::<String>("PROFILE")
        .map(|s| s.as_str())
        .unwrap_or("default");
    info!("Selected Profile: {}", profile_name);

    let all_profiles = ytflow::data::Profile::query_all(&conn)
        .context("Failed to load all Profiles from database")?;
    let profile = all_profiles
        .iter()
        .find(|p| p.name == profile_name)
        .ok_or_else(|| {
            error!(
                r#"Cannot find Profile: "{}". Existing Profiles: {}"#,
                profile_name,
                all_profiles
                    .iter()
                    .map(|p| p.name.clone())
                    .collect::<Vec<_>>()
                    .join("\r\n")
            );
            anyhow::anyhow!("Profile not found")
        })?;

    let all_plugins: Vec<_> = ytflow::data::Plugin::query_all_by_profile(profile.id, &conn)
        .context("Failed to load all plugins for selected Profile from database")?
        .into_iter()
        .map(From::from)
        .collect();
    let entry_plugins: Vec<_> = ytflow::data::Plugin::query_entry_by_profile(profile.id, &conn)
        .context("Failed to load entry plugins for selected Profile from database")?
        .into_iter()
        .map(From::from)
        .collect();
    use ytflow::config::loader::{ProfileLoadResult, ProfileLoader};
    let (factory, required_resources, load_errors) =
        ProfileLoader::parse_profile(entry_plugins.iter(), &all_plugins);
    if !load_errors.is_empty() {
        warn!(
            "{} errors detected from selected Profile:",
            load_errors.len()
        );
    }
    for load_error in load_errors {
        warn!("{}", load_error);
    }

    let runtime = ytflow::tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Error initializing Tokio runtime")?;
    let runtime_enter_guard = runtime.enter();

    let resource_registry = if required_resources.is_empty() {
        Box::new(ytflow::resource::EmptyResourceRegistry) as _
    } else {
        let resource_keys = required_resources
            .iter()
            .map(|r| r.key.to_string())
            .collect::<BTreeSet<_>>();
        let resource_len = resource_keys.len();
        let mut loader =
            ytflow::resource::DbFileResourceLoader::new_with_required_keys(resource_keys, &conn)
                .context("Loading resource information from database")?;
        info!("Loading {} resources...", resource_len);
        runtime
            .block_on(futures::future::join_all(
                loader.load_required_files(&init_resource_loader(args)?),
            ))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .context("Loading resource from file system")?;
        info!("Resources loaded");
        Box::new(loader) as _
    };

    if !args.get_flag("skip-grace") {
        info!("Starting YtFlow in 3 seconds...");
        std::thread::sleep(Duration::from_secs(3));
    }
    info!("Starting YtFlow...");

    let ProfileLoadResult {
        plugin_set,
        errors: load_errors,
        ..
    } = factory.load_all(runtime.handle(), resource_registry, db.as_ref());
    if !load_errors.is_empty() {
        warn!(
            "{} errors detected while loading plugins:",
            load_errors.len()
        );
    }
    for load_error in load_errors {
        error!("{}", load_error);
    }
    info!("Plugins loaded");

    let (ctrlc_tx, ctrlc_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        use std::sync::atomic::Ordering;
        static CTRLC_FIRED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if CTRLC_FIRED.load(Ordering::Relaxed) != 0 {
            std::process::exit(2);
        };
        CTRLC_FIRED.store(1, Ordering::Relaxed);
        let _ = ctrlc_tx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    ctrlc_rx
        .recv()
        .expect("Error waiting for Ctrl-C channel signal");
    info!("Shutting down all plugins");

    drop(plugin_set);
    info!("Plugins destroyed, shutting down runtime...");

    drop(runtime_enter_guard);
    drop(runtime);
    info!("Runtime destroyed. Bye!");

    Ok(())
}
