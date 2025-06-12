#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use clap::{Parser, arg, command};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{process::Command, runtime::Runtime};
use tracing::{debug, error, info};
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tray_icon::{
    TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

// ─────────────────────────────────────────────────────────────
// CLI / daemon flags
// ─────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Local helper to open files revealed by a remote indexer."
)]
struct Cli {
    /// TCP port to listen on (default 17600)
    #[arg(long)]
    port: Option<u16>,

    /// IP address to bind to (default 127.0.0.1)
    #[arg(long)]
    bind_address: Option<String>,

    /// Disable capability‑token check (NOT recommended)
    #[arg(long)]
    no_token: bool,
}

// ─────────────────────────────────────────────────────────────
// Config types – `[commands]` + `[mappings]` table compressed
// ─────────────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    commands: Commands,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default, with = "map_to_vec")]
    mappings: Vec<Mapping>,
}

#[derive(Debug, Deserialize, Default)]
struct Commands {
    open_file: Option<String>,
    show_in_fm: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NetworkConfig {
    bind_address: Option<String>,
    port: Option<u16>,
}

#[derive(Debug)]
struct Mapping {
    server: String,
    client: String,
}

// Custom deserializer converting TOML table to Vec<Mapping>
mod map_to_vec {
    use super::Mapping;
    use serde::{Deserialize, Deserializer};
    use std::cmp::Reverse;
    use std::collections::BTreeMap;

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<Mapping>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = BTreeMap::<String, String>::deserialize(de)?;
        let mut v: Vec<_> = map
            .into_iter()
            .map(|(k, v)| Mapping {
                server: k,
                client: v,
            })
            .collect();
        // Longest prefix first
        v.sort_by_key(|m| Reverse(m.server.len()));
        Ok(v)
    }
}

// ─────────────────────────────────────────────────────────────
// Runtime state shared with Axum handlers
// ─────────────────────────────────────────────────────────────
struct AppState {
    config_path: PathBuf,
    token: String,
    require_token: bool,
}

// ─────────────────────────────────────────────────────────────
// Constants for platform‑default commands
// ─────────────────────────────────────────────────────────────
#[cfg(target_os = "windows")]
const OPEN_DEFAULT: &str = r#"start "" "{path}""#;
#[cfg(target_os = "windows")]
const REVEAL_DEFAULT: &str = r#"explorer /select,{path}"#;

#[cfg(target_os = "macos")]
const OPEN_DEFAULT: &str = r#"open "{path}""#;
#[cfg(target_os = "macos")]
const REVEAL_DEFAULT: &str = r#"open -R "{path}""#;

#[cfg(target_os = "linux")]
const OPEN_DEFAULT: &str = r#"xdg-open "{path}""#;
#[cfg(target_os = "linux")]
const REVEAL_DEFAULT: &str = r#"dolphin --select "{path}" || \
nautilus --select "{path}" || \
thunar --select "{path}" || \
nemo "{path}" || \
xdg-open "{folder}""#;

// ─────────────────────────────────────────────────────────────
// Helper: substitute placeholders
// ─────────────────────────────────────────────────────────────
fn substitute(cmd_tpl: &str, path: &Path) -> String {
    let folder = path.parent().unwrap_or(Path::new(" ")).to_string_lossy();
    let filename = path.file_name().unwrap_or_default().to_string_lossy();

    cmd_tpl
        .replace("{path}", &format!(r#"{}"#, path.display()))
        .replace("{folder}", &format!(r#"{}"#, folder))
        .replace("{filename}", &format!(r#"{}"#, filename))
}

// ─────────────────────────────────────────────────────────────
// Run command via shell (Windows) or sh / direct exec (Unix)
// ─────────────────────────────────────────────────────────────
async fn run_command(cmd: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // On Windows, parsing command strings is tricky. It's more robust
        // to pass arguments separately instead of a single string to `cmd /C`.

        // Special, robust handling for the `start` command.
        // `start ""` requires the empty title `""` as its own argument.
        if let Some(path_part) = cmd.strip_prefix(r#"start "" "#) {
            // The path_part is the quoted path, e.g., `"C:\\path\\to\\file.toml"`.
            // We must un-quote it here, because the Command builder will add
            // its own quotes correctly when spawning the process.
            let unquoted_path = path_part.trim_matches('"');
            Command::new("cmd")
                .creation_flags(CREATE_NO_WINDOW) // Prevent console window flash
                .arg("/C")
                .arg("start")
                .arg("") // This is the empty title argument
                .arg(unquoted_path) // This is the file/URL to open
                .spawn()?;

        // Special, robust handling for the `explorer` command.
        // It's an executable, so we can call it directly without `cmd /C`.
        } else if let Some(path_part) = cmd.strip_prefix("explorer ") {
            Command::new("explorer")
                // explorer.exe is a GUI app, CREATE_NO_WINDOW is generally not needed here
                // but can be added if any issues were observed.
                // .creation_flags(CREATE_NO_WINDOW)
                .arg(path_part) // e.g., /select,"C:\\path\\to\\file.toml"
                .spawn()?;
        } else {
            // Fallback for other custom commands
            Command::new("cmd")
                .creation_flags(CREATE_NO_WINDOW) // Prevent console window flash
                .args(["/C", cmd])
                .spawn()?;
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Use /bin/sh -c when cmd contains pipes / multiline
        if cmd.contains('\n') || cmd.contains("||") || cmd.contains("&&") {
            Command::new("sh").arg("-c").arg(cmd).spawn()?;
        } else {
            let parts = shlex::split(cmd).expect("Unbalanced quotes");
            let (prog, args) = parts.split_first().expect("Empty command");
            Command::new(prog).args(args).spawn()?;
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Config loader + helpers
// ─────────────────────────────────────────────────────────────
impl Config {
    async fn load() -> anyhow::Result<(Self, PathBuf)> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("No config dir"))?
            .join("panoptikon-relay");

        let path = config_dir.join("config.toml");

        if !path.exists() {
            std::fs::create_dir_all(&config_dir)?;
            std::fs::write(&path, DEFAULT_CONFIG.trim_start())?;
            println!("Created default config at {}", path.display());

            // Attempt to open the config file and its folder
            info!(
                "Default config created at {}. Attempting to open config file and folder.",
                path.display()
            );

            let open_file_cmd_tpl = OPEN_DEFAULT;
            let show_folder_cmd_tpl = REVEAL_DEFAULT;

            let cmd_to_open_file = substitute(open_file_cmd_tpl, &path);
            let config_folder_path = path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "Config file path {} has no parent directory",
                    path.display()
                )
            })?;
            // Use `&path` for substitute, so explorer /select highlights the file
            let cmd_to_show_folder = substitute(show_folder_cmd_tpl, &path);

            if let Err(e) = run_command(&cmd_to_open_file).await {
                error!(
                    "Failed to open config file automatically ({}): {}",
                    cmd_to_open_file, e
                );
            } else {
                info!("Attempted to open config file: {}", path.display());
            }

            if let Err(e) = run_command(&cmd_to_show_folder).await {
                error!(
                    "Failed to show config folder automatically ({}): {}",
                    cmd_to_show_folder, e
                );
            } else {
                info!(
                    "Attempted to show config folder: {}",
                    config_folder_path.display()
                );
            }
        }
        let txt = std::fs::read_to_string(&path)?;
        Ok((toml::from_str(&txt)?, path))
    }

    /// Load config from a specific path (for reloading)
    fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        let txt = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&txt)?)
    }

    /// Translate by longest prefix (already sorted).
    fn translate(&self, server_path: &str) -> Option<PathBuf> {
        let canonical = server_path.replace('\\', "/");
        let mapping = self
            .mappings
            .iter()
            .find(|m| canonical.starts_with(&m.server))?;
        let suffix = canonical.strip_prefix(&mapping.server).unwrap_or("");
        let mut pb = PathBuf::from(&mapping.client);
        for c in Path::new(suffix).components() {
            pb.push(c);
        }
        Some(pb)
    }

    fn commands(&self) -> (String, String) {
        let open = std::env::var("OPEN_FILE_COMMAND")
            .ok()
            .or_else(|| self.commands.open_file.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| OPEN_DEFAULT.to_string());

        let show = std::env::var("SHOW_IN_FM_COMMAND")
            .ok()
            .or_else(|| self.commands.show_in_fm.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| REVEAL_DEFAULT.to_string());

        (open, show)
    }

    fn bind_address(&self, cli_bind_address: Option<&String>) -> String {
        // Priority: Environment variable > CLI argument > Config file > Default
        if let Ok(env_addr) = std::env::var("BIND_ADDRESS") {
            if !env_addr.is_empty() {
                return env_addr;
            }
        }

        // CLI argument takes precedence over config file
        if let Some(cli_addr) = cli_bind_address {
            return cli_addr.clone();
        }

        // Config file value
        self.network
            .bind_address
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    }

    fn port(&self, cli_port: Option<u16>) -> u16 {
        // Priority: Environment variable > CLI argument > Config file > Default
        if let Ok(env_port) = std::env::var("PORT") {
            if let Ok(port) = env_port.parse::<u16>() {
                return port;
            }
        }

        // CLI argument takes precedence over config file
        if let Some(port) = cli_port {
            return port;
        }

        // Config file value
        self.network.port.unwrap_or(17600)
    }
}

// ─────────────────────────────────────────────────────────────
// Token management functions
// ─────────────────────────────────────────────────────────────
fn get_token_file_path(config_path: &Path) -> PathBuf {
    config_path.parent().unwrap().join("token.txt")
}

fn load_or_generate_token(config_path: &Path) -> anyhow::Result<(String, bool)> {
    // Check environment variable first
    if let Ok(env_token) = std::env::var("API_KEY_SECRET") {
        info!("Using token from environment variable API_KEY_SECRET");
        return Ok((env_token, true)); // true means from env (don't print/store)
    }

    let token_path = get_token_file_path(config_path);

    // Try to load existing token file
    if token_path.exists() {
        match std::fs::read_to_string(&token_path) {
            Ok(token) => {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    info!("Loaded existing token from file");
                    return Ok((token, false)); // false means from file (can print)
                }
            }
            Err(e) => {
                error!("Failed to read token file: {}", e);
            }
        }
    }

    // Generate new token and save it
    let token = uuid::Uuid::new_v4().to_string();
    std::fs::write(&token_path, &token)?;
    info!("Generated new token and saved to file");
    Ok((token, false)) // false means from file (can print)
}

// ─────────────────────────────────────────────────────────────
// Axum handlers
// ─────────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct OpenQuery {
    path: String,
    verb: Option<String>, // open | folder
}

#[derive(Deserialize)]
struct ConfigQuery {
    verb: Option<String>, // open | folder
}

// Helper function to extract and validate Bearer token from Authorization header
fn validate_bearer_token(headers: &HeaderMap, expected_token: &str) -> bool {
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return token == expected_token;
            }
        }
    }
    false
}

async fn healthy() -> &'static str {
    "ok"
}

async fn open(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<OpenQuery>,
) -> impl IntoResponse {
    // Token enforcement
    if st.require_token {
        if !validate_bearer_token(&headers, &st.token) {
            return StatusCode::UNAUTHORIZED;
        }
    }

    // Reload config for fresh commands and mappings
    let cfg = match Config::load_from_path(&st.config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to reload config: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Path translation
    let client_path = match cfg.translate(&q.path) {
        Some(p) => p,
        None => return StatusCode::BAD_REQUEST,
    };

    // Get fresh commands
    let (open_cmd, show_cmd) = cfg.commands();

    // Resolve template
    let cmd_tpl = match q.verb.as_deref() {
        Some("folder") => &show_cmd,
        _ => &open_cmd,
    };
    let cmd = substitute(cmd_tpl, &client_path);
    info!("Running command: {cmd} for path: {client_path:?}");

    // Spawn command
    if let Err(e) = run_command(&cmd).await {
        error!(?e, "Command failed");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::NO_CONTENT
}

async fn config_endpoint(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ConfigQuery>,
) -> impl IntoResponse {
    // Token enforcement
    if st.require_token {
        if !validate_bearer_token(&headers, &st.token) {
            return StatusCode::UNAUTHORIZED;
        }
    }

    // Reload config for fresh commands
    let cfg = match Config::load_from_path(&st.config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to reload config: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Get fresh commands
    let (open_cmd, show_cmd) = cfg.commands();

    // Resolve template
    let cmd_tpl = match q.verb.as_deref() {
        Some("folder") => &show_cmd,
        _ => &open_cmd,
    };
    let cmd = substitute(cmd_tpl, &st.config_path);
    info!(
        "Running command: {cmd} for config path: {:?}",
        st.config_path
    );

    // Spawn command
    if let Err(e) = run_command(&cmd).await {
        error!(?e, "Command failed");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::NO_CONTENT
}

// ─────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_dir_for_logs = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("No config dir found for logging"))?
        .join("panoptikon-relay");
    if !config_dir_for_logs.exists() {
        std::fs::create_dir_all(&config_dir_for_logs)?;
    }

    // Setup file logging with rotation
    let file_appender = rolling::Builder::new()
        .rotation(rolling::Rotation::DAILY) // Or Rotation::HOURLY, or Rotation::NEVER
        .filename_prefix("panoptikon-relay")
        .filename_suffix("log")
        .max_log_files(7) // Keep 7 log files
        .build(&config_dir_for_logs)?; // Log directory

    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(file_appender);

    if tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(non_blocking_writer.and(std::io::stdout)) // Log to both file and stdout
        .try_init()
        .is_err()
    {
        eprintln!("Error: Failed to initialize the tracing subscriber. Logs may not be available.");
    }
    info!("Starting panoptikon-relay...");

    let cli = Cli::parse();
    let (cfg, config_path) = Config::load().await?;
    info!("Loaded config");

    // Network configuration is set at startup and remains fixed
    let bind_ip = cfg.bind_address(cli.bind_address.as_ref());
    let port = cfg.port(cli.port);
    let (token, from_env) = load_or_generate_token(&config_path)?;

    // Clone necessary data for the event handler before moving into AppState
    let token_for_events = token.clone();
    let config_path_for_events = config_path.clone();

    let state = Arc::new(AppState {
        config_path,
        token: token.clone(),
        require_token: !cli.no_token,
    });

    let app = Router::new()
        .route("/healthy", get(healthy))
        .route("/open", post(open))
        .route("/config", post(config_endpoint))
        .with_state(state);

    let addr = format!("{}:{}", bind_ip, port).parse::<std::net::SocketAddr>()?;

    info!("Listening on http://{addr}");
    if !from_env {
        info!("The API key is: {token}");
    } else {
        info!("Using API key from environment variable (not shown for security)");
    }

    // Create menu items
    let copy_token_item = MenuItem::new("Copy API Key", true, None);
    let open_config_item = MenuItem::new("Open Config File", true, None);
    let show_config_folder_item = MenuItem::new("Show Config Folder", true, None);
    let separator = PredefinedMenuItem::separator();
    let quit_item = MenuItem::new("Exit", true, None);

    // Create the tray menu with items
    let tray_menu = Menu::with_items(&[
        &copy_token_item,
        &separator,
        &open_config_item,
        &show_config_folder_item,
        &separator,
        &quit_item,
    ])
    .unwrap();

    // Store menu item IDs for event handling
    let copy_token_id = copy_token_item.id().clone();
    let open_config_id = open_config_item.id().clone();
    let show_config_folder_id = show_config_folder_item.id().clone();
    let quit_id = quit_item.id().clone();

    debug!(
        "Menu item IDs - Copy: {:?}, Open: {:?}, Show: {:?}, Quit: {:?}",
        copy_token_id, open_config_id, show_config_folder_id, quit_id
    );

    // Embed the icon at compile time and convert it to the proper format
    let icon_data = include_bytes!("../icon.ico");
    let icon = match image::load_from_memory(icon_data) {
        Ok(img) => {
            let rgba_img = img.to_rgba8();
            let (width, height) = rgba_img.dimensions();
            tray_icon::Icon::from_rgba(rgba_img.into_raw(), width, height).unwrap()
        }
        Err(_) => {
            // Fallback to a simple blue icon if the ICO file can't be loaded
            let mut fallback_data = Vec::new();
            for _ in 0..(16 * 16) {
                fallback_data.extend_from_slice(&[0, 100, 200, 255]); // Blue RGBA pixels
            }
            tray_icon::Icon::from_rgba(fallback_data, 16, 16).unwrap()
        }
    };

    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("Panoptikon Relay")
        .with_icon(icon)
        .build()
        .unwrap();

    // Start the menu event handler in a blocking task
    let token_for_events = token_for_events.clone();
    let config_path_for_events = config_path_for_events.clone();

    std::thread::spawn(move || {
        let menu_event_receiver = MenuEvent::receiver();
        debug!("Menu event handler started, waiting for events...");

        loop {
            match menu_event_receiver.recv() {
                Ok(event) => {
                    debug!("Received menu event: {:?}", event.id());
                    let event_id = event.id();

                    if *event_id == copy_token_id {
                        // Copy API key to clipboard
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                if let Err(e) = clipboard.set_text(&token_for_events) {
                                    error!("Failed to copy token to clipboard: {}", e);
                                } else {
                                    info!("API key copied to clipboard");
                                }
                            }
                            Err(e) => error!("Failed to access clipboard: {}", e),
                        }
                    } else if *event_id == open_config_id {
                        // Open config file
                        let cfg = match Config::load_from_path(&config_path_for_events) {
                            Ok(cfg) => cfg,
                            Err(e) => {
                                error!("Failed to load config: {}", e);
                                continue;
                            }
                        };
                        let (open_cmd, _) = cfg.commands();
                        let cmd = substitute(&open_cmd, &config_path_for_events);

                        // Run command synchronously in thread
                        let rt = Runtime::new().unwrap();
                        let run_command_sync =
                            |cmd: &str| rt.block_on(async { run_command(cmd).await });

                        let result = run_command_sync(&cmd);

                        if let Err(e) = result {
                            error!("Failed to open config file: {}", e);
                        } else {
                            info!("Opened config file");
                        }
                    } else if *event_id == show_config_folder_id {
                        let cfg = match Config::load_from_path(&config_path_for_events) {
                            Ok(cfg) => cfg,
                            Err(e) => {
                                error!("Failed to load config: {}", e);
                                continue;
                            }
                        };
                        let (_, show_cmd) = cfg.commands();
                        let cmd = substitute(&show_cmd, &config_path_for_events);

                        // Run command synchronously in thread
                        // Execute run_command function synchronously using tokio
                        let rt = Runtime::new().unwrap();
                        let run_command_sync =
                            |cmd: &str| rt.block_on(async { run_command(cmd).await });

                        let result = run_command_sync(&cmd);

                        if let Err(e) = result {
                            error!("Failed to show config folder: {}", e);
                        } else {
                            info!("Showed config folder");
                        }
                    } else if *event_id == quit_id {
                        // Exit the application
                        info!("Exit requested from tray menu");
                        std::process::exit(0);
                    } else {
                        info!("Unknown menu event: {:?}", event_id);
                    }
                }
                Err(e) => {
                    error!("Failed to receive menu event: {}", e);
                    break;
                }
            }
        }
    });

    // Start HTTP server in a separate thread
    let server_addr = addr;
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });

    debug!("HTTP server started on separate thread");

    // Platform-specific event loops
    #[cfg(windows)]
    {
        info!("Starting Windows message loop...");
        unsafe {
            use winapi::um::winuser::{DispatchMessageW, GetMessageW, MSG, TranslateMessage};
            let mut msg: MSG = std::mem::zeroed();
            loop {
                let bret = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                if bret == 0 || bret == -1 {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        info!("Starting GTK event loop...");
        gtk::init().expect("Failed to initialize GTK");
        gtk::main();
    }

    #[cfg(target_os = "macos")]
    {
        info!("Starting macOS event loop...");
        // On macOS, we need to run the main event loop
        // The tray icon is already created on the main thread
        use std::ffi::c_void;
        extern "C" {
            fn CFRunLoopRun();
        }
        unsafe {
            CFRunLoopRun();
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        debug!("Unknown platform, keeping main thread alive...");
        // For other platforms, just keep the main thread alive
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Embedded default_config.toml (created on first run)
// ─────────────────────────────────────────────────────────────
const DEFAULT_CONFIG: &str = r##"
[commands]
# You can customize the commands to open files or reveal them in the file manager.
# These commands support placeholders:
# {path} - full path to the file
# {folder} - parent folder of the file
# {filename} - name of the file
# The default commands are platform-specific.
open_file  = ""                      # leave empty to use platform default
show_in_fm = ""                      

[network]
# Network configuration
# IP address to bind to (default: 127.0.0.1)
# Priority: BIND_ADDRESS env var > --bind-address CLI arg > config file > default
bind_address = "127.0.0.1"

# Port to listen on (default: 17600)
# Priority: PORT env var > --port CLI arg > config file > default
port = 17600

# Map *server* path prefixes to *client* prefixes
[mappings]
"/srv/media"        = 'Z:\\media'
"/home/user/videos" = '/Volumes/videos'
"//nas/share/raw"   = 'X:\\raw'
"##;
