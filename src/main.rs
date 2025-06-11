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
use tokio::process::Command;
use tracing::{error, info};
use tracing_subscriber::EnvFilter; // Added for robust logger initialization

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
    #[arg(long, default_value_t = 17600)]
    port: u16,

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
    #[serde(default, with = "map_to_vec")]
    mappings: Vec<Mapping>,
}

#[derive(Debug, Deserialize, Default)]
struct Commands {
    open_file: Option<String>,
    show_in_fm: Option<String>,
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
    cfg: Config,
    config_path: PathBuf,
    open_cmd: String,
    show_cmd: String,
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
        // On Windows, parsing command strings is tricky. It's more robust
        // to pass arguments separately instead of a single string to `cmd /C`.

        // Special, robust handling for the `start` command.
        // `start ""` requires the empty title `""` as its own argument.
        if let Some(path_part) = cmd.strip_prefix(r#"start "" "#) {
            // The path_part is the quoted path, e.g., `"C:\path\to\file.toml"`.
            // We must un-quote it here, because the Command builder will add
            // its own quotes correctly when spawning the process.
            let unquoted_path = path_part.trim_matches('"');
            Command::new("cmd")
                .arg("/C")
                .arg("start")
                .arg("") // This is the empty title argument
                .arg(unquoted_path) // This is the file/URL to open
                .spawn()?;

        // Special, robust handling for the `explorer` command.
        // It's an executable, so we can call it directly without `cmd /C`.
        } else if let Some(path_part) = cmd.strip_prefix("explorer ") {
            Command::new("explorer")
                .arg(path_part) // e.g., /select,"C:\path\to\file.toml"
                .spawn()?;
        } else {
            // Fallback for other custom commands
            Command::new("cmd").args(["/C", cmd]).spawn()?;
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
    fn load() -> anyhow::Result<(Self, PathBuf)> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("No config dir"))?
            .join("panoptikon-relay");

        let path = config_dir.join("config.toml");

        if !path.exists() {
            std::fs::create_dir_all(&config_dir)?;
            std::fs::write(&path, DEFAULT_CONFIG.trim_start())?;
            println!("Created default config at {}", path.display());
        }
        let txt = std::fs::read_to_string(&path)?;
        Ok((toml::from_str(&txt)?, path))
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

    // Path translation
    let client_path = match st.cfg.translate(&q.path) {
        Some(p) => p,
        None => return StatusCode::BAD_REQUEST,
    };

    // Resolve template
    let cmd_tpl = match q.verb.as_deref() {
        Some("folder") => &st.show_cmd,
        _ => &st.open_cmd,
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

    // Resolve template
    let cmd_tpl = match q.verb.as_deref() {
        Some("folder") => &st.show_cmd,
        _ => &st.open_cmd,
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
    if tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .is_err()
    {
        eprintln!("Error: Failed to initialize the tracing subscriber. Logs may not be available.");
    }
    info!("Starting panoptikon-relay...");

    let cli = Cli::parse();
    let (cfg, config_path) = Config::load()?;
    info!("Loaded config");
    let (open_cmd, show_cmd) = cfg.commands();
    let (token, from_env) = load_or_generate_token(&config_path)?;
    let state = Arc::new(AppState {
        cfg,
        config_path,
        open_cmd,
        show_cmd,
        token: token.clone(),
        require_token: !cli.no_token,
    });

    let app = Router::new()
        .route("/healthy", get(healthy))
        .route("/open", post(open))
        .route("/config", post(config_endpoint))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cli.port));

    info!("Listening on http://{addr}");
    if !from_env {
        info!("The API key is: {token}");
    } else {
        info!("Using API key from environment variable (not shown for security)");
    }

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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

# Map *server* path prefixes to *client* prefixes
[mappings]
"/srv/media"        = 'Z:\\media'
"/home/user/videos" = '/Volumes/videos'
"//nas/share/raw"   = 'X:\\raw'
"##;
