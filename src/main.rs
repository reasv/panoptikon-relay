use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use clap::{Parser, arg, command};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::process::Command;
use tracing::{error, info};

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
    #[serde(default)]
    token: Option<String>, // capability token – can be stored here too
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
    open_cmd: String,
    show_cmd: String,
    token: String,
    require_token: bool,
}

// ─────────────────────────────────────────────────────────────
// Constants for platform‑default commands
// ─────────────────────────────────────────────────────────────
#[cfg(target_os = "windows")]
const OPEN_DEFAULT: &str = r#"cmd /C start "" "{path}""#;
#[cfg(target_os = "windows")]
const REVEAL_DEFAULT: &str = r#"explorer /select,"{path}""#;

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
        Command::new("cmd").args(["/C", cmd]).spawn()?;
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
    fn load() -> anyhow::Result<Self> {
        let path = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("No config dir"))?
            .join("openfile-helper")
            .join("config.toml");

        if !path.exists() {
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, DEFAULT_CONFIG.trim_start())?;
            println!("Created default config at {}", path.display());
        }
        let txt = std::fs::read_to_string(&path)?;
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
            .or_else(|| self.commands.open_file.clone())
            .unwrap_or_else(|| OPEN_DEFAULT.to_string());

        let show = std::env::var("SHOW_IN_FM_COMMAND")
            .ok()
            .or_else(|| self.commands.show_in_fm.clone())
            .unwrap_or_else(|| REVEAL_DEFAULT.to_string());

        (open, show)
    }
}

// ─────────────────────────────────────────────────────────────
// Axum handlers
// ─────────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct OpenQuery {
    path: String,
    verb: Option<String>, // open | folder
    token: Option<String>,
}

async fn healthy() -> &'static str {
    "ok"
}

async fn open(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<OpenQuery>,
) -> impl IntoResponse {
    // Token enforcement
    if st.require_token {
        if q.token.as_deref() != Some(&st.token) {
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cfg = Config::load()?;
    info!("Loaded config");
    let (open_cmd, show_cmd) = cfg.commands();

    let token: String = cfg
        .token
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let state = Arc::new(AppState {
        cfg,
        open_cmd,
        show_cmd,
        token: token.clone(),
        require_token: !cli.no_token,
    });

    let app = Router::new()
        .route("/healthy", get(healthy))
        .route("/open", get(open))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cli.port));
    info!("Listening on http://{addr}");
    info!("The API key is: {token}");

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
