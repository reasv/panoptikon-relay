# Panoptikon Relay

Panoptikon Relay is a lightweight tray icon application and local HTTP server designed to act as an optional companion to [Panoptikon](https://github.com/reasv/panoptikon), a state-of-the-art local multimodal multimedia search engine.

## Overview

Panoptikon Relay solves a specific challenge: when Panoptikon is running on a remote server, inside a container, or in any environment where it cannot directly access your local file system to open files or reveal them in your file manager. If you can access the files indexed by Panoptikon directly on your client machine (e.g., via network shares like SMB/NFS), Panoptikon Relay bridges this gap.

It runs on your client machine, listens for requests from the Panoptikon UI in your browser, translates server-side paths to local client-side paths, and then executes local commands to open the file or show it in your file manager.

## Features

- **Tray Icon:** Provides easy access to:
  - Copy the API Key.
  - Open the configuration file (`config.toml`).
  - Show the configuration folder in the file manager.
  - Exit the application.
- **HTTP Server:** Listens for commands from a Panoptikon instance.
  - `/open`: Handles requests to open a file or show it in the folder.
  - `/config`: Allows opening the configuration file or folder via an API call (primarily for convenience or remote management if needed, though tray icon is the main way).
  - `/healthy`: A simple health check endpoint.
- **Secure API:** Uses a Bearer Token (API Key) for authenticating requests from Panoptikon.
  - Token is automatically generated on first run if not provided.
  - Can be disabled via a command-line flag (which would be a hilariously poor decision).
- **Path Mapping:** Flexible configuration to translate file paths from the server's perspective (as Panoptikon sees them) to your local client machine's perspective.
- **Customizable Commands:** Define custom shell commands for:
  - Opening files (`open_file`).
  - Showing files in the file manager (`show_in_fm`).
  - Supports placeholders: `{path}`, `{folder}`, `{filename}`.
- **Platform-Aware Defaults:** Comes with sensible default commands for Windows, macOS, and Linux if custom commands are not specified.
- **Flexible Configuration:**
  - Primary configuration via `config.toml`.
  - Overrides via environment variables and command-line arguments.
- **Logging:** Records activity and errors to a log file (`panoptikon-relay.log`) in the configuration directory.

## How it Works

1.  **Run Panoptikon Relay:** Start the application on your client machine (e.g., your desktop or laptop) where the files indexed by Panoptikon are accessible.
2.  **Configure Panoptikon:** In the Panoptikon web UI, configure it to use Panoptikon Relay by providing the Relay's address (e.g., `http://127.0.0.1:17600`) and the API key.
3.  **User Action in Panoptikon:** When you click an "Open File" or "Show in Folder" button in Panoptikon's UI for a search result:
    - Panoptikon sends an API request to Panoptikon Relay, including the file path as known on the server and the desired action.
4.  **Relay Processing:**
    - Panoptikon Relay authenticates the request using the API key.
    - It uses the `[mappings]` in its `config.toml` to translate the received server path to a local client path.
    - It then constructs and executes the appropriate local shell command (e.g., `explorer /select,C:\MyFiles\video.mp4` or `xdg-open "/mnt/share/doc.pdf"`) to perform the action.

## Installation

1.  **Download:** Obtain the latest release for your operating system from the [GitHub Releases page](https://github.com/reasv/panoptikon-relay/releases) (Replace with actual link once available).
2.  **Run:** Execute the downloaded application.
    - On Windows, it's `panoptikon-relay.exe`.
    - On macOS/Linux, it's `panoptikon-relay`.
3.  **First Run:** On its first launch, Panoptikon Relay will automatically create:

    - A configuration directory.
    - A default `config.toml` file inside this directory.
    - A `token.txt` file containing the generated API key, also in this directory.
    - A log file `panoptikon-relay.log`.

    The configuration directory is typically located at:

    - **Windows:** `C:\Users\<YourUser>\AppData\Roaming\panoptikon-relay\`
    - **Linux:** `~/.config/panoptikon-relay/`
    - **macOS:** `~/Library/Application Support/panoptikon-relay/`

## Configuration

Panoptikon Relay can be configured via a `config.toml` file, environment variables, and command-line arguments.

### 1. `config.toml`

This is the primary configuration file, located in the configuration directory mentioned above. You can open it directly using the tray icon menu.

A default configuration file will be generated when you first run the app, and then opened for editing in your default application.

Here's an example structure with explanations:

```toml
# Default configuration generated on first run.
# Edit this file to match your setup.

[commands]
# Customize commands to open files or reveal them in the file manager.
# Placeholders:
#   {path}     - Full path to the file on the client.
#   {folder}   - Parent folder of the file on the client.
#   {filename} - Name of the file.
# Leave empty to use platform-specific defaults.
# Example for Windows to open .txt files in Notepad:
# open_file  = "notepad.exe {path}"
open_file  = "" # Uses default: e.g., 'start "" "{path}"' on Windows
show_in_fm = "" # Uses default: e.g., 'explorer /select,{path}' on Windows

[network]
# Network configuration for the Relay's HTTP server.
# IP address to bind to.
# Default: "127.0.0.1" (only accessible from the local machine).
# Set to "0.0.0.0" to allow access from other machines on your network
# (ensure your firewall is configured appropriately if you do this).
bind_address = "127.0.0.1"

# Port to listen on.
# Default: 17600
port = 17600

[mappings]
# Map *server* path prefixes (as Panoptikon sees them) to *client* path prefixes
# (how they are accessible on the machine running Panoptikon Relay).
# The relay will use the longest matching prefix.
#
# Examples:
#
# If Panoptikon runs on a Linux server and sees files at /srv/media,
# and these are mounted on your Windows client as Z:\media:
# "/srv/media" = 'Z:\media'
#
# If Panoptikon runs in Docker and sees files at /data/videos,
# and these are accessible on your macOS client at /Volumes/MyNAS/videos:
# "/data/videos" = '/Volumes/MyNAS/videos'
#
# If Panoptikon is on a NAS and paths are like //nas/share/raw,
# and on your Windows client they are X:\raw:
# "//nas/share/raw" = 'X:\raw'

# Add your mappings here:
# "/path/on/server" = "C:\path\on\client"
# "/another/server/path" = "/another/client/path"
```

### 2. API Key (Token)

- **Location:** The API key is stored in `token.txt` within the configuration directory.
- **Access:** You can easily copy the API key to your clipboard using the "Copy API Key" option in the tray icon menu.
- **Environment Variable:** Alternatively, you can set the `API_KEY_SECRET` environment variable to specify the token. This takes precedence over `token.txt`.

### 3. Command-Line Arguments

You can modify some settings at launch:

- `--port <PORT>`: Specifies the TCP port to listen on (e.g., `--port 17601`). Overrides `config.toml` and environment variable.
- `--bind-address <IP_ADDRESS>`: Specifies the IP address to bind to (e.g., `--bind-address 0.0.0.0`). Overrides `config.toml` and environment variable.
- `--no-token`: Disables API key authentication. **EXTREMELY DANGEROUS.**

Example: `panoptikon-relay.exe --port 12345 --bind-address 0.0.0.0`

### 4. Environment Variables

These provide another way to override settings:

- `API_KEY_SECRET`: Sets the API key. Takes precedence over `token.txt`.
- `PORT`: Sets the listening port. Takes precedence over `config.toml`.
- `BIND_ADDRESS`: Sets the bind IP address. Takes precedence over `config.toml`.
- `OPEN_FILE_COMMAND`: Overrides the `open_file` command from `config.toml`.
- `SHOW_IN_FM_COMMAND`: Overrides the `show_in_fm` command from `config.toml`.

### Configuration Priority

For network settings (`port`, `bind_address`):

1.  Command-Line Argument
2.  Environment Variable
3.  `config.toml`
4.  Application Default

For commands (`open_file`, `show_in_fm`):

1.  Environment Variable
2.  `config.toml`
3.  Application Default (platform-specific)

For API Key:

1.  `API_KEY_SECRET` Environment Variable
2.  `token.txt` file (generated if neither is present)

## Usage with Panoptikon

1.  **Start Panoptikon Relay:** Ensure Panoptikon Relay is running on your client machine.
2.  **Copy API Key:** Use the tray icon menu to copy the API key.
3.  **Configure Panoptikon:**

    - Open your Panoptikon web UI.
    - Navigate to the settings area for file opening/relay. This is typically found under a "File Details" tab or similar, with a section like "File Open Relay".
    - **Enable** the relay functionality.
    - **Enter the Panoptikon Relay Address:** This will be `http://<bind_address>:<port>`.

      - If Relay is on the same machine as your browser accessing Panoptikon, and using default settings, this is `http://127.0.0.1:17600`.

    - **Paste the API Key** into the appropriate field in Panoptikon's settings.
    - Save the settings in Panoptikon.

4.  **Verify Path Mappings:** Crucially, ensure your `[mappings]` section in Panoptikon Relay's `config.toml` correctly translates paths from Panoptikon's perspective to your client machine's file system. If paths are not translated correctly, the Relay won't be able to find the files.
5.  **Test:** Try clicking an "Open File" or "Show in Folder" button in Panoptikon. The action should now be performed on your client machine by Panoptikon Relay.

## Building from Source

If you wish to build Panoptikon Relay from source:

1.  **Prerequisites:**
    - Install the Rust toolchain (Rustup): [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
    - Git
2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/panoptikon-relay.git # Replace with actual repo URL
    cd panoptikon-relay
    ```
3.  **Build:**
    - For a release build (optimized):
      ```bash
      cargo build --release
      ```
    - The executable will be located in `target/release/panoptikon-relay` (or `panoptikon-relay.exe` on Windows).
    - For a debug build:
      ```bash
      cargo build
      ```
    - The executable will be in `target/debug/`.

## Troubleshooting

- **Check Logs:** The primary source of information for issues is the `panoptikon-relay.log` file located in the configuration directory. You can access this directory via the tray icon menu ("Show Config Folder").
- **Path Mappings:** Incorrect path mappings are a common issue. Double-check that the server paths in `[mappings]` exactly match how Panoptikon sees them, and client paths are correct for your local machine. Remember that the longest prefix match is used.
- **API Key:** Ensure the API key configured in Panoptikon matches the one in Relay's `token.txt` or `API_KEY_SECRET` environment variable.
- **Command Issues:** If files aren't opening correctly, test your custom commands (if any) directly in your terminal to ensure they work as expected with the `{path}`, `{folder}`, and `{filename}` placeholders manually substituted.

---

_Panoptikon Relay is an independent project and is not officially affiliated with the Panoptikon project, though it is designed to complement it._
