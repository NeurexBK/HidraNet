// SevenNine.hidra — Decentralized Website Builder for HidraNet
//
// Allows users to create, upload, and publish `.hidra` websites
// that are served via hidden services and discoverable via DHT.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use blake3;
use base64::Engine as _;
use chrono::Utc;
use crate::safelog::sensitive;

#[derive(Debug, Clone)]
pub struct DhtAnnouncement {
    pub service_hash: [u8; 20],
    pub service_pubkey: [u8; 32],
}

// ─── Limits ──────────────────────────────────────────────────────────────────

/// Largest single file a site may hold. The builder's page promises this
/// figure, and the server used to read only 512 KB of any request and save
/// whatever arrived, so a larger upload was reported as done and stored
/// truncated.
const MAX_FILE_BYTES: usize = 5 * 1024 * 1024;

/// Largest publish of a whole site (every generated page together).
const MAX_SITE_BYTES: usize = 5_000_000;

/// Largest request body the server reads: one file or one publish, plus the
/// multipart framing around it. Anything bigger is refused with 413 before it
/// is read, instead of being cut short in silence.
const MAX_BODY_BYTES: usize = MAX_FILE_BYTES + 64 * 1024;

/// Headers larger than this are not a browser's.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// How long a client gets to send its whole request. Without a limit, each
/// half-open connection held its buffer forever, which matters once the
/// builder is reachable over the network as a hidden service.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a site may be made of. Everything a page can show or link, and
/// nothing that only makes sense as a download of a program.
const ALLOWED_EXTENSIONS: &[&str] = &[
    "html", "htm", "css", "js", "json", "txt", "xml", "md",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
    "woff", "woff2", "ttf",
    "pdf", "mp4", "webm", "mp3", "wav",
];

// ─── Data Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub name: String,
    pub hidra_address: String,
    pub public_key: String,
    pub created_at: String,
    pub files: Vec<String>,
    pub size_bytes: u64,
    pub visits: u64,
    /// The address derived from the site's own key: forty hex characters and
    /// `.hidra`. It used to be written to the log and nowhere else. Older
    /// metadata files have no such field, so it is recomputed from the key
    /// when a site is loaded.
    #[serde(default)]
    pub crypto_address: String,
    /// Where other people reach the site, when this node is published as a
    /// hidden service: `http://<node address>.hidra/sites/<name>/`. Filled in
    /// when a site is reported, never stored, and absent in local-only mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SiteRecord {
    info: SiteInfo,
    #[serde(skip)]
    #[allow(dead_code)]
    signing_key_bytes: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateSiteRequest {
    name: String,
    /// A site is created only by someone who has accepted the Terms of Use
    /// served at `/terms`. The builder's page sends this once the box is
    /// ticked; a client that skips the page has to say so explicitly too.
    #[serde(default)]
    accept_terms: bool,
}

/// What `/api/status` reports: whether this builder is published on the
/// network, and at which address.
#[derive(Debug, Serialize)]
struct StatusResponse {
    ok: bool,
    network: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SavePageRequest {
    html: String,
    source: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct PageFile {
    path: String,
    html: String,
}

#[derive(Debug, Deserialize)]
struct PublishRequest {
    source: serde_json::Value,
    files: Vec<PageFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<SiteInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sites: Option<Vec<SiteInfo>>,
}

// ─── Site Manager ────────────────────────────────────────────────────────────

pub struct SiteManager {
    sites: Arc<RwLock<HashMap<String, SiteRecord>>>,
    base_dir: PathBuf,
    dht_tx: Option<tokio::sync::mpsc::Sender<DhtAnnouncement>>,
    port: u16,
    /// This node's own hidden-service address (`<hash>.hidra`), when the
    /// builder is published on the network. Every site is reachable under it.
    network_address: Option<String>,
}

/// The one rule for a site's name, applied to every operation and not only
/// to creation. A name that reached the file system unchecked could be `..`:
/// `DELETE /api/sites/..` removed the whole data directory, keys included,
/// and `/sites/../<file>` read any file next to it.
pub fn normalize_site_name(name: &str) -> Result<String, String> {
    let name = name.trim().to_lowercase();
    if name.is_empty() || name.len() > 32 {
        return Err("Name must be between 1 and 32 characters".into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Name may contain only letters, numbers, - and _".into());
    }
    Ok(name)
}

/// The label of a `.hidra` host, or None for any other host.
fn hidra_host_label(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    let host = host.split(':').next().unwrap_or(host);
    let label = host.strip_suffix(".hidra")?;
    if label.is_empty() {
        return None;
    }
    Some(label.to_lowercase())
}

/// `<hash>.hidra` for a site's signing key: blake3 of the public key, first
/// twenty bytes, in hex. The same derivation the hidden-service resolver uses.
fn crypto_address_for(signing_key_bytes: &[u8; 32]) -> (String, [u8; 20], [u8; 32]) {
    let sk = SigningKey::from_bytes(signing_key_bytes);
    let vk: VerifyingKey = (&sk).into();
    let pub_bytes = vk.to_bytes();
    let full_hash = blake3::hash(&pub_bytes);
    let mut address_hash = [0u8; 20];
    address_hash.copy_from_slice(&full_hash.as_bytes()[..20]);
    let hex: String = address_hash.iter().map(|b| format!("{b:02x}")).collect();
    (format!("{hex}.hidra"), address_hash, pub_bytes)
}

impl SiteManager {
    pub fn new(base_dir: &Path, port: u16) -> Self {
        Self::_init(base_dir, None, port)
    }

    pub fn new_with_dht(
        base_dir: &Path,
        dht_tx: tokio::sync::mpsc::Sender<DhtAnnouncement>,
        port: u16,
    ) -> Self {
        Self::_init(base_dir, Some(dht_tx), port)
    }

    /// Record the hidden-service address this builder is published under,
    /// so each site can report where other people reach it.
    pub fn with_network_address(mut self, address: &str) -> Self {
        let address = address.trim().to_lowercase();
        if !address.is_empty() {
            self.network_address = Some(address);
        }
        self
    }

    fn _init(
        base_dir: &Path,
        dht_tx: Option<tokio::sync::mpsc::Sender<DhtAnnouncement>>,
        port: u16,
    ) -> Self {
        let sites_dir = base_dir.join("sites");
        std::fs::create_dir_all(&sites_dir).ok();

        // Load existing sites from disk (including signing keys). This is
        // done here, before the manager is handed out, not in a spawned
        // task: a site created in the first instants used to be overwritten
        // in memory when that task finally ran.
        let mut sites_map = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&sites_dir) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                // A folder that is not a valid site name is not a site.
                if normalize_site_name(&name).ok().as_deref() != Some(name.as_str()) {
                    continue;
                }
                let site_path = entry.path();
                let meta_path = site_path.join(".sevennine-meta.json");
                let Ok(data) = std::fs::read_to_string(&meta_path) else { continue };
                let Ok(mut info) = serde_json::from_str::<SiteInfo>(&data) else { continue };
                let key_bytes = load_site_key(&site_path);
                if info.crypto_address.is_empty() && key_bytes != [0u8; 32] {
                    info.crypto_address = crypto_address_for(&key_bytes).0;
                }
                info.network_address = None;
                sites_map.insert(name, SiteRecord { info, signing_key_bytes: key_bytes });
            }
        }
        if !sites_map.is_empty() {
            tracing::info!("loaded {} existing sites", sites_map.len());
        }

        Self {
            sites: Arc::new(RwLock::new(sites_map)),
            base_dir: base_dir.to_path_buf(),
            dht_tx,
            port,
            network_address: None,
        }
    }

    /// Where this builder is published, if it is.
    pub fn network_address(&self) -> Option<&str> {
        self.network_address.as_deref()
    }

    /// A site as reported to a client: with the address other people use
    /// to reach it, when there is one.
    fn reported(&self, mut info: SiteInfo) -> SiteInfo {
        info.network_address = self
            .network_address
            .as_ref()
            .map(|node| format!("http://{node}/sites/{}/", info.name));
        info
    }

    /// The site a `.hidra` host label names, when it is one of this node's
    /// sites' own addresses. The node's own address names no single site.
    pub async fn site_for_label(&self, label: &str) -> Option<String> {
        let wanted = format!("{}.hidra", label.to_lowercase());
        let sites = self.sites.read().await;
        sites
            .values()
            .find(|r| r.info.crypto_address == wanted)
            .map(|r| r.info.name.clone())
    }

    pub async fn announce_all_sites(&self) {
        let tx = match self.dht_tx.as_ref() {
            Some(tx) => tx,
            None => return,
        };
        let sites = self.sites.read().await;
        let mut count = 0u32;
        for record in sites.values() {
            if record.signing_key_bytes == [0u8; 32] { continue; }
            let (_, address_hash, pub_bytes) = crypto_address_for(&record.signing_key_bytes);

            let announcement = DhtAnnouncement {
                service_hash: address_hash,
                service_pubkey: pub_bytes,
            };
            if tx.try_send(announcement).is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(count, "re-announced existing sites to DHT");
        }
    }

    pub fn has_site_sync(&self, name: &str) -> bool {
        let Ok(name) = normalize_site_name(name) else { return false };
        let site_dir = self.base_dir.join("sites").join(&name);
        site_dir.exists() && site_dir.join(".sevennine-meta.json").exists()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// The folder of an existing site, or the reason there is none. Every
    /// operation on a site goes through here, so no unchecked name reaches
    /// the file system.
    fn existing_site_dir(&self, site_name: &str) -> Result<(String, PathBuf), String> {
        let site_name = normalize_site_name(site_name)?;
        let site_dir = self.base_dir.join("sites").join(&site_name);
        if !site_dir.join(".sevennine-meta.json").exists() {
            return Err(format!("Site '{}' does not exist", site_name));
        }
        Ok((site_name, site_dir))
    }

    /// Re-read a site's folder and store what it holds in the metadata.
    async fn refresh_site(&self, site_name: &str, site_dir: &Path) -> Result<SiteInfo, String> {
        let mut total_size: u64 = 0;
        let mut file_list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(site_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with('.') { continue; }
                file_list.push(fname);
                total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        file_list.sort();

        let mut sites = self.sites.write().await;
        if let Some(record) = sites.get_mut(site_name) {
            record.info.files = file_list;
            record.info.size_bytes = total_size;
            let meta_json = serde_json::to_string_pretty(&record.info).unwrap_or_default();
            std::fs::write(site_dir.join(".sevennine-meta.json"), meta_json.as_bytes()).ok();
            return Ok(self.reported(record.info.clone()));
        }
        Err("Site not found".into())
    }

    pub async fn create_site(&self, name: &str) -> Result<SiteInfo, String> {
        let name = normalize_site_name(name)?;

        {
            let sites = self.sites.read().await;
            if sites.contains_key(&name) {
                return Err(format!("The name '{}' is already taken", name));
            }
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let (crypto_address, address_hash, pub_bytes) =
            crypto_address_for(&signing_key.to_bytes());

        // Human-friendly name maps to the cryptographic address
        let hidra_address = format!("{}.hidra", name);
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);

        let site_dir = self.base_dir.join("sites").join(&name);
        std::fs::create_dir_all(&site_dir).map_err(|e| format!("Could not create folder: {}", e))?;

        let default_html = generate_default_page(&name);
        std::fs::write(site_dir.join("index.html"), default_html.as_bytes())
            .map_err(|e| format!("Could not save index.html: {}", e))?;

        let info = SiteInfo {
            name: name.clone(),
            hidra_address: hidra_address.clone(),
            public_key: public_key_b64,
            created_at: Utc::now().to_rfc3339(),
            files: vec!["index.html".into()],
            size_bytes: default_html.len() as u64,
            visits: 0,
            crypto_address: crypto_address.clone(),
            network_address: None,
        };

        let meta_json = serde_json::to_string_pretty(&info).unwrap_or_default();
        std::fs::write(site_dir.join(".sevennine-meta.json"), meta_json.as_bytes()).ok();

        // Save signing key for future updates/verification
        let key_path = site_dir.join(".site-key.secret");
        std::fs::write(
            &key_path,
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes()),
        ).ok();

        let record = SiteRecord {
            info: info.clone(),
            signing_key_bytes: signing_key.to_bytes(),
        };

        {
            let mut sites = self.sites.write().await;
            sites.insert(name.clone(), record);
        }

        // Publish to DHT if available
        if let Some(ref tx) = self.dht_tx {
            let announcement = DhtAnnouncement {
                service_hash: address_hash,
                service_pubkey: pub_bytes,
            };
            if tx.try_send(announcement).is_ok() {
                tracing::info!(
                    site = %sensitive(&name),
                    address = %sensitive(&crypto_address),
                    "site published to DHT"
                );
            }
        }

        // The name and both addresses are the owner's, on the owner's own
        // machine; they are still scrubbed, like every other name in the log.
        tracing::info!(
            site = %sensitive(&name),
            address = %sensitive(&crypto_address),
            "site created"
        );
        Ok(self.reported(info))
    }

    pub async fn upload_file(&self, site_name: &str, filename: &str, content: &[u8]) -> Result<SiteInfo, String> {
        let (site_name, site_dir) = self.existing_site_dir(site_name)?;

        let safe_name = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid file name")?
            .to_string();

        if safe_name.starts_with('.') {
            return Err("Hidden files are not allowed".into());
        }
        if !is_allowed_file(&safe_name) {
            return Err(format!(
                "File type not allowed. Allowed: {}",
                ALLOWED_EXTENSIONS.join(", ")
            ));
        }
        if content.len() > MAX_FILE_BYTES {
            return Err("File too large (max 5 MB)".into());
        }

        std::fs::write(site_dir.join(&safe_name), content)
            .map_err(|e| format!("Could not save file: {}", e))?;

        self.refresh_site(&site_name, &site_dir).await
    }

    pub async fn delete_site(&self, name: &str) -> Result<(), String> {
        let (name, site_dir) = self.existing_site_dir(name)?;

        {
            let mut sites = self.sites.write().await;
            sites.remove(&name);
        }

        std::fs::remove_dir_all(&site_dir).map_err(|e| format!("Could not remove: {}", e))?;

        tracing::info!(site = %sensitive(&name), "site deleted");
        Ok(())
    }

    pub async fn list_sites(&self) -> Vec<SiteInfo> {
        let sites = self.sites.read().await;
        sites.values().map(|r| self.reported(r.info.clone())).collect()
    }

    #[allow(dead_code)]
    pub async fn get_site(&self, name: &str) -> Option<SiteInfo> {
        let name = normalize_site_name(name).ok()?;
        let sites = self.sites.read().await;
        sites.get(&name).map(|r| self.reported(r.info.clone()))
    }

    pub async fn save_page(
        &self,
        site_name: &str,
        html: &str,
        source: &serde_json::Value,
    ) -> Result<SiteInfo, String> {
        let (site_name, site_dir) = self.existing_site_dir(site_name)?;
        if html.len() > 2_000_000 {
            return Err("Page too large (max 2 MB)".into());
        }

        std::fs::write(site_dir.join("index.html"), html.as_bytes())
            .map_err(|e| format!("Could not save page: {}", e))?;

        // Persist the editable source so the page can be re-opened in the editor
        let src = serde_json::to_string(source).unwrap_or_default();
        std::fs::write(site_dir.join(".sevennine-page.json"), src.as_bytes()).ok();

        self.refresh_site(&site_name, &site_dir).await
    }

    pub async fn publish_site(
        &self,
        site_name: &str,
        source: &serde_json::Value,
        files: &[(String, String)],
    ) -> Result<SiteInfo, String> {
        let (site_name, site_dir) = self.existing_site_dir(site_name)?;

        let total: usize = files.iter().map(|(_, h)| h.len()).sum();
        if total > MAX_SITE_BYTES {
            return Err("Site too large (max 5 MB in total)".into());
        }
        if files.is_empty() {
            return Err("No page to publish".into());
        }

        // Remove old generated .html pages so renamed/deleted pages don't linger
        if let Ok(entries) = std::fs::read_dir(&site_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.ends_with(".html") {
                    std::fs::remove_file(entry.path()).ok();
                }
            }
        }

        let mut written = 0u32;
        for (path, html) in files {
            let safe = match Path::new(path).file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if safe.starts_with('.') || !safe.ends_with(".html") {
                continue;
            }
            std::fs::write(site_dir.join(&safe), html.as_bytes())
                .map_err(|e| format!("Could not save {}: {}", safe, e))?;
            written += 1;
        }
        if written == 0 {
            return Err("No valid page (.html)".into());
        }

        let src = serde_json::to_string(source).unwrap_or_default();
        std::fs::write(site_dir.join(".sevennine-page.json"), src.as_bytes()).ok();

        self.refresh_site(&site_name, &site_dir).await
    }

    pub fn load_page(&self, name: &str) -> Option<String> {
        let name = normalize_site_name(name).ok()?;
        let p = self.base_dir.join("sites").join(&name).join(".sevennine-page.json");
        std::fs::read_to_string(p).ok()
    }

    pub async fn serve_file(&self, site_name: &str, file_path: &str) -> Option<(Vec<u8>, String)> {
        let site_name = normalize_site_name(site_name).ok()?;
        let file_path = if file_path.is_empty() || file_path == "/" { "index.html" } else { file_path };
        let safe_path = Path::new(file_path).file_name()?.to_str()?;

        if safe_path.starts_with('.') { return None; }

        let full_path = self.base_dir.join("sites").join(&site_name).join(safe_path);
        let content = std::fs::read(&full_path).ok()?;
        let mime = guess_mime(safe_path);

        {
            let mut sites = self.sites.write().await;
            if let Some(record) = sites.get_mut(&site_name) {
                record.info.visits += 1;
            }
        }

        Some((content, mime))
    }
}

/// Whether a file name ends in one of the extensions a site may hold.
fn is_allowed_file(filename: &str) -> bool {
    let ext = match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_lowercase(),
        _ => return false,
    };
    ALLOWED_EXTENSIONS.contains(&ext.as_str())
}

fn load_site_key(site_dir: &Path) -> [u8; 32] {
    let key_path = site_dir.join(".site-key.secret");
    if let Ok(b64) = std::fs::read_to_string(&key_path) {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return arr;
            }
        }
    }
    [0u8; 32]
}

fn guess_mime(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }.to_string()
}

fn generate_default_page(site_name: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{name}.hidra</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #0d1526 50%, #0a0e17 100%);
      color: #e0e0e8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .container {{
      text-align: center;
      padding: 48px;
      background: rgba(16, 16, 28, 0.8);
      border: 1px solid rgba(0, 212, 170, 0.2);
      border-radius: 16px;
      max-width: 600px;
    }}
    h1 {{
      font-size: 2.5em;
      background: linear-gradient(135deg, #00d4aa, #00a888);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 16px;
    }}
    p {{ color: #8888a0; font-size: 1.1em; line-height: 1.6; }}
    .badge {{
      display: inline-block;
      margin-top: 24px;
      padding: 8px 20px;
      background: rgba(0, 212, 170, 0.1);
      border: 1px solid rgba(0, 212, 170, 0.3);
      border-radius: 20px;
      color: #00d4aa;
      font-size: 0.85em;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{name}.hidra</h1>
    <p>This site was built with <strong>SevenNine.hidra</strong><br>
    and is hosted on the decentralised <strong>HidraNet</strong> network.</p>
    <div class="badge">Powered by HidraNet</div>
  </div>
</body>
</html>"#, name = site_name)
}

// ─── HTTP Server ─────────────────────────────────────────────────────────────

pub async fn run_sevennine(
    listen_addr: &str,
    port: u16,
    data_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = Arc::new(SiteManager::new(data_dir, port));
    let listener = TcpListener::bind(format!("{}:{}", listen_addr, port)).await?;

    tracing::info!("SevenNine.hidra running on http://{}:{}", listen_addr, port);

    loop {
        let (stream, _addr) = listener.accept().await?;
        let mgr = manager.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, mgr).await {
                tracing::debug!("connection error: {}", e);
            }
        });
    }
}

pub async fn handle_connection_pub(
    stream: tokio::net::TcpStream,
    manager: Arc<SiteManager>,
) {
    if let Err(e) = handle_connection(stream, manager).await {
        tracing::debug!("connection error: {}", e);
    }
}

/// What came in on a connection, once read up to its declared length.
enum Incoming {
    Request(Vec<u8>),
    /// The headers declared more than the server reads; nothing was stored.
    TooLarge,
    /// The client sent nothing, or hung up before the headers ended.
    Nothing,
}

/// Value of `Content-Length` in a request head, or 0 when there is none.
fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// First value of a header, case-insensitively, from a raw request.
fn header_value(request: &str, name: &str) -> Option<String> {
    request
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
        })
}

/// Read one request: the headers, then exactly the body they announce. The
/// buffer grows with what arrives instead of being a fixed 512 KB, which
/// used to cut every larger upload short and save the stump as the file.
async fn read_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Incoming> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    let mut needed: Option<usize> = None;

    loop {
        if let Some(n) = needed {
            if buf.len() >= n {
                break;
            }
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if needed.is_none() {
            if let Some(hdr_end) = find_bytes(&buf, b"\r\n\r\n") {
                let body_len = content_length(&buf[..hdr_end]);
                if body_len > MAX_BODY_BYTES {
                    return Ok(Incoming::TooLarge);
                }
                needed = Some(hdr_end + 4 + body_len);
            } else if buf.len() > MAX_HEADER_BYTES {
                return Ok(Incoming::TooLarge);
            }
        }
    }

    match needed {
        Some(n) if buf.len() >= n => {
            buf.truncate(n);
            Ok(Incoming::Request(buf))
        }
        _ => Ok(Incoming::Nothing),
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    manager: Arc<SiteManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let raw = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(Incoming::Request(raw))) => raw,
        Ok(Ok(Incoming::TooLarge)) => {
            send_response(&mut stream, 413, "text/plain", b"Request too large (max 5 MB)", None).await;
            return Ok(());
        }
        Ok(Ok(Incoming::Nothing)) => return Ok(()),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // timed out waiting for the request
    };

    let request = String::from_utf8_lossy(&raw).into_owned();

    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request", None).await;
        return Ok(());
    }

    let method = parts[0];
    let raw_path = parts[1];
    let path = urldecode(raw_path);

    // A visitor who reached this builder over the network, through the
    // hidden service, sends `Host: <hash>.hidra`. The loopback screening
    // below refused that outright, so no published site ever opened. Such a
    // request may read a site and nothing else: creating, uploading and
    // deleting stay with the owner on this machine.
    if let Some(label) = header_value(&request, "host").and_then(|h| hidra_host_label(&h)) {
        handle_public(&mut stream, &manager, &label, method, &path).await;
        return Ok(());
    }

    // Every reply used to carry `Access-Control-Allow-Origin: *`, which let a
    // page on any site read this builder's site list and post to its API. The
    // publish UI does reach it from another local port, so the allowed origin
    // is echoed by name instead of wildcarded.
    let allowed_origin = match crate::local_guard::screen(&request) {
        crate::local_guard::Access::Allow(origin) => origin,
        crate::local_guard::Access::Deny => {
            send_response(
                &mut stream,
                crate::local_guard::DENIED_STATUS.0,
                "application/json",
                crate::local_guard::DENIED_BODY.as_bytes(),
                None,
            )
            .await;
            return Ok(());
        }
    };
    let allowed_origin = allowed_origin.as_deref();

    match (method, path.as_str()) {
        // ── API routes ──
        ("POST", "/api/sites") => {
            let body = extract_body(&request);
            match serde_json::from_str::<CreateSiteRequest>(&body) {
                Ok(req) if !req.accept_terms => {
                    let resp = ApiResponse {
                        ok: false,
                        msg: Some("You must accept the Terms of Use before creating a site".into()),
                        site: None,
                        sites: None,
                    };
                    send_json(&mut stream, 400, &resp, allowed_origin).await;
                }
                Ok(req) => {
                    match manager.create_site(&req.name).await {
                        Ok(site) => {
                            let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                            send_json(&mut stream, 201, &resp, allowed_origin).await;
                        }
                        Err(e) => {
                            let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                            send_json(&mut stream, 400, &resp, allowed_origin).await;
                        }
                    }
                }
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("Invalid JSON. Use: {\"name\": \"mysite\", \"accept_terms\": true}".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp, allowed_origin).await;
                }
            }
        }

        ("GET", "/api/sites") => {
            let sites = manager.list_sites().await;
            let resp = ApiResponse { ok: true, msg: None, site: None, sites: Some(sites) };
            send_json(&mut stream, 200, &resp, allowed_origin).await;
        }

        ("GET", "/api/status") => {
            let address = manager.network_address().map(|a| a.to_string());
            let status = StatusResponse { ok: true, network: address.is_some(), network_address: address };
            let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".into());
            send_response(&mut stream, 200, "application/json; charset=utf-8", body.as_bytes(), allowed_origin).await;
        }

        // ── Visual page editor (save/load page source) ──
        ("POST", p) if p.starts_with("/api/page/") => {
            let site_name = &p[10..];
            let body = extract_body(&request);
            match serde_json::from_str::<SavePageRequest>(&body) {
                Ok(req) => match manager.save_page(site_name, &req.html, &req.source).await {
                    Ok(site) => {
                        let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                        send_json(&mut stream, 200, &resp, allowed_origin).await;
                    }
                    Err(e) => {
                        let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                        send_json(&mut stream, 400, &resp, allowed_origin).await;
                    }
                },
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("Invalid JSON".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp, allowed_origin).await;
                }
            }
        }

        ("GET", p) if p.starts_with("/api/page/") => {
            let site_name = &p[10..];
            match manager.load_page(site_name) {
                Some(src) => send_response(&mut stream, 200, "application/json; charset=utf-8", src.as_bytes(), allowed_origin).await,
                None => send_response(&mut stream, 200, "application/json; charset=utf-8", b"null", allowed_origin).await,
            }
        }

        // ── Publish a full multi-page site at once ──
        ("POST", p) if p.starts_with("/api/publish/") => {
            let site_name = &p[13..];
            let body = extract_body(&request);
            match serde_json::from_str::<PublishRequest>(&body) {
                Ok(req) => {
                    let files: Vec<(String, String)> =
                        req.files.into_iter().map(|f| (f.path, f.html)).collect();
                    match manager.publish_site(site_name, &req.source, &files).await {
                        Ok(site) => {
                            let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                            send_json(&mut stream, 200, &resp, allowed_origin).await;
                        }
                        Err(e) => {
                            let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                            send_json(&mut stream, 400, &resp, allowed_origin).await;
                        }
                    }
                }
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("Invalid JSON".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp, allowed_origin).await;
                }
            }
        }

        ("GET", p) if p.starts_with("/api/resolve") => {
            let query = p.split('?').nth(1).unwrap_or("");
            let name = query.split('&')
                .find(|s| s.starts_with("name="))
                .map(|s| urldecode(&s[5..]))
                .unwrap_or_default()
                .to_lowercase();
            let name = name.replace(".hidra", "");
            if manager.has_site_sync(&name) {
                let port = manager.get_port();
                let json = format!(
                    r#"{{"found":true,"address":"127.0.0.1:{port}","path":"/sites/{name}/"}}"#,
                    port = port,
                    name = name
                );
                send_response(&mut stream, 200, "application/json; charset=utf-8", json.as_bytes(), allowed_origin).await;
            } else {
                send_response(&mut stream, 404, "application/json; charset=utf-8", br#"{"found":false}"#, allowed_origin).await;
            }
        }

        ("OPTIONS", _) => {
            send_response(&mut stream, 204, "text/plain", b"", allowed_origin).await;
        }

        ("DELETE", p) if p.starts_with("/api/sites/") => {
            let site_name = &p[11..];
            match manager.delete_site(site_name).await {
                Ok(()) => {
                    let resp = ApiResponse { ok: true, msg: Some("Site removed".into()), site: None, sites: None };
                    send_json(&mut stream, 200, &resp, allowed_origin).await;
                }
                Err(e) => {
                    let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                    send_json(&mut stream, 400, &resp, allowed_origin).await;
                }
            }
        }

        ("POST", p) if p.starts_with("/api/upload/") => {
            let site_name = &p[12..];
            let (filename, file_data) = extract_multipart(&request, &raw);
            if let (Some(fname), Some(data)) = (filename, file_data) {
                match manager.upload_file(site_name, &fname, &data).await {
                    Ok(site) => {
                        let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                        send_json(&mut stream, 200, &resp, allowed_origin).await;
                    }
                    Err(e) => {
                        let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                        send_json(&mut stream, 400, &resp, allowed_origin).await;
                    }
                }
            } else {
                let resp = ApiResponse { ok: false, msg: Some("Invalid upload".into()), site: None, sites: None };
                send_json(&mut stream, 400, &resp, allowed_origin).await;
            }
        }

        // ── Site preview ──
        ("GET", p) if p.starts_with("/sites/") => {
            serve_site_path(&mut stream, &manager, &p[7..], allowed_origin).await;
        }

        // ── Frontend ──
        ("GET", "/") | ("GET", "/index.html") => {
            send_response(&mut stream, 200, "text/html; charset=utf-8", FRONTEND_HTML.as_bytes(), allowed_origin).await;
        }

        ("GET", "/terms") | ("GET", "/terms.html") => {
            send_response(&mut stream, 200, "text/html; charset=utf-8", TERMS_HTML.as_bytes(), allowed_origin).await;
        }

        ("GET", "/style.css") => {
            send_response(&mut stream, 200, "text/css; charset=utf-8", FRONTEND_CSS.as_bytes(), allowed_origin).await;
        }

        ("GET", "/app.js") => {
            send_response(&mut stream, 200, "application/javascript; charset=utf-8", FRONTEND_JS.as_bytes(), allowed_origin).await;
        }

        ("GET", "/favicon.ico") => {
            send_response(&mut stream, 204, "image/x-icon", b"", allowed_origin).await;
        }

        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found", allowed_origin).await;
        }
    }

    Ok(())
}

/// Serve `<site>/<file>` from what follows `/sites/`.
async fn serve_site_path(
    stream: &mut tokio::net::TcpStream,
    manager: &SiteManager,
    rest: &str,
    allowed_origin: Option<&str>,
) {
    let (site_name, file_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, "index.html"),
    };
    match manager.serve_file(site_name, file_path).await {
        Some((content, mime)) => {
            send_site_file(stream, &mime, &content, allowed_origin).await;
        }
        None => {
            send_response(stream, 404, "text/plain", b"File not found", allowed_origin).await;
        }
    }
}

/// A request that arrived through the hidden service, addressed to
/// `<label>.hidra`. Read-only: the builder's pages and its API are not
/// served here, whatever the path.
///
/// Under this node's own address every site is at `/sites/<name>/`, and `/`
/// lists them. When the label is a site's own address (the one derived from
/// its key), the site is the root: `/` is its home page and `/<file>` one of
/// its files, so links inside the site work either way.
async fn handle_public(
    stream: &mut tokio::net::TcpStream,
    manager: &SiteManager,
    label: &str,
    method: &str,
    path: &str,
) {
    if method != "GET" && method != "HEAD" {
        send_response(stream, 403, "text/plain", b"Read-only: this site is managed from its owner's machine", None).await;
        return;
    }
    let path = path.split('?').next().unwrap_or("");

    if let Some(rest) = path.strip_prefix("/sites/") {
        serve_site_path(stream, manager, rest, None).await;
        return;
    }

    if let Some(site) = manager.site_for_label(label).await {
        let file = path.trim_start_matches('/');
        match manager.serve_file(&site, file).await {
            Some((content, mime)) => send_site_file(stream, &mime, &content, None).await,
            None => send_response(stream, 404, "text/plain", b"File not found", None).await,
        }
        return;
    }

    if path == "/" || path == "/index.html" {
        let sites = manager.list_sites().await;
        let body = public_index_page(&sites);
        send_response(stream, 200, "text/html; charset=utf-8", body.as_bytes(), None).await;
        return;
    }

    send_response(stream, 404, "text/plain", b"Not Found", None).await;
}

/// Escape text for an HTML page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// What a visitor sees at this node's own address: the sites it publishes.
fn public_index_page(sites: &[SiteInfo]) -> String {
    let mut names: Vec<&str> = sites.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    let items: String = if names.is_empty() {
        "<li class=\"empty\">No site is published here yet.</li>".to_string()
    } else {
        names
            .iter()
            .map(|n| {
                let n = html_escape(n);
                format!("<li><a href=\"/sites/{n}/\">{n}.hidra</a></li>")
            })
            .collect()
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sites on this HidraNet node</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0e17;color:#e0e0e8;margin:0;padding:40px 20px}}
main{{max-width:560px;margin:0 auto}}
h1{{color:#00d4aa;font-weight:600;font-size:1.4em}}
ul{{list-style:none;padding:0}}
li{{padding:10px 0;border-bottom:1px solid #1c2133}}
a{{color:#00d4aa;text-decoration:none}}
.empty{{color:#8888a0}}
p{{color:#8888a0;font-size:.9em}}
</style>
</head>
<body><main>
<h1>Sites on this HidraNet node</h1>
<ul>{items}</ul>
<p>Built with SevenNine.hidra.</p>
</main></body>
</html>"#
    )
}

fn extract_body(request: &str) -> String {
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

fn extract_multipart(request: &str, raw: &[u8]) -> (Option<String>, Option<Vec<u8>>) {
    let headers_end = if let Some(i) = find_bytes(raw, b"\r\n\r\n") { i + 4 } else { return (None, None); };

    let content_type_line = request.lines()
        .find(|l| l.to_lowercase().starts_with("content-type:"))
        .unwrap_or("");

    if content_type_line.contains("multipart/form-data") {
        if let Some(boundary_start) = content_type_line.find("boundary=") {
            let boundary = &content_type_line[boundary_start + 9..].trim_matches('"');
            let boundary_marker = format!("--{}", boundary);
            let body = &raw[headers_end..];
            return parse_multipart_body(body, &boundary_marker);
        }
    }

    // Fallback: treat as raw file with filename from query or header
    let filename = request.lines()
        .find(|l| l.to_lowercase().starts_with("x-filename:"))
        .map(|l| l[11..].trim().to_string())
        .unwrap_or_else(|| "upload.html".to_string());

    let data = raw[headers_end..].to_vec();
    if data.is_empty() { return (None, None); }
    (Some(filename), Some(data))
}

fn parse_multipart_body(body: &[u8], boundary: &str) -> (Option<String>, Option<Vec<u8>>) {
    let boundary_bytes = boundary.as_bytes();
    let parts: Vec<&[u8]> = split_bytes(body, boundary_bytes);

    for part in parts {
        if part.len() < 10 { continue; }
        let part_str = String::from_utf8_lossy(part);
        if let Some(header_end) = find_bytes(part, b"\r\n\r\n") {
            let headers = &part_str[..header_end];
            let data_start = header_end + 4;
            let mut data_end = part.len();
            if data_end > 2 && part[data_end - 2] == b'\r' && part[data_end - 1] == b'\n' {
                data_end -= 2;
            }

            if headers.contains("filename=") {
                let filename = headers.split("filename=").nth(1)
                    .and_then(|s| s.split('"').nth(1))
                    .unwrap_or("file")
                    .to_string();
                let file_data = part[data_start..data_end].to_vec();
                return (Some(filename), Some(file_data));
            }
        }
    }
    (None, None)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn split_bytes<'a>(data: &'a [u8], delimiter: &[u8]) -> Vec<&'a [u8]> {
    let mut result = Vec::new();
    let mut start = 0;
    for i in 0..data.len() {
        if data[i..].starts_with(delimiter) {
            result.push(&data[start..i]);
            start = i + delimiter.len();
        }
    }
    if start < data.len() {
        result.push(&data[start..]);
    }
    result
}

fn urldecode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next().unwrap_or(b'0');
            let l = chars.next().unwrap_or(b'0');
            let val = hex_val(h) * 16 + hex_val(l);
            result.push(val as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Policy sent with every file of a user's site.
///
/// A site's pages are written by whoever owns it, or copied from a template
/// found anywhere, and they used to be served with no policy at all, from the
/// same origin as this builder's API: a script in a page could delete sites
/// and read the builder's storage. `sandbox` without `allow-same-origin` gives
/// the page an opaque origin, so its requests carry `Origin: null` and the
/// API refuses them, while its own scripts and forms still work.
/// `connect-src 'none'` stops a page sending what it reads anywhere, and
/// nothing is loaded from outside the site.
const SITE_CSP: &str = "Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups allow-modals; \
default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data:; connect-src 'none'; \
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'\r\n";

async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    allowed_origin: Option<&str>,
) {
    send_response_with(stream, status, content_type, body, allowed_origin, "").await;
}

/// A file of a user's site, with the policy above.
async fn send_site_file(
    stream: &mut tokio::net::TcpStream,
    content_type: &str,
    body: &[u8],
    allowed_origin: Option<&str>,
) {
    send_response_with(stream, 200, content_type, body, allowed_origin, SITE_CSP).await;
}

async fn send_response_with(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    allowed_origin: Option<&str>,
    extra_headers: &str,
) {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         {}\
         {}\
         Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, X-Filename\r\n\
         Connection: close\r\n\
         \r\n",
        status,
        status_text,
        content_type,
        body.len(),
        crate::local_guard::response_headers(allowed_origin),
        extra_headers
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

async fn send_json(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    data: &ApiResponse,
    allowed_origin: Option<&str>,
) {
    let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".into());
    send_response(
        stream,
        status,
        "application/json; charset=utf-8",
        body.as_bytes(),
        allowed_origin,
    )
    .await;
}

// ─── Frontend HTML ───────────────────────────────────────────────────────────

const FRONTEND_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SevenNine.hidra — Site builder</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="app">
    <!-- Header -->
    <header class="header">
      <div class="logo">
        <svg viewBox="0 0 48 48" width="48" height="48">
          <circle cx="24" cy="24" r="22" fill="none" stroke="#00d4aa" stroke-width="2" opacity="0.3"/>
          <circle cx="24" cy="24" r="16" fill="none" stroke="#00d4aa" stroke-width="1.5" opacity="0.5"/>
          <text x="24" y="30" text-anchor="middle" fill="#00d4aa" font-size="18" font-weight="bold" font-family="monospace">79</text>
        </svg>
        <div>
          <h1>SevenNine<span class="accent">.hidra</span></h1>
          <p class="tagline">Decentralised site builder for the HidraNet network</p>
        </div>
      </div>
      <div class="header-stats" id="header-stats">
        <div class="stat"><span class="stat-value" id="total-sites">0</span><span class="stat-label">Sites</span></div>
      </div>
    </header>

    <!-- Create Section -->
    <section class="card create-card">
      <h2><span class="icon">+</span> Create a new site</h2>
      <div class="create-form">
        <div class="name-input-group">
          <input type="text" id="site-name" placeholder="mysite" maxlength="32" autocomplete="off" spellcheck="false">
          <span class="domain-suffix">.hidra</span>
        </div>
        <button class="btn btn-primary" id="create-btn" onclick="createSite()">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 5v14M5 12h14"/>
          </svg>
          Create site
        </button>
      </div>
      <label class="terms-check">
        <input type="checkbox" id="accept-terms">
        <span>I have read and accept the <a href="/terms" target="_blank">Terms of Use</a>. I am responsible for what I publish.</span>
      </label>
      <div id="net-status" class="net-status"></div>
      <div id="create-msg" class="msg hidden"></div>
    </section>

    <!-- Success Banner (shown after create/publish) -->
    <section class="card success-card hidden" id="success-section">
      <div class="success-content">
        <div class="success-icon">
          <svg viewBox="0 0 48 48" width="48" height="48" fill="none" stroke="#00d4aa" stroke-width="2.5">
            <circle cx="24" cy="24" r="20" opacity="0.3"/><path d="M14 24l7 7 13-13"/>
          </svg>
        </div>
        <h2>Site published on HidraNet</h2>
        <div class="address-box" id="address-box">
          <span class="address-text" id="address-text"></span>
          <button class="btn-copy" onclick="copyAddress()" title="Copy address">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>
        </div>
        <div class="success-actions">
          <a id="open-local-link" href="#" target="_blank" class="btn btn-primary">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            Open site
          </a>
          <button class="btn btn-ghost" onclick="hideSuccess()">Continue</button>
        </div>
      </div>
    </section>

    <!-- Upload Section (shown after site creation) -->
    <section class="card upload-card hidden" id="upload-section">
      <h2><span class="icon">&#8593;</span> Upload files to <span id="upload-site-name" class="accent"></span></h2>
      <div class="upload-zone" id="drop-zone">
        <svg viewBox="0 0 64 64" width="48" height="48" fill="none" stroke="#00d4aa" stroke-width="2" opacity="0.5">
          <rect x="8" y="16" width="48" height="40" rx="4"/>
          <polyline points="24,36 32,28 40,36"/>
          <line x1="32" y1="28" x2="32" y2="48"/>
          <path d="M20,16 V12 a4,4 0 0,1 4,-4 h16 a4,4 0 0,1 4,4 v4"/>
        </svg>
        <p>Drag files here, or <label class="upload-link" for="file-input">click to choose</label></p>
        <p class="hint">HTML, CSS, JS, images &mdash; up to 5 MB per file</p>
        <input type="file" id="file-input" multiple hidden>
      </div>
      <div id="file-list" class="file-list"></div>
      <div id="upload-progress" class="upload-progress hidden"></div>
      <div class="upload-actions">
        <button class="btn btn-accent" id="publish-btn" onclick="publishSite()">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/>
          </svg>
          Publish to HidraNet
        </button>
      </div>
    </section>

    <!-- Sites List -->
    <section class="card sites-card">
      <h2><span class="icon">&#9776;</span> My sites</h2>
      <div id="sites-list" class="sites-list">
        <div class="empty-state">No sites created yet. Create your first one above.</div>
      </div>
    </section>

    <!-- Templates Section -->
    <section class="card templates-card">
      <h2><span class="icon">&#10025;</span> Ready-made templates</h2>
      <div class="templates-grid">
        <div class="template-item" onclick="useTemplate('landing')">
          <div class="template-preview landing-preview">
            <div class="tp-bar"></div><div class="tp-hero"></div><div class="tp-cols"><div></div><div></div><div></div></div>
          </div>
          <span>Landing Page</span>
        </div>
        <div class="template-item" onclick="useTemplate('blog')">
          <div class="template-preview blog-preview">
            <div class="tp-bar"></div><div class="tp-content"><div class="tp-line w80"></div><div class="tp-line w60"></div><div class="tp-line w90"></div><div class="tp-line w40"></div></div>
          </div>
          <span>Blog</span>
        </div>
        <div class="template-item" onclick="useTemplate('portfolio')">
          <div class="template-preview portfolio-preview">
            <div class="tp-bar"></div><div class="tp-grid"><div></div><div></div><div></div><div></div></div>
          </div>
          <span>Portfolio</span>
        </div>
        <div class="template-item" onclick="useTemplate('docs')">
          <div class="template-preview docs-preview">
            <div class="tp-bar"></div><div class="tp-sidebar"></div><div class="tp-main"><div class="tp-line w90"></div><div class="tp-line w70"></div></div>
          </div>
          <span>Documentation</span>
        </div>
        <div class="template-item" onclick="useTemplate('shop')">
          <div class="template-preview portfolio-preview">
            <div class="tp-bar"></div><div class="tp-grid"><div></div><div></div><div></div><div></div></div>
          </div>
          <span>Online shop</span>
        </div>
        <div class="template-item" onclick="useTemplate('news')">
          <div class="template-preview blog-preview">
            <div class="tp-bar"></div><div class="tp-content"><div class="tp-line w90"></div><div class="tp-line w60"></div><div class="tp-line w80"></div><div class="tp-line w40"></div></div>
          </div>
          <span>News portal</span>
        </div>
      </div>
    </section>

    <footer class="footer">
      <p>SevenNine.hidra &mdash; Powered by <strong>HidraNet</strong></p>
      <p class="hint">Every site is hosted decentrally on the HidraNet network</p>
      <p class="hint"><a href="/terms" target="_blank">Terms of Use</a></p>
    </footer>
  </div>

  <!-- ═══ Visual Page Editor (WordPress-style) ═══ -->
  <div id="editor" class="editor hidden">
    <div class="ed-top">
      <div class="ed-top-left">
        <button class="btn btn-ghost btn-sm" onclick="closeEditor()">&larr; Back</button>
        <span class="ed-editing">Editing <span id="ed-site-name" class="accent">site.hidra</span></span>
      </div>
      <div class="ed-top-right">
        <button class="btn btn-ghost btn-sm" id="ed-devtoggle" onclick="toggleDevice()" title="Toggle preview">🖥 Desktop</button>
        <a id="ed-open" href="#" target="_blank" class="btn btn-ghost btn-sm">View site</a>
        <button class="btn btn-primary btn-sm" id="ed-publish" onclick="publishEditor()">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/></svg>
          Publish
        </button>
      </div>
    </div>
    <div class="ed-main">
      <aside class="ed-side">
        <div class="ed-block">
          <div class="ed-block-title">Brand</div>
          <label class="ed-label">Name / logo (appears in the menu)</label>
          <input type="text" id="ed-brand" class="ed-input" placeholder="My brand" oninput="setMeta('brand', this.value)">
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Appearance</div>
          <label class="ed-label">Theme</label>
          <div class="ed-themes" id="ed-themes"></div>
          <label class="ed-label">Font</label>
          <select id="ed-font" class="ed-input" onchange="setMeta('font', this.value)">
            <option value="system">Modern (sans-serif)</option>
            <option value="serif">Elegant (serif)</option>
            <option value="mono">Technical (monospace)</option>
            <option value="round">Rounded</option>
          </select>
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Add block</div>
          <div class="ed-palette" id="ed-palette"></div>
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Footer / Social</div>
          <label class="ed-label">WhatsApp (number)</label>
          <input type="text" id="ed-wa" class="ed-input" placeholder="5511999999999" oninput="setSocial('whatsapp', this.value)">
          <label class="ed-label">Instagram (@username)</label>
          <input type="text" id="ed-ig" class="ed-input" placeholder="@mybrand" oninput="setSocial('instagram', this.value)">
          <label class="ed-label">E-mail</label>
          <input type="text" id="ed-mail" class="ed-input" placeholder="contact@example" oninput="setSocial('email', this.value)">
        </div>
      </aside>

      <main class="ed-canvas-wrap">
        <div class="ed-pages" id="ed-pages"></div>
        <div class="ed-canvas" id="ed-canvas"></div>
      </main>

      <section class="ed-preview">
        <div class="ed-preview-head">
          <span>Preview &mdash; click the text to edit &#9998;</span>
          <span class="ed-preview-dot" id="ed-preview-dot"></span>
        </div>
        <div class="ed-frame-wrap" id="ed-frame-wrap">
          <iframe id="ed-frame" title="preview" sandbox="allow-same-origin allow-scripts"></iframe>
        </div>
      </section>
    </div>
  </div>

  <!-- Own modal (prompt/confirm do not work in Electron) -->
  <div id="s9-modal" class="s9-modal hidden">
    <div class="s9-modal-box">
      <div class="s9-modal-title" id="s9-modal-title">Title</div>
      <div class="s9-modal-msg" id="s9-modal-msg"></div>
      <input type="text" id="s9-modal-input" class="ed-input" autocomplete="off" spellcheck="false">
      <div class="s9-modal-actions">
        <button class="btn btn-ghost" id="s9-modal-cancel">Cancel</button>
        <button class="btn btn-primary" id="s9-modal-ok">Confirm</button>
      </div>
    </div>
  </div>
  <div id="s9-toast" class="s9-toast"></div>

  <script src="/app.js"></script>
</body>
</html>"##;

// ─── Frontend CSS ────────────────────────────────────────────────────────────

const FRONTEND_CSS: &str = r##"
* { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --bg: #06060b;
  --bg-card: #10101c;
  --bg-card-hover: #14142a;
  --bg-input: #0a0a16;
  --text: #e0e0e8;
  --text2: #8888a0;
  --text3: #555570;
  --accent: #00d4aa;
  --accent-dim: #00a888;
  --accent-glow: rgba(0, 212, 170, 0.15);
  --danger: #ff4466;
  --warning: #ffaa33;
  --success: #00d4aa;
  --border: #1a1a2e;
  --radius: 12px;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}

.app { max-width: 900px; margin: 0 auto; padding: 32px 20px; }

/* Header */
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }
.logo { display: flex; align-items: center; gap: 16px; }
.logo h1 { font-size: 1.8em; color: var(--text); }
.accent { color: var(--accent); }
.tagline { color: var(--text2); font-size: 0.9em; margin-top: 4px; }

.header-stats { display: flex; gap: 24px; }
.stat { display: flex; flex-direction: column; align-items: center; }
.stat-value { font-size: 1.6em; font-weight: 700; color: var(--accent); }
.stat-label { font-size: 0.75em; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; }

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  margin-bottom: 20px;
}
.card h2 { font-size: 1.15em; color: var(--text); margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
.icon { color: var(--accent); font-size: 1.2em; }

/* Create form */
.create-form { display: flex; gap: 12px; align-items: stretch; }
.name-input-group {
  display: flex;
  align-items: center;
  flex: 1;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  transition: border-color 0.2s;
}
.name-input-group:focus-within { border-color: var(--accent); }
.name-input-group input {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text);
  padding: 12px 16px;
  font-size: 1.05em;
  outline: none;
  font-family: 'SF Mono', 'Fira Code', monospace;
}
.name-input-group input::placeholder { color: var(--text3); }
.domain-suffix {
  padding: 12px 16px;
  background: rgba(0, 212, 170, 0.08);
  color: var(--accent);
  font-weight: 600;
  font-family: 'SF Mono', 'Fira Code', monospace;
  border-left: 1px solid var(--border);
  white-space: nowrap;
}

/* Buttons */
.btn {
  display: flex; align-items: center; gap: 8px;
  padding: 12px 24px;
  border: none; border-radius: 8px;
  font-size: 0.95em; font-weight: 600;
  cursor: pointer; transition: all 0.2s;
  white-space: nowrap;
}
.btn-primary { background: var(--accent); color: #000; }
.btn-primary:hover { background: var(--accent-dim); transform: translateY(-1px); }
.btn-accent { background: var(--accent); color: #000; }
.btn-accent:hover { background: var(--accent-dim); }
.btn-danger { background: transparent; color: var(--danger); border: 1px solid var(--danger); padding: 6px 14px; font-size: 0.8em; }
.btn-danger:hover { background: rgba(255, 68, 102, 0.1); }
.btn-sm { padding: 6px 14px; font-size: 0.8em; }
.btn-ghost { background: rgba(0,212,170,0.1); color: var(--accent); border: 1px solid rgba(0,212,170,0.3); }
.btn-ghost:hover { background: rgba(0,212,170,0.2); }

/* Messages */
.msg { padding: 12px 16px; border-radius: 8px; margin-top: 12px; font-size: 0.9em; }
.msg.success { background: rgba(0,212,170,0.1); color: var(--success); border: 1px solid rgba(0,212,170,0.3); }
.msg.error { background: rgba(255,68,102,0.1); color: var(--danger); border: 1px solid rgba(255,68,102,0.3); }
.hidden { display: none !important; }

/* Upload zone */
.upload-zone {
  border: 2px dashed var(--border);
  border-radius: var(--radius);
  padding: 40px;
  text-align: center;
  transition: all 0.3s;
  cursor: pointer;
}
.upload-zone:hover, .upload-zone.dragover { border-color: var(--accent); background: var(--accent-glow); }
.upload-zone p { color: var(--text2); margin-top: 12px; }
.upload-zone .hint { color: var(--text3); font-size: 0.8em; margin-top: 8px; }
.upload-link { color: var(--accent); cursor: pointer; text-decoration: underline; }

.file-list { margin-top: 16px; }
.file-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px;
  background: var(--bg-input);
  border-radius: 6px;
  margin-bottom: 6px;
  font-size: 0.9em;
}
.file-item .fname { color: var(--text); font-family: monospace; }
.file-item .fsize { color: var(--text3); font-size: 0.8em; }

.upload-actions { margin-top: 16px; display: flex; justify-content: flex-end; }

/* Sites list */
.sites-list { display: flex; flex-direction: column; gap: 10px; }
.empty-state { color: var(--text3); text-align: center; padding: 40px; font-style: italic; }

.site-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 20px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 10px;
  transition: border-color 0.2s;
}
.site-item:hover { border-color: rgba(0,212,170,0.3); }
.site-info { flex: 1; }
.site-name { font-weight: 700; color: var(--accent); font-size: 1.05em; font-family: monospace; }
.site-meta { color: var(--text3); font-size: 0.8em; margin-top: 4px; }
.site-actions { display: flex; gap: 8px; align-items: center; }

/* Templates */
.templates-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 16px; }
.template-item {
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}
.template-item:hover { border-color: var(--accent); transform: translateY(-2px); }
.template-item span { display: block; margin-top: 12px; color: var(--text2); font-size: 0.9em; }

.template-preview {
  height: 100px;
  background: var(--bg);
  border-radius: 6px;
  overflow: hidden;
  padding: 8px;
}
.tp-bar { height: 8px; background: rgba(0,212,170,0.2); border-radius: 3px; margin-bottom: 8px; }
.tp-hero { height: 30px; background: rgba(0,212,170,0.1); border-radius: 4px; margin-bottom: 8px; }
.tp-cols { display: flex; gap: 4px; }
.tp-cols div { flex: 1; height: 30px; background: rgba(0,212,170,0.06); border-radius: 3px; }
.tp-content { padding: 4px; }
.tp-line { height: 6px; background: rgba(255,255,255,0.05); border-radius: 2px; margin-bottom: 6px; }
.tp-line.w80 { width: 80%; } .tp-line.w60 { width: 60%; } .tp-line.w90 { width: 90%; } .tp-line.w40 { width: 40%; } .tp-line.w70 { width: 70%; }
.tp-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; }
.tp-grid div { height: 28px; background: rgba(0,212,170,0.08); border-radius: 3px; }
.tp-sidebar { float: left; width: 30%; height: 60px; background: rgba(0,212,170,0.06); border-radius: 3px; margin-right: 8px; }
.tp-main { overflow: hidden; padding-top: 4px; }

/* Footer */
.footer { text-align: center; padding: 32px 0 16px; color: var(--text3); font-size: 0.85em; }
.footer strong { color: var(--accent); }

/* Success banner */
.success-card { border-color: rgba(0,212,170,0.4); background: linear-gradient(135deg, rgba(0,212,170,0.05), var(--bg-card)); }
.success-content { text-align: center; padding: 16px 0; }
.success-icon { margin-bottom: 12px; }
.success-content h2 { color: var(--accent); font-size: 1.3em; margin-bottom: 16px; justify-content: center; }
.address-box {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--bg-input); border: 1px solid rgba(0,212,170,0.3);
  border-radius: 8px; padding: 12px 20px; margin-bottom: 20px;
}
.address-text { font-family: 'SF Mono','Fira Code',monospace; font-size: 1.15em; color: var(--accent); font-weight: 600; }
.btn-copy {
  background: none; border: none; color: var(--text3); cursor: pointer;
  padding: 4px; border-radius: 4px; transition: color 0.2s;
}
.btn-copy:hover { color: var(--accent); }
.success-actions { display: flex; gap: 12px; justify-content: center; }
.success-actions a { text-decoration: none; }

/* Upload progress */
.upload-progress { margin-top: 12px; padding: 12px 16px; border-radius: 8px; background: var(--bg-input); border: 1px solid var(--border); }
.upload-progress .prog-text { color: var(--text2); font-size: 0.9em; }
.upload-progress .prog-bar { height: 4px; background: var(--border); border-radius: 2px; margin-top: 8px; overflow: hidden; }
.upload-progress .prog-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.3s; }

/* File remove button */
.file-remove { background: none; border: none; color: var(--text3); cursor: pointer; font-size: 1.1em; padding: 2px 6px; border-radius: 4px; }
.file-remove:hover { color: var(--danger); background: rgba(255,68,102,0.1); }

/* Loading spinner */
.spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(0,212,170,0.3); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Responsive */
@media (max-width: 640px) {
  .header { flex-direction: column; gap: 16px; }
  .create-form { flex-direction: column; }
  .templates-grid { grid-template-columns: repeat(2, 1fr); }
}

/* ═══ Visual Editor ═══ */
.editor { position: fixed; inset: 0; background: var(--bg); z-index: 1000; display: flex; flex-direction: column; }
.editor.hidden { display: none; }

.ed-top { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; background: var(--bg-card); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.ed-top-left, .ed-top-right { display: flex; align-items: center; gap: 12px; }
.ed-editing { color: var(--text2); font-size: 0.9em; }

.ed-main { flex: 1; display: grid; grid-template-columns: 270px 1fr 42%; min-height: 0; }

.ed-side { background: var(--bg-card); border-right: 1px solid var(--border); overflow-y: auto; padding: 18px; }
.ed-block { margin-bottom: 24px; }
.ed-block-title { font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; color: var(--text3); margin-bottom: 12px; font-weight: 700; }
.ed-label { display: block; font-size: 0.8em; color: var(--text2); margin: 12px 0 5px; }
.ed-input { width: 100%; padding: 9px 12px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 7px; color: var(--text); font-size: 0.9em; outline: none; font-family: inherit; }
.ed-input:focus { border-color: var(--accent); }
textarea.ed-input { resize: vertical; min-height: 64px; line-height: 1.5; }

.ed-themes { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.ed-theme { height: 34px; border-radius: 7px; cursor: pointer; border: 2px solid transparent; position: relative; overflow: hidden; }
.ed-theme.active { border-color: var(--accent); }
.ed-theme span { position: absolute; bottom: 3px; right: 4px; width: 10px; height: 10px; border-radius: 50%; }

.ed-palette { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.ed-pal-btn { display: flex; align-items: center; gap: 7px; padding: 10px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; color: var(--text2); cursor: pointer; font-size: 0.82em; transition: all 0.15s; }
.ed-pal-btn:hover { border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }

.ed-canvas-wrap { overflow-y: auto; padding: 20px; background: var(--bg); }
.ed-canvas { max-width: 640px; margin: 0 auto; display: flex; flex-direction: column; gap: 12px; }
.ed-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; transition: box-shadow .15s, border-color .15s; }
.ed-card.ed-sel { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(0,212,170,0.25); }
.ed-card-head { display: flex; align-items: center; justify-content: space-between; padding: 9px 14px; background: var(--bg-card-hover); border-bottom: 1px solid var(--border); }
.ed-card-type { font-size: 0.78em; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: 0.5px; }
.ed-card-tools { display: flex; gap: 4px; }
.ed-tool { background: none; border: none; color: var(--text3); cursor: pointer; padding: 3px 7px; border-radius: 5px; font-size: 0.95em; }
.ed-tool:hover { background: var(--bg-input); color: var(--text); }
.ed-tool.del:hover { color: var(--danger); }
.ed-card-body { padding: 14px; display: flex; flex-direction: column; gap: 8px; }
.ed-card-body .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.ed-feat-item { border: 1px dashed var(--border); border-radius: 8px; padding: 10px; display: flex; flex-direction: column; gap: 6px; position: relative; }
.ed-feat-rm { position: absolute; top: 6px; right: 8px; background: none; border: none; color: var(--text3); cursor: pointer; }
.ed-feat-rm:hover { color: var(--danger); }
.ed-mini-btn { align-self: flex-start; padding: 6px 12px; font-size: 0.8em; background: rgba(0,212,170,0.1); color: var(--accent); border: 1px solid rgba(0,212,170,0.3); border-radius: 6px; cursor: pointer; }
.ed-canvas-empty { text-align: center; color: var(--text3); padding: 48px 16px; font-style: italic; }

.ed-preview { border-left: 1px solid var(--border); display: flex; flex-direction: column; background: #000; min-height: 0; }
.ed-preview-head { display: flex; align-items: center; gap: 8px; padding: 10px 16px; background: var(--bg-card); border-bottom: 1px solid var(--border); font-size: 0.8em; color: var(--text2); flex-shrink: 0; }
.ed-preview-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.ed-frame-wrap { flex: 1; overflow: auto; display: flex; justify-content: center; background: #15151f; padding: 0; }
.ed-frame-wrap.mobile { padding: 16px; }
#ed-frame { width: 100%; height: 100%; border: none; background: #fff; }
.ed-frame-wrap.mobile #ed-frame { width: 390px; max-width: 100%; height: 100%; border-radius: 12px; box-shadow: 0 8px 40px rgba(0,0,0,0.5); }

@media (max-width: 900px) {
  .ed-main { grid-template-columns: 1fr; grid-template-rows: auto 1fr; }
  .ed-side { display: none; }
  .ed-preview { display: none; }
}

/* Modal */
.s9-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(3px); z-index: 3000; display: flex; align-items: center; justify-content: center; }
.s9-modal.hidden { display: none; }
.s9-modal-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 28px; width: 420px; max-width: 92vw; box-shadow: 0 24px 60px rgba(0,0,0,0.5); }
.s9-modal-title { font-size: 1.2em; font-weight: 700; color: var(--text); margin-bottom: 8px; }
.s9-modal-msg { color: var(--text2); font-size: 0.92em; margin-bottom: 16px; line-height: 1.5; }
.s9-modal-box .ed-input { width: 100%; padding: 12px 14px; font-size: 1em; margin-bottom: 18px; }
.s9-modal-actions { display: flex; justify-content: flex-end; gap: 10px; }
.s9-toast { position: fixed; bottom: 28px; left: 50%; transform: translateX(-50%) translateY(20px); background: var(--bg-card); border: 1px solid var(--accent); color: var(--text); padding: 13px 22px; border-radius: 10px; font-size: 0.92em; z-index: 4000; opacity: 0; pointer-events: none; transition: all 0.25s; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
.s9-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

/* Page tabs */
.ed-pages { display: flex; align-items: center; gap: 6px; max-width: 640px; margin: 0 auto 14px; flex-wrap: wrap; }
.ed-page-tab { display: flex; align-items: center; gap: 6px; padding: 7px 12px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; color: var(--text2); cursor: pointer; font-size: 0.85em; }
.ed-page-tab.active { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,0.08); }
.ed-page-tab .pg-edit { opacity: 0.5; font-size: 0.85em; }
.ed-page-tab:hover .pg-edit { opacity: 1; }
.ed-page-add { padding: 7px 12px; background: rgba(0,212,170,0.1); border: 1px dashed rgba(0,212,170,0.4); border-radius: 8px; color: var(--accent); cursor: pointer; font-size: 0.85em; }
.ed-page-add:hover { background: rgba(0,212,170,0.2); }

/* Item sub-editors (products, articles, etc.) */
.ed-items { display: flex; flex-direction: column; gap: 10px; }
.ed-item { border: 1px dashed var(--border); border-radius: 9px; padding: 12px; position: relative; display: flex; flex-direction: column; gap: 7px; }
.ed-item-rm { position: absolute; top: 8px; right: 10px; background: none; border: none; color: var(--text3); cursor: pointer; font-size: 1.05em; }
.ed-item-rm:hover { color: var(--danger); }
.ed-item-n { font-size: 0.72em; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }
.ed-check { display: flex; align-items: center; gap: 7px; font-size: 0.85em; color: var(--text2); cursor: pointer; }
.ed-palette { grid-template-columns: 1fr 1fr; }
.terms-check { display: flex; align-items: flex-start; gap: 8px; margin-top: 14px; font-size: 0.85em; color: var(--text2); cursor: pointer; line-height: 1.5; }
.terms-check input { margin-top: 3px; }
.terms-check a, .footer a { color: var(--accent); }
.net-status { margin-top: 12px; font-size: 0.82em; padding: 9px 12px; border-radius: 8px; line-height: 1.5; }
.net-status.on { background: rgba(0, 212, 170, 0.08); color: var(--accent); border: 1px solid rgba(0, 212, 170, 0.25); }
.net-status.off { background: rgba(255, 255, 255, 0.03); color: var(--text2); border: 1px solid var(--border); }
.site-share { font-size: 0.78em; color: var(--text2); margin-top: 3px; word-break: break-all; }
.site-share code { color: var(--accent); }
"##;

// ─── Frontend JavaScript ─────────────────────────────────────────────────────

const FRONTEND_JS: &str = r##"
const API = window.location.origin;
let currentSite = null;
let pendingFiles = [];

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  loadSites();
  loadNetworkStatus();
  setupDragDrop();
  document.getElementById('site-name').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') createSite();
  });
});

// ── Create Site ──
async function createSite() {
  const nameInput = document.getElementById('site-name');
  const name = nameInput.value.trim().toLowerCase();
  if (!name) { showMsg('create-msg', 'Enter a name for the site', 'error'); return; }
  if (!termsAccepted()) return;

  const btn = document.getElementById('create-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Creating...';

  try {
    const res = await fetch(API + '/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, accept_terms: true })
    });
    const data = await res.json();

    if (data.ok && data.site) {
      currentSite = data.site.name;
      nameInput.value = '';
      loadSites();
      openEditor(data.site.name);          // opens the visual editor on the home page
    } else {
      showMsg('create-msg', data.msg || 'Could not create site', 'error');
    }
  } catch (e) {
    showMsg('create-msg', 'Connection error: ' + e.message, 'error');
  }

  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Create site';
}

// ── Upload ──
function showUploadSection(siteName) {
  const section = document.getElementById('upload-section');
  section.classList.remove('hidden');
  document.getElementById('upload-site-name').textContent = siteName + '.hidra';
  pendingFiles = [];
  document.getElementById('file-list').innerHTML = '';
}

function setupDragDrop() {
  const zone = document.getElementById('drop-zone');
  const input = document.getElementById('file-input');

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => { zone.classList.remove('dragover'); });
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
  });
  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => { handleFiles(input.files); input.value = ''; });
}

function handleFiles(fileList) {
  for (const file of fileList) {
    if (file.size > 5 * 1024 * 1024) {
      toast('File ' + file.name + ' exceeds 5 MB');
      continue;
    }
    pendingFiles.push(file);
  }
  renderFileList();
}

function renderFileList() {
  const container = document.getElementById('file-list');
  container.innerHTML = pendingFiles.map((f, i) =>
    '<div class="file-item">' +
      '<span class="fname">' + escapeHtml(f.name) + '</span>' +
      '<div style="display:flex;align-items:center;gap:8px">' +
        '<span class="fsize">' + formatSize(f.size) + '</span>' +
        '<button class="file-remove" onclick="removeFile(' + i + ')" title="Remove">&times;</button>' +
      '</div>' +
    '</div>'
  ).join('');
}

function removeFile(index) {
  pendingFiles.splice(index, 1);
  renderFileList();
}

async function publishSite() {
  if (!currentSite) return;
  if (pendingFiles.length === 0) { showMsg('create-msg', 'Add at least one file', 'error'); return; }

  const btn = document.getElementById('publish-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Publishing...';

  const prog = document.getElementById('upload-progress');
  prog.classList.remove('hidden');
  const total = pendingFiles.length;
  let uploaded = 0;
  let lastSite = null;

  for (const file of pendingFiles) {
    prog.innerHTML = '<div class="prog-text">Uploading ' + escapeHtml(file.name) + ' (' + (uploaded+1) + '/' + total + ')</div>' +
      '<div class="prog-bar"><div class="prog-fill" style="width:' + Math.round((uploaded/total)*100) + '%"></div></div>';

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(API + '/api/upload/' + currentSite, { method: 'POST', body: formData });
      const data = await res.json();
      if (data.ok && data.site) lastSite = data.site;
      uploaded++;
    } catch (e) {
      showMsg('create-msg', 'Could not upload ' + file.name + ': ' + e.message, 'error');
    }
  }

  prog.innerHTML = '<div class="prog-text">Done! ' + uploaded + '/' + total + ' files uploaded</div>' +
    '<div class="prog-bar"><div class="prog-fill" style="width:100%"></div></div>';

  pendingFiles = [];
  document.getElementById('file-list').innerHTML = '';
  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/></svg> Publish to HidraNet';

  showSuccess(currentSite);
  loadSites();

  setTimeout(() => { prog.classList.add('hidden'); }, 3000);
}

function showSuccess(siteName) {
  const section = document.getElementById('success-section');
  const addr = siteName + '.hidra';
  document.getElementById('address-text').textContent = addr;
  document.getElementById('open-local-link').href = '/sites/' + siteName + '/';
  section.classList.remove('hidden');
  section.scrollIntoView({ behavior: 'smooth' });
}

function hideSuccess() {
  document.getElementById('success-section').classList.add('hidden');
}

function copyAddress() {
  const text = document.getElementById('address-text').textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.querySelector('.btn-copy');
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#00d4aa" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
      setTimeout(() => {
        btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
      }, 2000);
    });
  }
}

// ── Sites List ──
async function loadSites() {
  try {
    const res = await fetch(API + '/api/sites');
    const data = await res.json();
    if (data.ok && data.sites) {
      renderSites(data.sites);
      document.getElementById('total-sites').textContent = data.sites.length;
    }
  } catch (e) {
    // silent
  }
}

function renderSites(sites) {
  const container = document.getElementById('sites-list');
  if (sites.length === 0) {
    container.innerHTML = '<div class="empty-state">No sites created yet. Create your first one above.</div>';
    return;
  }

  container.innerHTML = sites.map(s =>
    '<div class="site-item">' +
      '<div class="site-info">' +
        '<div class="site-name">' + escapeHtml(s.hidra_address) + '</div>' +
        (s.network_address
          ? '<div class="site-share">Share this address: <code>' + escapeHtml(s.network_address) + '</code></div>'
          : '<div class="site-share">Only on this computer for now</div>') +
        '<div class="site-meta">' +
          s.files.length + ' file(s) &middot; ' + formatSize(s.size_bytes) + ' &middot; ' +
          s.visits + ' visit(s) &middot; ' + new Date(s.created_at).toLocaleDateString('en-US') +
        '</div>' +
      '</div>' +
      '<div class="site-actions">' +
        '<button class="btn btn-primary btn-sm" onclick="openEditor(\'' + escapeHtml(s.name) + '\')">Edit</button>' +
        '<a href="/sites/' + escapeHtml(s.name) + '/" target="_blank" class="btn btn-ghost btn-sm">Open</a>' +
        '<button class="btn btn-ghost btn-sm" onclick="uploadTo(\'' + escapeHtml(s.name) + '\')">Upload</button>' +
        '<button class="btn btn-danger btn-sm" onclick="deleteSite(\'' + escapeHtml(s.name) + '\')">Delete</button>' +
      '</div>' +
    '</div>'
  ).join('');
}

function uploadTo(name) {
  currentSite = name;
  showUploadSection(name);
  document.getElementById('upload-section').scrollIntoView({ behavior: 'smooth' });
}

async function deleteSite(name) {
  if (!await askConfirm('Delete the site "' + name + '.hidra"? This cannot be undone.')) return;

  try {
    await fetch(API + '/api/sites/' + name, { method: 'DELETE' });
    loadSites();
    toast('Site deleted.');
  } catch (e) {
    toast('Error: ' + e.message);
  }
}

// ── Templates: create the site and open the editor already filled in ──
async function useTemplate(type) {
  const name = await askText({ title: 'Create a site from a template', msg: 'Choose a name — it becomes your site\'s .hidra address.', placeholder: 'mysite', ok: 'Create and edit' });
  if (!name) return;
  const clean = name.trim().toLowerCase();
  if (!clean) return;
  if (!termsAccepted()) return;
  try {
    const res = await fetch(API + '/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: clean, accept_terms: true })
    });
    const data = await res.json();
    if (data.ok && data.site) {
      currentSite = data.site.name;
      loadSites();
      openEditor(data.site.name, type);   // open the editor with the template blocks
    } else {
      showMsg('create-msg', data.msg || 'Could not create site', 'error');
    }
  } catch (e) {
    showMsg('create-msg', 'Connection error: ' + e.message, 'error');
  }
}

// ── Terms of Use ──
// A site is created only once the owner has accepted the Terms of Use. The
// server refuses a create request that does not say so.
function termsAccepted() {
  const box = document.getElementById('accept-terms');
  if (box && box.checked) return true;
  showMsg('create-msg', 'Please read and accept the Terms of Use first.', 'error');
  if (box) box.focus();
  return false;
}

// ── Network status: is this builder published as a hidden service? ──
let networkAddress = null;
async function loadNetworkStatus() {
  const el = document.getElementById('net-status');
  try {
    const res = await fetch(API + '/api/status');
    const data = await res.json();
    networkAddress = data && data.network ? data.network_address : null;
  } catch (e) { networkAddress = null; }
  if (!el) return;
  if (networkAddress) {
    el.className = 'net-status on';
    el.textContent = 'Online on HidraNet. Other people reach your sites at ' + networkAddress + '.';
  } else {
    el.className = 'net-status off';
    el.textContent = 'Local only: sites are visible on this computer. Start SevenNine on the network to share them.';
  }
}

// ── Helpers ──
function showMsg(id, text, type) {
  const el = document.getElementById(id);
  el.className = 'msg ' + type;
  el.textContent = text;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 8000);
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ═══════════════════ Visual page editor (WordPress style) ═══════════════════

var ed = { site:null, theme:'hidra', font:'system', brand:'', social:{whatsapp:'',instagram:'',email:''}, pages:[], cur:0 };
var edPreviewTimer = null;
var edDevice = 'desktop';

function curPage(){ return ed.pages[ed.cur] || {blocks:[]}; }
function curBlocks(){ return curPage().blocks; }
function newPage(id,name,blocks){ return { id:id, name:name, blocks:blocks }; }
function fileFor(p){ return p.id==='index' ? 'index.html' : p.id+'.html'; }
function slugify(s){ s=(s||'').toLowerCase(); try{ s=s.normalize('NFD').replace(/[̀-ͯ]/g,''); }catch(e){} return s.replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); }
function uniquePageId(base){ if(!base||base==='index') base='page'; var id=base,n=2,ids=ed.pages.map(function(p){return p.id;}); while(ids.indexOf(id)>=0){ id=base+'-'+n; n++; } return id; }
function isListBlock(t){ return ['features','products','articles','pricing','testimonials','gallery'].indexOf(t)>=0; }

var THEMES = {
  hidra:    { name:'Hidra',    mode:'dark',  primary:'#00d4aa', primary2:'#00a888', bg:'#06060b', card:'#10101c', border:'#1a1a2e', text:'#e8e8f0', muted:'#8a8aa0' },
  midnight: { name:'Midnight', mode:'dark',  primary:'#4f8cff', primary2:'#2f6fe0', bg:'#0a0e1a', card:'#121a2e', border:'#1e2a44', text:'#e6ebf5', muted:'#8a93a8' },
  nebula:   { name:'Nebula',   mode:'dark',  primary:'#a06bff', primary2:'#7b46d6', bg:'#0c0814', card:'#181226', border:'#271b3d', text:'#ece6f5', muted:'#9a8ab0' },
  charcoal: { name:'Charcoal', mode:'dark',  primary:'#f5a623', primary2:'#d68a10', bg:'#121212', card:'#1c1c1c', border:'#2a2a2a', text:'#f0f0f0', muted:'#9a9a9a' },
  clean:    { name:'Clean',    mode:'light', primary:'#2563eb', primary2:'#1d4ed8', bg:'#ffffff', card:'#f4f6fb', border:'#e2e8f0', text:'#1a1f2e', muted:'#667085' },
  mint:     { name:'Mint',     mode:'light', primary:'#0f9d77', primary2:'#0b7d5e', bg:'#f2fbf7', card:'#ffffff', border:'#d6ece2', text:'#10241d', muted:'#5d7d70' },
  sepia:    { name:'Sepia',    mode:'light', primary:'#b4612f', primary2:'#8f4a22', bg:'#f7f1e6', card:'#fffaf2', border:'#e6dcc8', text:'#2e261c', muted:'#8a7a63' },
  coral:    { name:'Coral',    mode:'light', primary:'#e8536b', primary2:'#c63a52', bg:'#fff5f6', card:'#ffffff', border:'#f6dbe0', text:'#2c1419', muted:'#8a6066' }
};

// Sites saved before the editor was translated store the old theme ids. The
// theme is part of the saved source, so without this the editor would fall
// back to the default and silently restyle someone's published site.
var THEME_LEGACY = { meianoite:'midnight', nebulosa:'nebula', carvao:'charcoal', menta:'mint' };
function normTheme(t){ return THEMES[t] ? t : (THEME_LEGACY[t] || 'hidra'); }

var FONTS = {
  system: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  serif:  "Georgia, 'Times New Roman', serif",
  mono:   "'SF Mono', 'Fira Code', Consolas, monospace",
  round:  "'Trebuchet MS', 'Segoe UI', Verdana, sans-serif"
};

var PALETTE_BLOCKS = [
  { type:'hero',         label:'Cover',        icon:'★' },
  { type:'heading',      label:'Title',      icon:'H' },
  { type:'text',         label:'Text',       icon:'¶' },
  { type:'image',        label:'Image',      icon:'▣' },
  { type:'button',       label:'Button',       icon:'▭' },
  { type:'features',     label:'Features',    icon:'⊞' },
  { type:'products',     label:'Products',    icon:'🛍' },
  { type:'articles',     label:'News',        icon:'📰' },
  { type:'pricing',      label:'Pricing',     icon:'$' },
  { type:'testimonials', label:'Testimonials',icon:'❝' },
  { type:'gallery',      label:'Gallery',     icon:'▦' },
  { type:'cta',          label:'Call to action', icon:'➤' },
  { type:'contact',      label:'Contact',     icon:'✉' },
  { type:'divider',      label:'Divider',     icon:'—' }
];

function defaultItem(type){
  if(type==='features') return {icon:'✦',title:'Feature',text:'Feature description'};
  if(type==='products') return {img:'',name:'Product',price:'99.90',desc:'Product description.',url:'#',label:'Buy'};
  if(type==='articles') return {img:'',cat:'General',title:'Story headline',date:'Today',excerpt:'A one or two line summary of the story.',url:'#'};
  if(type==='pricing') return {plan:'Plan',price:'0',period:'/mo',feats:'Included feature\nAnother feature',button:'Choose',url:'#',featured:false};
  if(type==='testimonials') return {quote:'Excellent service, highly recommended.',author:'Customer',role:'Role'};
  if(type==='gallery') return {url:''};
  return {};
}
function itemName(type){
  return {features:'Feature',products:'Product',articles:'Story',pricing:'Plan',testimonials:'Testimonial',gallery:'Image'}[type] || 'Item';
}

function defaultBlock(type) {
  switch(type) {
    case 'hero': return { type:type, title:'Welcome to my site', subtitle:'Hosted on the decentralised HidraNet network.', button:'Learn more', url:'#' };
    case 'heading': return { type:type, text:'A section title' };
    case 'text': return { type:type, text:'Write your content here. Tell people about you, your project or your ideas.' };
    case 'image': return { type:type, url:'', alt:'Image description' };
    case 'button': return { type:type, text:'Click here', url:'#' };
    case 'features': return { type:type, title:'', items:[ {icon:'🔒',title:'Secure',text:'End-to-end encryption'}, {icon:'🕵',title:'Anonymous',text:'No tracking'}, {icon:'🌐',title:'Decentralised',text:'No central server'} ] };
    case 'products': return { type:type, title:'Our products', currency:'$', items:[ {img:'',name:'Product 1',price:'99.90',desc:'A great product, quality guaranteed.',url:'#',label:'Buy'}, {img:'',name:'Product 2',price:'149.90',desc:'Our best seller.',url:'#',label:'Buy'}, {img:'',name:'Product 3',price:'199.90',desc:'Special edition.',url:'#',label:'Buy'} ] };
    case 'articles': return { type:type, title:'Latest news', items:[ {img:'',cat:'Featured',title:'Lead story headline',date:'Today',excerpt:'A short summary of the story to draw the reader in.',url:'#'}, {img:'',cat:'General',title:'Second important story',date:'Yesterday',excerpt:'Another informative summary here.',url:'#'} ] };
    case 'pricing': return { type:type, title:'Plans', items:[ {plan:'Basic',price:'29',period:'/mo',feats:'1 site\nEmail support\n.hidra domain',button:'Get started',url:'#',featured:false}, {plan:'Pro',price:'79',period:'/mo',feats:'Unlimited sites\nPriority support\nStatistics',button:'Subscribe',url:'#',featured:true} ] };
    case 'testimonials': return { type:type, title:'What people say', items:[ {quote:'Best decision I made. Recommended.',author:'Sarah M.',role:'Business owner'}, {quote:'Fast, secure and easy to use.',author:'James P.',role:'Developer'} ] };
    case 'gallery': return { type:type, title:'Gallery', items:[ {url:''},{url:''},{url:''} ] };
    case 'cta': return { type:type, title:'Ready to start?', text:'Join us today and become part of the network.', button:'Start now', url:'#' };
    case 'contact': return { type:type, title:'Get in touch', email:'contact@example.hidra', phone:'', whatsapp:'', address:'' };
    case 'divider': return { type:type };
    default: return { type:'text', text:'' };
  }
}

function starterBlocks() { return [ defaultBlock('hero'), defaultBlock('features') ]; }

function applyTemplate(type) {
  if (type === 'shop') {
    ed.theme='clean'; ed.font='system';
    ed.pages=[
      newPage('index','Home',[ {type:'hero',title:(ed.brand||'My shop'),subtitle:'Quality products, delivered.',button:'See products',url:'products.html'}, defaultBlock('products'), defaultBlock('testimonials'), {type:'cta',title:'Limited-time offers',text:'Take advantage of this week\'s discounts.',button:'Buy now',url:'products.html'} ]),
      newPage('products','Products',[ {type:'heading',text:'Full catalogue'}, defaultBlock('products') ]),
      newPage('contact','Contact',[ {type:'contact',title:'Get in touch',email:'shop@example.hidra',phone:'',whatsapp:'',address:''} ])
    ];
  } else if (type === 'news' || type === 'blog') {
    ed.theme=(type==='news')?'clean':'sepia'; ed.font=(type==='news')?'system':'serif';
    ed.pages=[
      newPage('index','Home',[ {type:'hero',title:(ed.brand||'My portal'),subtitle:'News, articles and analysis.',button:'Read now',url:'#'}, defaultBlock('articles') ]),
      newPage('about','About',[ {type:'heading',text:'About this portal'}, {type:'text',text:'An independent space for free information — no censorship, no tracking — on the HidraNet network.'} ])
    ];
  } else if (type === 'portfolio') {
    ed.theme='midnight'; ed.font='system';
    ed.pages=[ newPage('index','Home',[ {type:'hero',title:(ed.brand||'My portfolio'),subtitle:'Design & development',button:'See work',url:'#'}, defaultBlock('gallery'), defaultBlock('features'), {type:'contact',title:'Talk to me',email:'me@example.hidra',phone:'',whatsapp:'',address:''} ]) ];
  } else if (type === 'docs') {
    ed.theme='hidra'; ed.font='mono';
    ed.pages=[ newPage('index','Home',[ {type:'heading',text:'Documentation'}, {type:'text',text:'Welcome to the project documentation.'} ]), newPage('guide','Guide',[ {type:'heading',text:'Quick start'}, {type:'text',text:'1. Download the program\n2. Run the installer\n3. Ready to use'} ]) ];
  } else {
    ed.theme='hidra'; ed.font='system';
    ed.pages=[ newPage('index','Home',[ defaultBlock('hero'), defaultBlock('features'), defaultBlock('cta') ]) ];
  }
  ed.cur=0;
}

async function openEditor(name, template) {
  ed.site=name; ed.theme='hidra'; ed.font='system'; ed.brand=name;
  ed.social={whatsapp:'',instagram:'',email:''};
  ed.pages=[ newPage('index','Home', starterBlocks()) ]; ed.cur=0;
  try {
    const res = await fetch(API + '/api/page/' + name);
    const src = await res.json();
    if (src && src.pages && src.pages.length) {
      ed.theme=normTheme(src.theme); ed.font=src.font||'system'; ed.brand=src.brand||name;
      ed.social=src.social||ed.social; ed.pages=src.pages; ed.cur=0;
    } else if (src && src.blocks) {
      ed.theme=normTheme(src.theme); ed.font=src.font||'system'; ed.brand=src.title||name;
      ed.pages=[ newPage('index','Home', src.blocks) ];
    } else if (template) { applyTemplate(template); }
  } catch(e) { if (template) applyTemplate(template); }

  document.getElementById('ed-site-name').textContent = name + '.hidra';
  document.getElementById('ed-brand').value = ed.brand;
  document.getElementById('ed-font').value = ed.font;
  document.getElementById('ed-wa').value = ed.social.whatsapp || '';
  document.getElementById('ed-ig').value = ed.social.instagram || '';
  document.getElementById('ed-mail').value = ed.social.email || '';
  document.getElementById('ed-open').href = '/sites/' + name + '/';
  renderThemes(); renderPalette(); renderPageTabs(); renderCanvas(); updatePreview();
  document.getElementById('editor').classList.remove('hidden');
}

function closeEditor() { document.getElementById('editor').classList.add('hidden'); loadSites(); }
function setMeta(key, val) { ed[key] = val; schedulePreview(); }
function setSocial(key, val) { ed.social[key] = val; schedulePreview(); }

// ── Pages ──
function renderPageTabs() {
  var el = document.getElementById('ed-pages');
  var tabs = ed.pages.map(function(p, i){
    var del = (i===0) ? '' : '<span class="pg-edit" title="Delete" onclick="event.stopPropagation();deletePage('+i+')">&times;</span>';
    return '<div class="ed-page-tab'+(i===ed.cur?' active':'')+'" onclick="switchPage('+i+')">' +
      '<span>'+esc(p.name)+'</span>' +
      '<span class="pg-edit" title="Renomear" onclick="event.stopPropagation();renamePage('+i+')">&#9998;</span>' + del + '</div>';
  }).join('');
  el.innerHTML = tabs + '<div class="ed-page-add" onclick="addPage()">+ Page</div>';
}
function switchPage(i){ ed.cur=i; renderPageTabs(); renderCanvas(); updatePreview(); }
async function addPage(){
  var name = await askText({ title: 'New page', msg: 'e.g. Shop, Products, About, Contact.', placeholder: 'Shop', ok: 'Create page' }); if(!name) return;
  name = name.trim(); if(!name) return;
  var id = uniquePageId(slugify(name) || 'page');
  ed.pages.push(newPage(id, name, [ defaultBlock('heading'), defaultBlock('text') ]));
  ed.cur = ed.pages.length - 1;
  renderPageTabs(); renderCanvas(); updatePreview();
}
async function renamePage(i){
  var name = await askText({ title: 'Rename page', value: ed.pages[i].name, ok: 'Save' }); if(!name) return;
  ed.pages[i].name = name.trim() || ed.pages[i].name;
  renderPageTabs(); updatePreview();
}
async function deletePage(i){
  if(i===0){ toast('The home page cannot be deleted.'); return; }
  if(!await askConfirm('Delete the page "'+ed.pages[i].name+'"?')) return;
  ed.pages.splice(i,1);
  if(ed.cur>=ed.pages.length) ed.cur=ed.pages.length-1;
  renderPageTabs(); renderCanvas(); updatePreview();
}

function renderThemes() {
  document.getElementById('ed-themes').innerHTML = Object.keys(THEMES).map(function(id){
    var t = THEMES[id];
    return '<div class="ed-theme'+(ed.theme===id?' active':'')+'" title="'+t.name+'" style="background:'+t.bg+'" onclick="pickTheme(\''+id+'\')"><span style="background:'+t.primary+'"></span></div>';
  }).join('');
}
function pickTheme(id){ ed.theme=id; renderThemes(); updatePreview(); }

function renderPalette() {
  document.getElementById('ed-palette').innerHTML = PALETTE_BLOCKS.map(function(b){
    return '<div class="ed-pal-btn" onclick="addBlock(\''+b.type+'\')"><span>'+b.icon+'</span> '+b.label+'</div>';
  }).join('');
}

function blockLabel(type){
  var m = {hero:'Cover', heading:'Title', text:'Text', image:'Image', button:'Button', features:'Features', products:'Products', articles:'News', pricing:'Pricing', testimonials:'Testimonials', gallery:'Gallery', cta:'Call to action', contact:'Contact', divider:'Divider'};
  return m[type] || type;
}

function renderCanvas() {
  var el = document.getElementById('ed-canvas');
  var blocks = curBlocks();
  if (blocks.length === 0) { el.innerHTML = '<div class="ed-canvas-empty">Empty page. Add blocks from the panel on the left.</div>'; return; }
  el.innerHTML = blocks.map(function(b, i){ return blockCard(b, i); }).join('');
}

function blockCard(b, i) {
  var body = '';
  if (b.type === 'hero') {
    body = field('Title', b.title, i, 'title') + field('Subtitle', b.subtitle, i, 'subtitle') +
      '<div class="row2">' + field('Button text', b.button, i, 'button') + field('Button link', b.url, i, 'url') + '</div>';
  } else if (b.type === 'heading') { body = field('Title', b.text, i, 'text'); }
  else if (b.type === 'text') { body = area('Text', b.text, i, 'text'); }
  else if (b.type === 'image') { body = field('Image URL (https://...)', b.url, i, 'url') + field('Description', b.alt, i, 'alt'); }
  else if (b.type === 'button') { body = '<div class="row2">' + field('Text', b.text, i, 'text') + field('Link', b.url, i, 'url') + '</div>'; }
  else if (b.type === 'cta') {
    body = field('Title', b.title, i, 'title') + area('Text', b.text, i, 'text') +
      '<div class="row2">' + field('Button text', b.button, i, 'button') + field('Link', b.url, i, 'url') + '</div>';
  } else if (b.type === 'contact') {
    body = field('Title', b.title, i, 'title') +
      '<div class="row2">' + field('E-mail', b.email, i, 'email') + field('Phone', b.phone, i, 'phone') + '</div>' +
      '<div class="row2">' + field('WhatsApp (number)', b.whatsapp, i, 'whatsapp') + field('Address', b.address, i, 'address') + '</div>';
  } else if (b.type === 'divider') { body = '<div style="color:var(--text3);font-size:0.85em">Divider line (no options)</div>'; }
  else if (isListBlock(b.type)) { body = listBlockBody(b, i); }
  return '<div class="ed-card">' +
    '<div class="ed-card-head"><span class="ed-card-type">'+blockLabel(b.type)+'</span>' +
      '<div class="ed-card-tools">' +
        '<button class="ed-tool" onclick="moveBlock('+i+',-1)" title="Subir">&uarr;</button>' +
        '<button class="ed-tool" onclick="moveBlock('+i+',1)" title="Descer">&darr;</button>' +
        '<button class="ed-tool del" onclick="delBlock('+i+')" title="Remove">&#128465;</button>' +
      '</div></div>' +
    '<div class="ed-card-body">'+body+'</div></div>';
}

function listBlockBody(b, i) {
  var head = '';
  if (b.type === 'products') head = field('Section title', b.title, i, 'title') + field('Currency ($, EUR...)', b.currency, i, 'currency');
  else if (b.type !== 'features') head = field('Section title', b.title, i, 'title');
  var items = (b.items||[]).map(function(it, j){
    return '<div class="ed-item"><button class="ed-item-rm" onclick="rmItem('+i+','+j+')" title="Remove">&times;</button>' +
      '<div class="ed-item-n">'+itemName(b.type)+' '+(j+1)+'</div>' + itemFields(b.type, it, i, j) + '</div>';
  }).join('');
  return head + '<div class="ed-items">'+items+'</div><button class="ed-mini-btn" onclick="addItem('+i+')">+ Add '+itemName(b.type)+'</button>';
}

function itemFields(type, it, bi, ii) {
  if (type === 'features') return iField('Icon (emoji)', it.icon, bi, ii, 'icon') + iField('Title', it.title, bi, ii, 'title') + iField('Text', it.text, bi, ii, 'text');
  if (type === 'products') return iField('Image URL', it.img, bi, ii, 'img') + iField('Name', it.name, bi, ii, 'name') + '<div class="row2">' + iField('Price', it.price, bi, ii, 'price') + iField('Button text', it.label, bi, ii, 'label') + '</div>' + iField('Description', it.desc, bi, ii, 'desc') + iField('Purchase link', it.url, bi, ii, 'url');
  if (type === 'articles') return iField('Image URL', it.img, bi, ii, 'img') + '<div class="row2">' + iField('Category', it.cat, bi, ii, 'cat') + iField('Date', it.date, bi, ii, 'date') + '</div>' + iField('Title', it.title, bi, ii, 'title') + iArea('Summary', it.excerpt, bi, ii, 'excerpt') + iField('Link', it.url, bi, ii, 'url');
  if (type === 'pricing') return iField('Plan', it.plan, bi, ii, 'plan') + '<div class="row2">' + iField('Price', it.price, bi, ii, 'price') + iField('Period', it.period, bi, ii, 'period') + '</div>' + iArea('Features (one per line)', it.feats, bi, ii, 'feats') + '<div class="row2">' + iField('Button text', it.button, bi, ii, 'button') + iField('Link', it.url, bi, ii, 'url') + '</div>' + iCheck('Highlight this plan', it.featured, bi, ii, 'featured');
  if (type === 'testimonials') return iArea('Testimonial', it.quote, bi, ii, 'quote') + '<div class="row2">' + iField('Author', it.author, bi, ii, 'author') + iField('Role', it.role, bi, ii, 'role') + '</div>';
  if (type === 'gallery') return iField('Image URL', it.url, bi, ii, 'url');
  return '';
}

function field(label, val, i, key) {
  return '<div><label class="ed-label">'+label+'</label><input class="ed-input" value="'+attr(val)+'" oninput="setField('+i+',\''+key+'\',this.value)"></div>';
}
function area(label, val, i, key) {
  return '<div><label class="ed-label">'+label+'</label><textarea class="ed-input" oninput="setField('+i+',\''+key+'\',this.value)">'+esc(val)+'</textarea></div>';
}
function iField(label, val, bi, ii, key) {
  return '<input class="ed-input" placeholder="'+label+'" value="'+attr(val)+'" oninput="setItem('+bi+','+ii+',\''+key+'\',this.value)">';
}
function iArea(label, val, bi, ii, key) {
  return '<textarea class="ed-input" placeholder="'+label+'" oninput="setItem('+bi+','+ii+',\''+key+'\',this.value)">'+esc(val)+'</textarea>';
}
function iCheck(label, val, bi, ii, key) {
  return '<label class="ed-check"><input type="checkbox" '+(val?'checked':'')+' onchange="setItemBool('+bi+','+ii+',\''+key+'\',this.checked)"> '+label+'</label>';
}

function setField(i, key, val){ curBlocks()[i][key] = val; schedulePreview(); if(key==='name'){} }
function setItem(bi, ii, key, val){ curBlocks()[bi].items[ii][key] = val; schedulePreview(); }
function setItemBool(bi, ii, key, val){ curBlocks()[bi].items[ii][key] = val; schedulePreview(); }
function addItem(bi){ var b = curBlocks()[bi]; if(!b.items) b.items=[]; b.items.push(defaultItem(b.type)); renderCanvas(); updatePreview(); }
function rmItem(bi, ii){ curBlocks()[bi].items.splice(ii,1); renderCanvas(); updatePreview(); }
function addBlock(type){ curBlocks().push(defaultBlock(type)); renderCanvas(); updatePreview(); }
function delBlock(i){ curBlocks().splice(i,1); renderCanvas(); updatePreview(); }
function moveBlock(i, dir){
  var bl = curBlocks(); var j = i + dir; if (j < 0 || j >= bl.length) return;
  var tmp = bl[i]; bl[i] = bl[j]; bl[j] = tmp;
  renderCanvas(); updatePreview();
}

function schedulePreview(){ clearTimeout(edPreviewTimer); edPreviewTimer = setTimeout(updatePreview, 350); }
function updatePreview(){ document.getElementById('ed-frame').srcdoc = renderPageHTML(curPage(), true); }

// Inline editing: receive edits/selections from the preview iframe
var _inlineTimer = null;
window.addEventListener('message', function(ev){
  var m = ev.data || {};
  if (typeof m.s9ed === 'string') applyInlineEdit(m.s9ed, m.val);
  else if (typeof m.s9sel === 'number') selectBlockCard(m.s9sel);
});
function applyInlineEdit(spec, val){
  var c = spec.indexOf(':'); if (c < 0) return;
  var path = spec.slice(0, c), field = spec.slice(c+1);
  var blocks = curBlocks();
  if (path.indexOf('.') >= 0) {
    var pp = path.split('.'); var bi = +pp[0], ii = +pp[1];
    if (blocks[bi] && blocks[bi].items && blocks[bi].items[ii]) blocks[bi].items[ii][field] = val;
  } else {
    var b = +path; if (blocks[b]) blocks[b][field] = val;
  }
  clearTimeout(_inlineTimer); _inlineTimer = setTimeout(renderCanvas, 600);
}
function selectBlockCard(bi){
  var cards = document.querySelectorAll('#ed-canvas .ed-card');
  cards.forEach(function(c){ c.classList.remove('ed-sel'); });
  if (cards[bi]) { cards[bi].classList.add('ed-sel'); cards[bi].scrollIntoView({behavior:'smooth', block:'center'}); }
}

function toggleDevice(){
  edDevice = (edDevice === 'desktop') ? 'mobile' : 'desktop';
  document.getElementById('ed-frame-wrap').classList.toggle('mobile', edDevice === 'mobile');
  document.getElementById('ed-devtoggle').innerHTML = (edDevice==='desktop') ? '🖥 Desktop' : '📱 Mobile';
}

async function publishEditor(){
  var btn = document.getElementById('ed-publish');
  btn.disabled = true; var old = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span> Publishing...';
  var files = ed.pages.map(function(p){ return { path: fileFor(p), html: renderPageHTML(p, false) }; });
  var source = { brand: ed.brand, theme: ed.theme, font: ed.font, social: ed.social, pages: ed.pages };
  try {
    var res = await fetch(API + '/api/publish/' + ed.site, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: source, files: files })
    });
    var data = await res.json();
    if (data.ok) { btn.innerHTML = '✓ Published'; setTimeout(function(){ btn.disabled=false; btn.innerHTML=old; }, 1600); }
    else { toast('Could not publish: ' + (data.msg||'')); btn.disabled=false; btn.innerHTML=old; }
  } catch(e) { toast('Connection error: ' + e.message); btn.disabled=false; btn.innerHTML=old; }
}

function navbarHTML(){
  var brand = esc(ed.brand || ed.site || 'Site');
  var links = ed.pages.map(function(p){ return '<a href="'+fileFor(p)+'">'+esc(p.name)+'</a>'; }).join('');
  return '<header class="s9-nav"><div class="s9-nav-in"><a class="s9-brand" href="index.html">'+brand+'</a><nav class="s9-menu">'+links+'</nav></div></header>';
}
function footerHTML(){
  var brand = esc(ed.brand || ed.site || 'Site');
  var s = ed.social || {};
  var soc = '';
  if (s.whatsapp) soc += '<a href="https://wa.me/'+s.whatsapp.replace(/\D/g,'')+'">WhatsApp</a>';
  if (s.instagram) soc += '<a href="https://instagram.com/'+attr(s.instagram.replace(/^@/,''))+'">Instagram</a>';
  if (s.email) soc += '<a href="mailto:'+attr(s.email)+'">E-mail</a>';
  var links = ed.pages.map(function(p){ return '<a href="'+fileFor(p)+'">'+esc(p.name)+'</a>'; }).join('');
  return '<footer class="s9-foot"><div class="s9-foot-in">' +
    '<div class="s9-foot-col"><div class="s9-foot-brand">'+brand+'</div><div class="s9-foot-soc">'+soc+'</div></div>' +
    '<nav class="s9-foot-links">'+links+'</nav></div>' +
    '<div class="s9-foot-bottom">Built with <strong>SevenNine.hidra</strong> &middot; HidraNet network</div></footer>';
}

// Inline edit helpers (only active in preview/edit mode)
function ce(em){ return em ? ' contenteditable="true" spellcheck="false"' : ''; }
function de(em, spec){ return em ? (' data-ed="'+spec+'"') : ''; }
function db(em, bi){ return em ? (' data-block="'+bi+'"') : ''; }
function secTitle(b, em, bi){ return b.title ? '<h2 class="s9-sec-h"'+ce(em)+de(em,bi+':title')+'>'+esc(b.title)+'</h2>' : ''; }

function editorCSS(){
  return '[data-ed]{outline:1px dashed transparent;border-radius:5px;transition:outline .12s,background .12s;cursor:text}' +
    '[data-ed]:hover{outline-color:rgba(0,180,160,.6)}' +
    '[data-ed]:focus{outline:2px solid #00b4a0;background:rgba(0,180,160,.10)}' +
    '[data-block]{position:relative}' +
    '[data-block]:hover{box-shadow:inset 0 0 0 2px rgba(0,180,160,.32)}';
}
function editorScript(){
  return '<scr'+'ipt>(function(){function s(o){parent.postMessage(o,"*");}' +
    'document.querySelectorAll("[data-ed]").forEach(function(el){' +
      'el.addEventListener("input",function(){s({s9ed:el.getAttribute("data-ed"),val:el.innerText});});' +
      'el.addEventListener("keydown",function(e){if(e.key==="Enter"&&el.getAttribute("data-multi")!=="1"){e.preventDefault();el.blur();}});' +
    '});' +
    'document.addEventListener("click",function(e){var a=e.target.closest("a");if(a)e.preventDefault();' +
      'var b=e.target.closest("[data-block]");if(b)s({s9sel:parseInt(b.getAttribute("data-block"),10)});},true);' +
  '})();</scr'+'ipt>';
}

function renderPageHTML(page, em){
  var t = THEMES[normTheme(ed.theme)] || THEMES.hidra;
  var font = FONTS[ed.font] || FONTS.system;
  var title = esc((ed.brand ? ed.brand + ' — ' : '') + (page.name || 'Site'));
  var body = (page.blocks||[]).map(function(b,i){ return blockHTML(b, t, em, i); }).join('\n');
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>' + title + '</title><style>' + siteCSS(t, font) + (em ? editorCSS() : '') + '</style></head><body>' +
    navbarHTML() + body + footerHTML() + (em ? editorScript() : '') + '</body></html>';
}

function siteCSS(t, font){
  var btnText = (t.mode==='light' ? '#fff' : '#06060b');
  var navBg = (t.mode==='light' ? 'rgba(255,255,255,0.85)' : 'rgba(10,10,18,0.85)');
  var shadow = (t.mode==='light' ? '0 6px 24px rgba(20,30,60,0.08)' : '0 6px 24px rgba(0,0,0,0.35)');
  return '*{margin:0;padding:0;box-sizing:border-box}' +
    'body{font-family:' + font + ';background:' + t.bg + ';color:' + t.text + ';line-height:1.6}' +
    'img{max-width:100%;display:block}' +
    'a{color:inherit}' +
    /* nav */
    '.s9-nav{position:sticky;top:0;z-index:50;background:' + navBg + ';backdrop-filter:blur(10px);border-bottom:1px solid ' + t.border + '}' +
    '.s9-nav-in{max-width:1100px;margin:0 auto;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}' +
    '.s9-brand{font-weight:800;font-size:1.25em;color:' + t.primary + ';text-decoration:none;letter-spacing:-0.5px}' +
    '.s9-menu{display:flex;gap:6px;flex-wrap:wrap}' +
    '.s9-menu a{color:' + t.muted + ';text-decoration:none;font-size:0.92em;font-weight:600;padding:7px 13px;border-radius:8px;transition:.15s}' +
    '.s9-menu a:hover{color:' + t.primary + ';background:' + t.card + '}' +
    /* hero */
    '.s9-hero{text-align:center;padding:80px 24px 72px;background:linear-gradient(135deg,' + t.card + ',' + t.bg + ')}' +
    '.s9-hero h1{font-size:clamp(2em,5vw,3.5em);background:linear-gradient(135deg,' + t.primary + ',' + t.primary2 + ');-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:16px;letter-spacing:-1px}' +
    '.s9-hero p{color:' + t.muted + ';font-size:1.2em;max-width:640px;margin:0 auto 26px}' +
    /* generic section */
    '.s9-sec{max-width:1100px;margin:0 auto;padding:48px 24px}' +
    '.s9-sec-h{text-align:center;font-size:1.9em;color:' + t.text + ';margin-bottom:32px;letter-spacing:-0.5px}' +
    '.s9-wrap{max-width:760px;margin:0 auto;padding:24px}' +
    '.s9-h{font-size:1.8em;color:' + t.text + ';margin:6px 0 12px}' +
    '.s9-p{color:' + t.muted + ';font-size:1.06em;white-space:pre-wrap}' +
    '.s9-btn{display:inline-block;padding:13px 30px;background:' + t.primary + ';color:' + btnText + ';border-radius:10px;font-weight:700;text-decoration:none;margin:8px 0;transition:.15s}' +
    '.s9-btn:hover{background:' + t.primary2 + ';transform:translateY(-1px)}' +
    '.s9-btn-sm{padding:9px 18px;font-size:0.9em}' +
    '.s9-center{text-align:center}' +
    '.s9-img{margin:16px auto;border-radius:14px;border:1px solid ' + t.border + ';box-shadow:' + shadow + '}' +
    '.s9-ph{display:flex;align-items:center;justify-content:center;color:' + t.muted + ';background:' + t.card + ';border:1px dashed ' + t.border + '}' +
    '.s9-imgph{margin:16px auto;max-width:720px;height:220px;border-radius:14px}' +
    '.s9-hr{border:none;border-top:1px solid ' + t.border + ';margin:8px auto;max-width:1100px}' +
    /* features */
    '.s9-feats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:20px;max-width:1100px;margin:0 auto;padding:48px 24px}' +
    '.s9-feat{background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:16px;padding:30px 24px;text-align:center}' +
    '.s9-feat .ic{font-size:2.1em;margin-bottom:12px}' +
    '.s9-feat h3{color:' + t.primary + ';margin-bottom:8px;font-size:1.15em}' +
    '.s9-feat p{color:' + t.muted + ';font-size:0.95em}' +
    /* products */
    '.s9-prod-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:22px}' +
    '.s9-prod{background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:16px;overflow:hidden;display:flex;flex-direction:column;transition:.18s}' +
    '.s9-prod:hover{transform:translateY(-4px);box-shadow:' + shadow + '}' +
    '.s9-prod-img{width:100%;height:190px;object-fit:cover}' +
    'div.s9-prod-img{height:190px}' +
    '.s9-prod-b{padding:18px;display:flex;flex-direction:column;gap:8px;flex:1}' +
    '.s9-prod-b h3{font-size:1.1em;color:' + t.text + '}' +
    '.s9-price{font-size:1.3em;font-weight:800;color:' + t.primary + '}' +
    '.s9-prod-b p{color:' + t.muted + ';font-size:0.9em;flex:1}' +
    /* articles */
    '.s9-art-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:22px}' +
    '.s9-art{background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:16px;overflow:hidden;text-decoration:none;color:inherit;display:flex;flex-direction:column;transition:.18s}' +
    '.s9-art:hover{transform:translateY(-4px);box-shadow:' + shadow + '}' +
    '.s9-art-img{width:100%;height:170px;object-fit:cover}' +
    'div.s9-art-img{height:170px}' +
    '.s9-art-b{padding:18px;display:flex;flex-direction:column;gap:6px}' +
    '.s9-cat{align-self:flex-start;background:' + t.primary + ';color:' + btnText + ';font-size:0.7em;font-weight:700;padding:3px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:0.5px}' +
    '.s9-art-b h3{font-size:1.15em;color:' + t.text + ';line-height:1.3}' +
    '.s9-date{color:' + t.muted + ';font-size:0.78em}' +
    '.s9-art-b p{color:' + t.muted + ';font-size:0.92em}' +
    /* pricing */
    '.s9-price-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:22px;align-items:start}' +
    '.s9-plan{background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:18px;padding:30px 24px;text-align:center}' +
    '.s9-plan.feat{border-color:' + t.primary + ';border-width:2px;transform:scale(1.03)}' +
    '.s9-plan-name{font-size:1.2em;font-weight:700;margin-bottom:10px}' +
    '.s9-plan-price{font-size:2.4em;font-weight:800;color:' + t.primary + ';margin-bottom:4px}' +
    '.s9-plan-price span{font-size:0.4em;color:' + t.muted + ';font-weight:600}' +
    '.s9-plan ul{list-style:none;margin:18px 0;text-align:left;display:flex;flex-direction:column;gap:9px}' +
    '.s9-plan li{color:' + t.muted + ';font-size:0.95em;padding-left:24px;position:relative}' +
    '.s9-plan li:before{content:"✓";position:absolute;left:0;color:' + t.primary + ';font-weight:800}' +
    /* testimonials */
    '.s9-quote-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:22px}' +
    '.s9-quote{background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:16px;padding:28px}' +
    '.s9-quote p{font-size:1.05em;font-style:italic;margin-bottom:14px;color:' + t.text + '}' +
    '.s9-quote-a{font-weight:700;color:' + t.primary + '}' +
    '.s9-quote-r{color:' + t.muted + ';font-size:0.85em}' +
    /* gallery */
    '.s9-gal{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}' +
    '.s9-gal img,.s9-gal .s9-ph{width:100%;height:200px;object-fit:cover;border-radius:12px}' +
    /* cta */
    '.s9-cta{text-align:center;padding:64px 24px;margin:0;background:linear-gradient(135deg,' + t.primary + ',' + t.primary2 + ')}' +
    '.s9-cta h2{color:' + btnText + ';font-size:2em;margin-bottom:12px}' +
    '.s9-cta p{color:' + btnText + ';opacity:0.9;margin-bottom:22px;font-size:1.1em}' +
    '.s9-cta .s9-btn{background:' + t.bg + ';color:' + t.primary + '}' +
    '.s9-cta .s9-btn:hover{background:' + t.card + '}' +
    /* contact */
    '.s9-contact{max-width:520px;margin:0 auto;background:' + t.card + ';border:1px solid ' + t.border + ';border-radius:16px;padding:32px;text-align:left;display:flex;flex-direction:column;gap:12px}' +
    '.s9-cd{color:' + t.muted + '}' +
    '.s9-cd b{color:' + t.text + '}' +
    /* footer */
    '.s9-foot{border-top:1px solid ' + t.border + ';margin-top:24px;background:' + t.card + '}' +
    '.s9-foot-in{max-width:1100px;margin:0 auto;padding:40px 24px;display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap}' +
    '.s9-foot-brand{font-weight:800;font-size:1.2em;color:' + t.primary + ';margin-bottom:10px}' +
    '.s9-foot-soc{display:flex;gap:14px;flex-wrap:wrap}' +
    '.s9-foot-soc a{color:' + t.muted + ';text-decoration:none;font-size:0.9em}' +
    '.s9-foot-soc a:hover{color:' + t.primary + '}' +
    '.s9-foot-links{display:flex;flex-direction:column;gap:8px}' +
    '.s9-foot-links a{color:' + t.muted + ';text-decoration:none;font-size:0.9em}' +
    '.s9-foot-links a:hover{color:' + t.primary + '}' +
    '.s9-foot-bottom{text-align:center;padding:18px;color:' + t.muted + ';font-size:0.8em;border-top:1px solid ' + t.border + '}' +
    '.s9-foot-bottom strong{color:' + t.primary + '}';
}

function imgOr(url, cls, alt, ph){
  if (url && /^(https?:|\/)/i.test(url)) return '<img class="'+cls+'" src="'+safeUrl(url)+'" alt="'+attr(alt||'')+'">';
  return '<div class="'+cls+' s9-ph">'+esc(ph||'Image')+'</div>';
}

function blockHTML(b, t, em, bi){
  if (b.type === 'hero') {
    var btn = b.button ? '<a class="s9-btn" href="' + safeUrl(b.url) + '"'+ce(em)+de(em,bi+':button')+'>' + esc(b.button) + '</a>' : '';
    return '<section class="s9-hero"'+db(em,bi)+'><div><h1'+ce(em)+de(em,bi+':title')+'>' + esc(b.title) + '</h1><p'+ce(em)+de(em,bi+':subtitle')+' data-multi="1">' + esc(b.subtitle) + '</p>' + btn + '</div></section>';
  }
  if (b.type === 'heading') return '<div class="s9-wrap"'+db(em,bi)+'><h2 class="s9-h"'+ce(em)+de(em,bi+':text')+'>' + esc(b.text) + '</h2></div>';
  if (b.type === 'text') return '<div class="s9-wrap"'+db(em,bi)+'><p class="s9-p"'+ce(em)+de(em,bi+':text')+' data-multi="1">' + esc(b.text) + '</p></div>';
  if (b.type === 'image') {
    var inner = (b.url && /^(https?:|\/)/i.test(b.url)) ? '<img class="s9-img" src="' + safeUrl(b.url) + '" alt="' + attr(b.alt) + '">' : '<div class="s9-img s9-imgph s9-ph">' + (esc(b.alt) || 'Image') + '</div>';
    return '<div class="s9-wrap s9-center"'+db(em,bi)+'>'+inner+'</div>';
  }
  if (b.type === 'button') return '<div class="s9-wrap s9-center"'+db(em,bi)+'><a class="s9-btn" href="' + safeUrl(b.url) + '"'+ce(em)+de(em,bi+':text')+'>' + esc(b.text) + '</a></div>';
  if (b.type === 'features') {
    var items = (b.items||[]).map(function(it,ii){
      return '<div class="s9-feat"><div class="ic">' + esc(it.icon) + '</div><h3'+ce(em)+de(em,bi+'.'+ii+':title')+'>' + esc(it.title) + '</h3><p'+ce(em)+de(em,bi+'.'+ii+':text')+'>' + esc(it.text) + '</p></div>';
    }).join('');
    return '<section class="s9-feats"'+db(em,bi)+'>' + items + '</section>';
  }
  if (b.type === 'products') {
    var cards = (b.items||[]).map(function(it,ii){
      var buy = it.url ? '<a class="s9-btn s9-btn-sm" href="'+safeUrl(it.url)+'"'+ce(em)+de(em,bi+'.'+ii+':label')+'>'+esc(it.label||'Buy')+'</a>' : '';
      return '<div class="s9-prod">' + imgOr(it.img,'s9-prod-img',it.name,'No image') +
        '<div class="s9-prod-b"><h3'+ce(em)+de(em,bi+'.'+ii+':name')+'>'+esc(it.name)+'</h3><div class="s9-price">'+esc(b.currency||'')+' <span'+ce(em)+de(em,bi+'.'+ii+':price')+'>'+esc(it.price||'')+'</span></div><p'+ce(em)+de(em,bi+'.'+ii+':desc')+'>'+esc(it.desc)+'</p>'+buy+'</div></div>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-prod-grid">'+cards+'</div></section>';
  }
  if (b.type === 'articles') {
    var arts = (b.items||[]).map(function(it,ii){
      return '<a class="s9-art" href="'+safeUrl(it.url)+'">' + imgOr(it.img,'s9-art-img',it.title,'No image') +
        '<div class="s9-art-b"><span class="s9-cat">'+esc(it.cat||'General')+'</span><h3'+ce(em)+de(em,bi+'.'+ii+':title')+'>'+esc(it.title)+'</h3><div class="s9-date">'+esc(it.date)+'</div><p'+ce(em)+de(em,bi+'.'+ii+':excerpt')+'>'+esc(it.excerpt)+'</p></div></a>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-art-grid">'+arts+'</div></section>';
  }
  if (b.type === 'pricing') {
    var plans = (b.items||[]).map(function(it,ii){
      var feats = (it.feats||'').split('\n').filter(function(x){return x.trim();}).map(function(f){ return '<li>'+esc(f)+'</li>'; }).join('');
      var bt = it.url ? '<a class="s9-btn" href="'+safeUrl(it.url)+'"'+ce(em)+de(em,bi+'.'+ii+':button')+'>'+esc(it.button||'Choose')+'</a>' : '';
      return '<div class="s9-plan'+(it.featured?' feat':'')+'"><div class="s9-plan-name"'+ce(em)+de(em,bi+'.'+ii+':plan')+'>'+esc(it.plan)+'</div><div class="s9-plan-price"><span'+ce(em)+de(em,bi+'.'+ii+':price')+'>'+esc(it.price)+'</span><span>'+esc(it.period||'')+'</span></div><ul>'+feats+'</ul>'+bt+'</div>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-price-grid">'+plans+'</div></section>';
  }
  if (b.type === 'testimonials') {
    var qs = (b.items||[]).map(function(it,ii){
      return '<div class="s9-quote"><p'+ce(em)+de(em,bi+'.'+ii+':quote')+' data-multi="1">'+esc(it.quote)+'</p><div class="s9-quote-a"'+ce(em)+de(em,bi+'.'+ii+':author')+'>'+esc(it.author)+'</div><div class="s9-quote-r"'+ce(em)+de(em,bi+'.'+ii+':role')+'>'+esc(it.role)+'</div></div>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-quote-grid">'+qs+'</div></section>';
  }
  if (b.type === 'gallery') {
    var imgs = (b.items||[]).map(function(it){ return imgOr(it.url,'','','Image'); }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-gal">'+imgs+'</div></section>';
  }
  if (b.type === 'cta') {
    var cb = b.button ? '<a class="s9-btn" href="'+safeUrl(b.url)+'"'+ce(em)+de(em,bi+':button')+'>'+esc(b.button)+'</a>' : '';
    return '<section class="s9-cta"'+db(em,bi)+'><h2'+ce(em)+de(em,bi+':title')+'>'+esc(b.title)+'</h2><p'+ce(em)+de(em,bi+':text')+' data-multi="1">'+esc(b.text)+'</p>'+cb+'</section>';
  }
  if (b.type === 'contact') {
    var rows = '';
    if (b.email) rows += '<div class="s9-cd"><b>E-mail:</b> <a href="mailto:'+attr(b.email)+'">'+esc(b.email)+'</a></div>';
    if (b.phone) rows += '<div class="s9-cd"><b>Phone:</b> '+esc(b.phone)+'</div>';
    if (b.whatsapp) rows += '<div class="s9-cd"><b>WhatsApp:</b> <a href="https://wa.me/'+b.whatsapp.replace(/\D/g,'')+'">'+esc(b.whatsapp)+'</a></div>';
    if (b.address) rows += '<div class="s9-cd"><b>Address:</b> '+esc(b.address)+'</div>';
    return '<section class="s9-sec"'+db(em,bi)+'><h2 class="s9-sec-h"'+ce(em)+de(em,bi+':title')+'>'+esc(b.title)+'</h2><div class="s9-contact">'+rows+'</div></section>';
  }
  if (b.type === 'divider') return '<hr class="s9-hr"'+db(em,bi)+'>';
  return '';
}

function esc(s){ s=(s==null?'':String(s)); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function attr(s){ s=(s==null?'':String(s)); return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
function safeUrl(u){ u=(u==null?'#':String(u).trim()); if(/^(https?:|mailto:|#|\/)/i.test(u)) return attr(u); return '#'; }

// ── Own modal (prompt/confirm/alert do not work in Electron) ──
function askText(opts){
  return new Promise(function(resolve){
    var m=document.getElementById('s9-modal');
    document.getElementById('s9-modal-title').textContent=opts.title||'';
    document.getElementById('s9-modal-msg').textContent=opts.msg||'';
    var inp=document.getElementById('s9-modal-input');
    inp.style.display=''; inp.placeholder=opts.placeholder||''; inp.value=opts.value||'';
    document.getElementById('s9-modal-ok').textContent=opts.ok||'Confirm';
    m.classList.remove('hidden');
    setTimeout(function(){ inp.focus(); inp.select(); }, 40);
    var ok=document.getElementById('s9-modal-ok'), cancel=document.getElementById('s9-modal-cancel');
    function done(v){ m.classList.add('hidden'); ok.onclick=null; cancel.onclick=null; inp.onkeydown=null; resolve(v); }
    ok.onclick=function(){ var v=inp.value.trim(); done(v||null); };
    cancel.onclick=function(){ done(null); };
    inp.onkeydown=function(e){ if(e.key==='Enter'){ var v=inp.value.trim(); done(v||null); } else if(e.key==='Escape'){ done(null); } };
  });
}
function askConfirm(message){
  return new Promise(function(resolve){
    var m=document.getElementById('s9-modal');
    document.getElementById('s9-modal-title').textContent='Confirm';
    document.getElementById('s9-modal-msg').textContent=message;
    var inp=document.getElementById('s9-modal-input'); inp.style.display='none';
    document.getElementById('s9-modal-ok').textContent='Delete';
    m.classList.remove('hidden');
    var ok=document.getElementById('s9-modal-ok'), cancel=document.getElementById('s9-modal-cancel');
    function done(v){ m.classList.add('hidden'); inp.style.display=''; ok.onclick=null; cancel.onclick=null; resolve(v); }
    ok.onclick=function(){ done(true); };
    cancel.onclick=function(){ done(false); };
  });
}
function toast(msg){
  var t=document.getElementById('s9-toast'); if(!t) return;
  t.textContent=msg; t.classList.add('show');
  clearTimeout(t._t); t._t=setTimeout(function(){ t.classList.remove('show'); }, 3500);
}

// Auto-refresh
setInterval(loadSites, 10000);
"##;

// ─── Terms of Use ────────────────────────────────────────────────────────────

/// Served at `/terms`. The builder's page links here, and a site is created
/// only once its owner has ticked the box that says they accept it.
const TERMS_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SevenNine.hidra — Terms of Use</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e8; margin: 0; padding: 40px 20px; line-height: 1.65; }
    main { max-width: 720px; margin: 0 auto; }
    h1 { color: #00d4aa; font-size: 1.6em; margin-bottom: 4px; }
    h2 { color: #00d4aa; font-size: 1.1em; margin-top: 28px; }
    p, li { color: #c4c4d4; font-size: 0.95em; }
    .muted { color: #8888a0; font-size: 0.85em; }
    a { color: #00d4aa; }
  </style>
</head>
<body>
<main>
  <h1>SevenNine.hidra — Terms of Use</h1>
  <p class="muted">Applies to every site created with the SevenNine builder on the HidraNet network.</p>

  <h2>1. What SevenNine is</h2>
  <p>SevenNine is a tool that runs on your own computer. It lets you build a website and publish it on the HidraNet network under a <code>.hidra</code> address. Your site is stored and served from your machine. HidraNet does not host, review or keep a copy of it.</p>

  <h2>2. You are responsible for your site</h2>
  <p>You are the publisher of everything on your site: text, images, files, links and code. You must have the right to publish all of it. You are responsible for following the laws that apply to you and to your visitors.</p>

  <h2>3. What you may not publish</h2>
  <ul>
    <li>Sexual content involving minors, in any form.</li>
    <li>Content that incites violence or terrorism, or threatens a person.</li>
    <li>Malware, phishing pages, or anything built to deceive visitors or take over their devices or accounts.</li>
    <li>Other people's personal data published without their consent, including doxxing.</li>
    <li>Content that infringes copyright, trademarks or other rights you do not hold.</li>
    <li>The sale or promotion of illegal goods or services, including weapons, drugs and stolen data.</li>
    <li>Fraud, scams and impersonation of a person or an organisation.</li>
  </ul>

  <h2>4. Privacy</h2>
  <p>Visitors reach your site through onion circuits, so neither you nor they learn each other's network address from the visit. SevenNine does not show your visitors' identities and does not write site names, addresses or contents to its log. Do not use your site to collect visitors' personal data without telling them clearly.</p>

  <h2>5. Availability</h2>
  <p>Your site is online only while your HidraNet node is running and published on the network. If you delete a site, it stops being served from your machine, but copies other people already saved cannot be recalled. Keep your own backups: deleting a site cannot be undone.</p>

  <h2>6. Limits</h2>
  <p>Each file may be up to 5 MB, and a site published from the editor up to 5 MB in total. Only file types a web page uses are accepted (HTML, CSS, JavaScript, JSON, text, images, fonts, PDF, audio and video).</p>

  <h2>7. No warranty</h2>
  <p>SevenNine and HidraNet are provided as they are, without any warranty. The developers are not liable for content published by users, for loss of data, or for a site being unavailable.</p>

  <h2>8. Reporting abuse</h2>
  <p>If you find a <code>.hidra</code> site that breaks these terms, report it through the HidraNet community channels. Nodes and directories in the network may refuse to list or relay a site that breaks them.</p>

  <h2>9. Changes</h2>
  <p>These terms may change with new versions of SevenNine. The version shown here is the one that applies to the copy of SevenNine you are running.</p>

  <p class="muted"><a href="/">Back to SevenNine</a></p>
</main>
</body>
</html>"##;

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fresh data directory for one test, removed when dropped.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("sevennine-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Serve `manager` on an ephemeral loopback port and return the port.
    async fn serve(manager: Arc<SiteManager>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                tokio::spawn(handle_connection_pub(stream, manager.clone()));
            }
        });
        port
    }

    /// Send a raw request and return the whole raw reply.
    async fn raw(port: u16, request: &[u8]) -> String {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(request).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn get(path: &str, host: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
    }

    fn post_json(path: &str, body: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn multipart(site: &str, filename: &str, data: &[u8]) -> Vec<u8> {
        let boundary = "XBOUNDARYX";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut req = format!(
            "POST /api/upload/{site} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(&body);
        req
    }

    #[test]
    fn site_names_are_checked_everywhere() {
        assert_eq!(normalize_site_name(" My-Site_1 ").unwrap(), "my-site_1");
        for bad in ["..", ".", "", "a/b", "a\\b", "../keys", "%2e%2e", "a b", &"x".repeat(33)] {
            assert!(normalize_site_name(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn only_web_file_types_are_allowed() {
        for ok in ["index.html", "a.CSS", "app.js", "logo.png", "font.woff2", "doc.pdf"] {
            assert!(is_allowed_file(ok), "{ok}");
        }
        for bad in ["evil.exe", "run.sh", "x.php", "noext", ".png", "a.html.bat"] {
            assert!(!is_allowed_file(bad), "{bad}");
        }
    }

    #[test]
    fn hidra_host_labels() {
        assert_eq!(hidra_host_label("ABC.hidra:80").as_deref(), Some("abc"));
        assert_eq!(hidra_host_label("abc.hidra.").as_deref(), Some("abc"));
        assert_eq!(hidra_host_label("127.0.0.1:8084"), None);
        assert_eq!(hidra_host_label(".hidra"), None);
        assert_eq!(hidra_host_label("evil.com"), None);
    }

    #[tokio::test]
    async fn dot_dot_cannot_delete_read_or_write_the_data_dir() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.0.join("keys")).unwrap();
        std::fs::write(dir.0.join("keys/node.key"), b"k").unwrap();
        std::fs::write(dir.0.join("marker.txt"), b"TOPSECRET").unwrap();
        let mgr = SiteManager::new(&dir.0, 0);

        assert!(mgr.delete_site("..").await.is_err());
        assert!(mgr.serve_file("..", "marker.txt").await.is_none());
        assert!(mgr.upload_file("..", "x.txt", b"pwned").await.is_err());
        assert!(mgr.save_page("..", "<p>", &serde_json::Value::Null).await.is_err());
        assert!(mgr.publish_site("..", &serde_json::Value::Null, &[("index.html".into(), "x".into())]).await.is_err());
        assert!(mgr.load_page("..").is_none());

        assert!(dir.0.join("keys/node.key").exists(), "the keys must survive");
        assert!(dir.0.join("marker.txt").exists());
        assert!(!dir.0.join("x.txt").exists());
    }

    #[tokio::test]
    async fn the_same_over_http_with_raw_paths() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.0.join("keys")).unwrap();
        std::fs::write(dir.0.join("marker.txt"), b"TOPSECRET").unwrap();
        let port = serve(Arc::new(SiteManager::new(&dir.0, 0))).await;

        let del = raw(port, b"DELETE /api/sites/.. HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
        assert!(del.starts_with("HTTP/1.1 400"), "{del}");
        assert!(dir.0.join("keys").exists());
        for path in ["/sites/../marker.txt", "/sites/%2e%2e/marker.txt"] {
            let r = raw(port, &get(path, "127.0.0.1")).await;
            assert!(!r.contains("TOPSECRET"), "{path} leaked: {r}");
        }
    }

    #[tokio::test]
    async fn uploads_are_stored_whole_and_limits_are_enforced() {
        let dir = TempDir::new();
        let mgr = Arc::new(SiteManager::new(&dir.0, 0));
        mgr.create_site("demo").await.unwrap();
        let port = serve(mgr.clone()).await;

        // 900 KB: bigger than the old 512 KB read, which stored a stump.
        let data: Vec<u8> = (0..900_000u32).map(|i| (i % 251) as u8).collect();
        let r = raw(port, &multipart("demo", "big.js", &data)).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{}", &r[..r.len().min(200)]);
        assert_eq!(std::fs::read(dir.0.join("sites/demo/big.js")).unwrap(), data);

        let r = raw(port, &multipart("demo", "evil.exe", b"MZ")).await;
        assert!(r.starts_with("HTTP/1.1 400") && r.contains("File type not allowed"), "{r}");
        assert!(!dir.0.join("sites/demo/evil.exe").exists());

        // Over the limit: refused before the body is read, not truncated.
        let req = format!(
            "POST /api/upload/demo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let r = raw(port, req.as_bytes()).await;
        assert!(r.starts_with("HTTP/1.1 413"), "{r}");

        assert!(mgr.upload_file("demo", "huge.png", &vec![0u8; MAX_FILE_BYTES + 1]).await.is_err());
    }

    #[tokio::test]
    async fn creating_a_site_needs_the_terms_accepted() {
        let dir = TempDir::new();
        let port = serve(Arc::new(SiteManager::new(&dir.0, 0))).await;

        let r = raw(port, &post_json("/api/sites", r#"{"name":"demo"}"#)).await;
        assert!(r.starts_with("HTTP/1.1 400") && r.contains("Terms of Use"), "{r}");
        assert!(!dir.0.join("sites/demo").exists());

        let r = raw(port, &post_json("/api/sites", r#"{"name":"demo","accept_terms":true}"#)).await;
        assert!(r.starts_with("HTTP/1.1 201"), "{r}");

        let terms = raw(port, &get("/terms", "127.0.0.1")).await;
        assert!(terms.starts_with("HTTP/1.1 200") && terms.contains("Terms of Use"));
    }

    #[tokio::test]
    async fn sites_survive_a_restart_with_their_address() {
        let dir = TempDir::new();
        let created = SiteManager::new(&dir.0, 0).create_site("demo").await.unwrap();
        assert!(created.crypto_address.ends_with(".hidra") && created.crypto_address.len() == 46);

        // A new manager sees the site at once: loading is no longer deferred.
        let again = SiteManager::new(&dir.0, 0);
        let sites = again.list_sites().await;
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].crypto_address, created.crypto_address);
        assert!(again.serve_file("demo", "").await.is_some());
    }

    #[tokio::test]
    async fn a_network_visitor_can_read_a_site_and_nothing_else() {
        let dir = TempDir::new();
        let node = "0123456789abcdef0123456789abcdef01234567.hidra";
        let mgr = Arc::new(SiteManager::new(&dir.0, 0).with_network_address(node));
        let site = mgr.create_site("demo").await.unwrap();
        assert_eq!(site.network_address.as_deref(), Some(&*format!("http://{node}/sites/demo/")));
        let port = serve(mgr).await;

        // Was 403 for every visitor.
        let r = raw(port, &get("/sites/demo/", node)).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains("demo.hidra"));
        assert!(r.contains("Content-Security-Policy: sandbox"), "site pages need a policy");

        // The node's own address lists its sites.
        let r = raw(port, &get("/", node)).await;
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("/sites/demo/"), "{r}");

        // A site's own address serves it at the root.
        let r = raw(port, &get("/", &site.crypto_address)).await;
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("demo.hidra"), "{r}");

        // The builder and its API are not reachable from the network.
        for path in ["/api/sites", "/api/status", "/app.js", "/api/page/demo"] {
            let r = raw(port, &get(path, node)).await;
            assert!(!r.starts_with("HTTP/1.1 200") || !r.contains("\"sites\""), "{path}: {r}");
            assert!(!r.contains("const API"), "{path} served the builder");
        }
        let del = format!("DELETE /api/sites/demo HTTP/1.1\r\nHost: {node}\r\n\r\n");
        assert!(raw(port, del.as_bytes()).await.starts_with("HTTP/1.1 403"));
        assert!(dir.0.join("sites/demo").exists());
        let up = format!("POST /api/upload/demo HTTP/1.1\r\nHost: {node}\r\nContent-Length: 2\r\n\r\nhi");
        assert!(raw(port, up.as_bytes()).await.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn the_builder_still_refuses_other_web_pages() {
        let dir = TempDir::new();
        let mgr = Arc::new(SiteManager::new(&dir.0, 0));
        mgr.create_site("demo").await.unwrap();
        let port = serve(mgr).await;

        let r = raw(port, b"DELETE /api/sites/demo HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.com\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 403"));
        // A site page runs with an opaque origin, which sends this.
        let r = raw(port, b"DELETE /api/sites/demo HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: null\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 403"));
        assert!(dir.0.join("sites/demo").exists());

        let r = raw(port, &get("/api/status", "127.0.0.1")).await;
        assert!(r.contains("\"network\":false"), "{r}");
    }
}
