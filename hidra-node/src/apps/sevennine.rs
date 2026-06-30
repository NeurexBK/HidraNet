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

#[derive(Debug, Clone)]
pub struct DhtAnnouncement {
    pub service_hash: [u8; 20],
    pub service_pubkey: [u8; 32],
}

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

    fn _init(
        base_dir: &Path,
        dht_tx: Option<tokio::sync::mpsc::Sender<DhtAnnouncement>>,
        port: u16,
    ) -> Self {
        let sites_dir = base_dir.join("sites");
        std::fs::create_dir_all(&sites_dir).ok();

        let manager = Self {
            sites: Arc::new(RwLock::new(HashMap::new())),
            base_dir: base_dir.to_path_buf(),
            dht_tx,
            port,
        };

        // Load existing sites from disk (including signing keys)
        if let Ok(entries) = std::fs::read_dir(&sites_dir) {
            let rt_sites = manager.sites.clone();
            let mut sites_map = HashMap::new();

            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let site_path = entry.path();
                    let meta_path = site_path.join(".sevennine-meta.json");
                    if let Ok(data) = std::fs::read_to_string(&meta_path) {
                        if let Ok(info) = serde_json::from_str::<SiteInfo>(&data) {
                            let key_bytes = load_site_key(&site_path);
                            sites_map.insert(name.clone(), SiteRecord {
                                info,
                                signing_key_bytes: key_bytes,
                            });
                        }
                    }
                }
            }

            if !sites_map.is_empty() {
                let count = sites_map.len();
                tokio::spawn(async move {
                    let mut w = rt_sites.write().await;
                    *w = sites_map;
                });
                tracing::info!("loaded {} existing sites", count);
            }
        }

        manager
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
            let verifying_key = match VerifyingKey::from_bytes(&{
                let sk = SigningKey::from_bytes(&record.signing_key_bytes);
                let vk: VerifyingKey = (&sk).into();
                vk.to_bytes()
            }) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let pub_bytes = verifying_key.to_bytes();
            let full_hash = blake3::hash(&pub_bytes);
            let mut address_hash = [0u8; 20];
            address_hash.copy_from_slice(&full_hash.as_bytes()[..20]);

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
        let name = name.trim().to_lowercase();
        let site_dir = self.base_dir.join("sites").join(&name);
        site_dir.exists() && site_dir.join(".sevennine-meta.json").exists()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub async fn create_site(&self, name: &str) -> Result<SiteInfo, String> {
        let name = name.trim().to_lowercase();

        if name.is_empty() || name.len() > 32 {
            return Err("Nome deve ter entre 1 e 32 caracteres".into());
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("Nome pode conter apenas letras, números, - e _".into());
        }

        {
            let sites = self.sites.read().await;
            if sites.contains_key(&name) {
                return Err(format!("O nome '{}' já está em uso", name));
            }
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let pub_bytes = verifying_key.to_bytes();

        // Derive .hidra address: blake3(pubkey)[..20] as hex
        let full_hash = blake3::hash(&pub_bytes);
        let mut address_hash = [0u8; 20];
        address_hash.copy_from_slice(&full_hash.as_bytes()[..20]);
        let address_hex: String = address_hash.iter().map(|b| format!("{b:02x}")).collect();

        // Human-friendly name maps to the cryptographic address
        let hidra_address = format!("{}.hidra", name);
        let crypto_address = format!("{}.hidra", address_hex);
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);

        let site_dir = self.base_dir.join("sites").join(&name);
        std::fs::create_dir_all(&site_dir).map_err(|e| format!("Erro ao criar pasta: {}", e))?;

        let default_html = generate_default_page(&name);
        std::fs::write(site_dir.join("index.html"), default_html.as_bytes())
            .map_err(|e| format!("Erro ao salvar index.html: {}", e))?;

        let info = SiteInfo {
            name: name.clone(),
            hidra_address: hidra_address.clone(),
            public_key: public_key_b64,
            created_at: Utc::now().to_rfc3339(),
            files: vec!["index.html".into()],
            size_bytes: default_html.len() as u64,
            visits: 0,
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
                    site = %name,
                    address = %crypto_address,
                    "site published to DHT"
                );
            }
        }

        tracing::info!("site created: {} -> {} (crypto: {})", name, hidra_address, crypto_address);
        Ok(info)
    }

    pub async fn upload_file(&self, site_name: &str, filename: &str, content: &[u8]) -> Result<SiteInfo, String> {
        let site_name = site_name.trim().to_lowercase();

        let safe_name = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nome de arquivo inválido")?
            .to_string();

        if safe_name.starts_with('.') {
            return Err("Arquivos ocultos não são permitidos".into());
        }

        let site_dir = self.base_dir.join("sites").join(&site_name);
        if !site_dir.exists() {
            return Err(format!("Site '{}' não existe", site_name));
        }

        std::fs::write(site_dir.join(&safe_name), content)
            .map_err(|e| format!("Erro ao salvar arquivo: {}", e))?;

        let mut total_size: u64 = 0;
        let mut file_list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&site_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with('.') { continue; }
                file_list.push(fname);
                total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        file_list.sort();

        {
            let mut sites = self.sites.write().await;
            if let Some(record) = sites.get_mut(&site_name) {
                record.info.files = file_list;
                record.info.size_bytes = total_size;

                let meta_json = serde_json::to_string_pretty(&record.info).unwrap_or_default();
                std::fs::write(site_dir.join(".sevennine-meta.json"), meta_json.as_bytes()).ok();

                return Ok(record.info.clone());
            }
        }

        Err("Site não encontrado".into())
    }

    pub async fn delete_site(&self, name: &str) -> Result<(), String> {
        let name = name.trim().to_lowercase();
        let site_dir = self.base_dir.join("sites").join(&name);

        {
            let mut sites = self.sites.write().await;
            sites.remove(&name);
        }

        if site_dir.exists() {
            std::fs::remove_dir_all(&site_dir).map_err(|e| format!("Erro ao remover: {}", e))?;
        }

        tracing::info!("site deleted: {}", name);
        Ok(())
    }

    pub async fn list_sites(&self) -> Vec<SiteInfo> {
        let sites = self.sites.read().await;
        sites.values().map(|r| r.info.clone()).collect()
    }

    #[allow(dead_code)]
    pub async fn get_site(&self, name: &str) -> Option<SiteInfo> {
        let sites = self.sites.read().await;
        sites.get(name).map(|r| r.info.clone())
    }

    pub async fn save_page(
        &self,
        site_name: &str,
        html: &str,
        source: &serde_json::Value,
    ) -> Result<SiteInfo, String> {
        let site_name = site_name.trim().to_lowercase();
        let site_dir = self.base_dir.join("sites").join(&site_name);
        if !site_dir.exists() {
            return Err(format!("Site '{}' não existe", site_name));
        }
        if html.len() > 2_000_000 {
            return Err("Página muito grande (máx. 2 MB)".into());
        }

        std::fs::write(site_dir.join("index.html"), html.as_bytes())
            .map_err(|e| format!("Erro ao salvar página: {}", e))?;

        // Persist the editable source so the page can be re-opened in the editor
        let src = serde_json::to_string(source).unwrap_or_default();
        std::fs::write(site_dir.join(".sevennine-page.json"), src.as_bytes()).ok();

        let mut total_size: u64 = 0;
        let mut file_list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&site_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with('.') { continue; }
                file_list.push(fname);
                total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        file_list.sort();

        {
            let mut sites = self.sites.write().await;
            if let Some(record) = sites.get_mut(&site_name) {
                record.info.files = file_list;
                record.info.size_bytes = total_size;
                let meta_json = serde_json::to_string_pretty(&record.info).unwrap_or_default();
                std::fs::write(site_dir.join(".sevennine-meta.json"), meta_json.as_bytes()).ok();
                return Ok(record.info.clone());
            }
        }
        Err("Site não encontrado".into())
    }

    pub async fn publish_site(
        &self,
        site_name: &str,
        source: &serde_json::Value,
        files: &[(String, String)],
    ) -> Result<SiteInfo, String> {
        let site_name = site_name.trim().to_lowercase();
        let site_dir = self.base_dir.join("sites").join(&site_name);
        if !site_dir.exists() {
            return Err(format!("Site '{}' não existe", site_name));
        }

        let total: usize = files.iter().map(|(_, h)| h.len()).sum();
        if total > 5_000_000 {
            return Err("Site muito grande (máx. 5 MB no total)".into());
        }
        if files.is_empty() {
            return Err("Nenhuma página para publicar".into());
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
                .map_err(|e| format!("Erro ao salvar {}: {}", safe, e))?;
            written += 1;
        }
        if written == 0 {
            return Err("Nenhuma página válida (.html)".into());
        }

        let src = serde_json::to_string(source).unwrap_or_default();
        std::fs::write(site_dir.join(".sevennine-page.json"), src.as_bytes()).ok();

        let mut total_size: u64 = 0;
        let mut file_list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&site_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with('.') { continue; }
                file_list.push(fname);
                total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        file_list.sort();

        {
            let mut sites = self.sites.write().await;
            if let Some(record) = sites.get_mut(&site_name) {
                record.info.files = file_list;
                record.info.size_bytes = total_size;
                let meta_json = serde_json::to_string_pretty(&record.info).unwrap_or_default();
                std::fs::write(site_dir.join(".sevennine-meta.json"), meta_json.as_bytes()).ok();
                return Ok(record.info.clone());
            }
        }
        Err("Site não encontrado".into())
    }

    pub fn load_page(&self, name: &str) -> Option<String> {
        let name = name.trim().to_lowercase();
        let p = self.base_dir.join("sites").join(&name).join(".sevennine-page.json");
        std::fs::read_to_string(p).ok()
    }

    pub async fn serve_file(&self, site_name: &str, file_path: &str) -> Option<(Vec<u8>, String)> {
        let site_name = site_name.trim().to_lowercase();
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
<html lang="pt">
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
    <p>Este site foi criado na plataforma <strong>SevenNine.hidra</strong><br>
    e está hospedado na rede descentralizada <strong>HidraNet</strong>.</p>
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

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    manager: Arc<SiteManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 1024 * 512]; // 512KB request limit
    let mut total = 0usize;

    // Read until we have headers + full body based on Content-Length
    loop {
        if total >= buf.len() { break; }
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 { break; }
        total += n;

        if let Some(hdr_end) = find_bytes(&buf[..total], b"\r\n\r\n") {
            let hdr_str = String::from_utf8_lossy(&buf[..hdr_end]);
            let content_length = hdr_str.lines()
                .find(|l| l.to_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let needed = hdr_end + 4 + content_length;
            if total >= needed { break; }
        }
    }

    if total == 0 { return Ok(()); }

    let raw = &buf[..total];
    let request = String::from_utf8_lossy(raw);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request").await;
        return Ok(());
    }

    let method = parts[0];
    let raw_path = parts[1];
    let path = urldecode(raw_path);

    match (method, path.as_str()) {
        // ── API routes ──
        ("POST", "/api/sites") => {
            let body = extract_body(&request);
            match serde_json::from_str::<CreateSiteRequest>(&body) {
                Ok(req) => {
                    match manager.create_site(&req.name).await {
                        Ok(site) => {
                            let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                            send_json(&mut stream, 201, &resp).await;
                        }
                        Err(e) => {
                            let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                            send_json(&mut stream, 400, &resp).await;
                        }
                    }
                }
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("JSON inválido. Use: {\"name\": \"meusite\"}".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp).await;
                }
            }
        }

        ("GET", "/api/sites") => {
            let sites = manager.list_sites().await;
            let resp = ApiResponse { ok: true, msg: None, site: None, sites: Some(sites) };
            send_json(&mut stream, 200, &resp).await;
        }

        // ── Visual page editor (save/load page source) ──
        ("POST", p) if p.starts_with("/api/page/") => {
            let site_name = &p[10..];
            let body = extract_body(&request);
            match serde_json::from_str::<SavePageRequest>(&body) {
                Ok(req) => match manager.save_page(site_name, &req.html, &req.source).await {
                    Ok(site) => {
                        let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                        send_json(&mut stream, 200, &resp).await;
                    }
                    Err(e) => {
                        let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                        send_json(&mut stream, 400, &resp).await;
                    }
                },
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("JSON inválido".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp).await;
                }
            }
        }

        ("GET", p) if p.starts_with("/api/page/") => {
            let site_name = &p[10..];
            match manager.load_page(site_name) {
                Some(src) => send_response(&mut stream, 200, "application/json; charset=utf-8", src.as_bytes()).await,
                None => send_response(&mut stream, 200, "application/json; charset=utf-8", b"null").await,
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
                            send_json(&mut stream, 200, &resp).await;
                        }
                        Err(e) => {
                            let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                            send_json(&mut stream, 400, &resp).await;
                        }
                    }
                }
                Err(_) => {
                    let resp = ApiResponse { ok: false, msg: Some("JSON inválido".into()), site: None, sites: None };
                    send_json(&mut stream, 400, &resp).await;
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
                send_response(&mut stream, 200, "application/json; charset=utf-8", json.as_bytes()).await;
            } else {
                send_response(&mut stream, 404, "application/json; charset=utf-8", br#"{"found":false}"#).await;
            }
        }

        ("OPTIONS", _) => {
            send_response(&mut stream, 204, "text/plain", b"").await;
        }

        ("DELETE", p) if p.starts_with("/api/sites/") => {
            let site_name = &p[11..];
            match manager.delete_site(site_name).await {
                Ok(()) => {
                    let resp = ApiResponse { ok: true, msg: Some("Site removido".into()), site: None, sites: None };
                    send_json(&mut stream, 200, &resp).await;
                }
                Err(e) => {
                    let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                    send_json(&mut stream, 400, &resp).await;
                }
            }
        }

        ("POST", p) if p.starts_with("/api/upload/") => {
            let site_name = &p[12..];
            let (filename, file_data) = extract_multipart(&request, raw);
            if let (Some(fname), Some(data)) = (filename, file_data) {
                match manager.upload_file(site_name, &fname, &data).await {
                    Ok(site) => {
                        let resp = ApiResponse { ok: true, msg: None, site: Some(site), sites: None };
                        send_json(&mut stream, 200, &resp).await;
                    }
                    Err(e) => {
                        let resp = ApiResponse { ok: false, msg: Some(e), site: None, sites: None };
                        send_json(&mut stream, 400, &resp).await;
                    }
                }
            } else {
                let resp = ApiResponse { ok: false, msg: Some("Upload inválido".into()), site: None, sites: None };
                send_json(&mut stream, 400, &resp).await;
            }
        }

        // ── Site preview ──
        ("GET", p) if p.starts_with("/sites/") => {
            let rest = &p[7..]; // after "/sites/"
            let (site_name, file_path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i+1..]),
                None => (rest, "index.html"),
            };
            match manager.serve_file(site_name, file_path).await {
                Some((content, mime)) => {
                    send_response(&mut stream, 200, &mime, &content).await;
                }
                None => {
                    send_response(&mut stream, 404, "text/plain", b"Arquivo nao encontrado").await;
                }
            }
        }

        // ── Frontend ──
        ("GET", "/") | ("GET", "/index.html") => {
            send_response(&mut stream, 200, "text/html; charset=utf-8", FRONTEND_HTML.as_bytes()).await;
        }

        ("GET", "/style.css") => {
            send_response(&mut stream, 200, "text/css; charset=utf-8", FRONTEND_CSS.as_bytes()).await;
        }

        ("GET", "/app.js") => {
            send_response(&mut stream, 200, "application/javascript; charset=utf-8", FRONTEND_JS.as_bytes()).await;
        }

        ("GET", "/favicon.ico") => {
            send_response(&mut stream, 204, "image/x-icon", b"").await;
        }

        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found").await;
        }
    }

    Ok(())
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

async fn send_response(stream: &mut tokio::net::TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, X-Filename\r\n\
         Connection: close\r\n\
         \r\n",
        status, status_text, content_type, body.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

async fn send_json(stream: &mut tokio::net::TcpStream, status: u16, data: &ApiResponse) {
    let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".into());
    send_response(stream, status, "application/json; charset=utf-8", body.as_bytes()).await;
}

// ─── Frontend HTML ───────────────────────────────────────────────────────────

const FRONTEND_HTML: &str = r##"<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SevenNine.hidra — Criador de Sites</title>
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
          <p class="tagline">Criador descentralizado de sites para a rede HidraNet</p>
        </div>
      </div>
      <div class="header-stats" id="header-stats">
        <div class="stat"><span class="stat-value" id="total-sites">0</span><span class="stat-label">Sites</span></div>
      </div>
    </header>

    <!-- Create Section -->
    <section class="card create-card">
      <h2><span class="icon">+</span> Criar Novo Site</h2>
      <div class="create-form">
        <div class="name-input-group">
          <input type="text" id="site-name" placeholder="meusite" maxlength="32" autocomplete="off" spellcheck="false">
          <span class="domain-suffix">.hidra</span>
        </div>
        <button class="btn btn-primary" id="create-btn" onclick="createSite()">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 5v14M5 12h14"/>
          </svg>
          Criar Site
        </button>
      </div>
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
        <h2>Site Publicado na HidraNet!</h2>
        <div class="address-box" id="address-box">
          <span class="address-text" id="address-text"></span>
          <button class="btn-copy" onclick="copyAddress()" title="Copiar endereco">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>
        </div>
        <div class="success-actions">
          <a id="open-local-link" href="#" target="_blank" class="btn btn-primary">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            Abrir Site
          </a>
          <button class="btn btn-ghost" onclick="hideSuccess()">Continuar</button>
        </div>
      </div>
    </section>

    <!-- Upload Section (shown after site creation) -->
    <section class="card upload-card hidden" id="upload-section">
      <h2><span class="icon">&#8593;</span> Upload de Arquivos para <span id="upload-site-name" class="accent"></span></h2>
      <div class="upload-zone" id="drop-zone">
        <svg viewBox="0 0 64 64" width="48" height="48" fill="none" stroke="#00d4aa" stroke-width="2" opacity="0.5">
          <rect x="8" y="16" width="48" height="40" rx="4"/>
          <polyline points="24,36 32,28 40,36"/>
          <line x1="32" y1="28" x2="32" y2="48"/>
          <path d="M20,16 V12 a4,4 0 0,1 4,-4 h16 a4,4 0 0,1 4,4 v4"/>
        </svg>
        <p>Arraste arquivos aqui ou <label class="upload-link" for="file-input">clique para selecionar</label></p>
        <p class="hint">HTML, CSS, JS, imagens &mdash; ate 5 MB por arquivo</p>
        <input type="file" id="file-input" multiple hidden>
      </div>
      <div id="file-list" class="file-list"></div>
      <div id="upload-progress" class="upload-progress hidden"></div>
      <div class="upload-actions">
        <button class="btn btn-accent" id="publish-btn" onclick="publishSite()">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/>
          </svg>
          Publicar na HidraNet
        </button>
      </div>
    </section>

    <!-- Sites List -->
    <section class="card sites-card">
      <h2><span class="icon">&#9776;</span> Meus Sites</h2>
      <div id="sites-list" class="sites-list">
        <div class="empty-state">Nenhum site criado ainda. Crie o seu primeiro acima!</div>
      </div>
    </section>

    <!-- Templates Section -->
    <section class="card templates-card">
      <h2><span class="icon">&#10025;</span> Templates Prontos</h2>
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
          <span>Documentacao</span>
        </div>
        <div class="template-item" onclick="useTemplate('loja')">
          <div class="template-preview portfolio-preview">
            <div class="tp-bar"></div><div class="tp-grid"><div></div><div></div><div></div><div></div></div>
          </div>
          <span>Loja Online</span>
        </div>
        <div class="template-item" onclick="useTemplate('noticias')">
          <div class="template-preview blog-preview">
            <div class="tp-bar"></div><div class="tp-content"><div class="tp-line w90"></div><div class="tp-line w60"></div><div class="tp-line w80"></div><div class="tp-line w40"></div></div>
          </div>
          <span>Portal de Noticias</span>
        </div>
      </div>
    </section>

    <footer class="footer">
      <p>SevenNine.hidra &mdash; Powered by <strong>HidraNet</strong></p>
      <p class="hint">Todos os sites sao hospedados de forma descentralizada na rede HidraNet</p>
    </footer>
  </div>

  <!-- ═══ Visual Page Editor (WordPress-style) ═══ -->
  <div id="editor" class="editor hidden">
    <div class="ed-top">
      <div class="ed-top-left">
        <button class="btn btn-ghost btn-sm" onclick="closeEditor()">&larr; Voltar</button>
        <span class="ed-editing">Editando <span id="ed-site-name" class="accent">site.hidra</span></span>
      </div>
      <div class="ed-top-right">
        <button class="btn btn-ghost btn-sm" id="ed-devtoggle" onclick="toggleDevice()" title="Alternar visualizacao">🖥 Desktop</button>
        <a id="ed-open" href="#" target="_blank" class="btn btn-ghost btn-sm">Ver site</a>
        <button class="btn btn-primary btn-sm" id="ed-publish" onclick="publishEditor()">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/></svg>
          Publicar
        </button>
      </div>
    </div>
    <div class="ed-main">
      <aside class="ed-side">
        <div class="ed-block">
          <div class="ed-block-title">Marca</div>
          <label class="ed-label">Nome / Logo (aparece no menu)</label>
          <input type="text" id="ed-brand" class="ed-input" placeholder="Minha Marca" oninput="setMeta('brand', this.value)">
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Aparencia</div>
          <label class="ed-label">Tema</label>
          <div class="ed-themes" id="ed-themes"></div>
          <label class="ed-label">Fonte</label>
          <select id="ed-font" class="ed-input" onchange="setMeta('font', this.value)">
            <option value="system">Moderna (sans-serif)</option>
            <option value="serif">Elegante (serif)</option>
            <option value="mono">Tecnica (monospace)</option>
            <option value="round">Arredondada</option>
          </select>
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Adicionar bloco</div>
          <div class="ed-palette" id="ed-palette"></div>
        </div>
        <div class="ed-block">
          <div class="ed-block-title">Rodape / Redes</div>
          <label class="ed-label">WhatsApp (numero)</label>
          <input type="text" id="ed-wa" class="ed-input" placeholder="5511999999999" oninput="setSocial('whatsapp', this.value)">
          <label class="ed-label">Instagram (@usuario)</label>
          <input type="text" id="ed-ig" class="ed-input" placeholder="@minhamarca" oninput="setSocial('instagram', this.value)">
          <label class="ed-label">E-mail</label>
          <input type="text" id="ed-mail" class="ed-input" placeholder="contato@exemplo" oninput="setSocial('email', this.value)">
        </div>
      </aside>

      <main class="ed-canvas-wrap">
        <div class="ed-pages" id="ed-pages"></div>
        <div class="ed-canvas" id="ed-canvas"></div>
      </main>

      <section class="ed-preview">
        <div class="ed-preview-head">
          <span>Pre-visualizacao &mdash; clique no texto para editar &#9998;</span>
          <span class="ed-preview-dot" id="ed-preview-dot"></span>
        </div>
        <div class="ed-frame-wrap" id="ed-frame-wrap">
          <iframe id="ed-frame" title="preview" sandbox="allow-same-origin allow-scripts"></iframe>
        </div>
      </section>
    </div>
  </div>

  <!-- Modal proprio (prompt/confirm nao funcionam no Electron) -->
  <div id="s9-modal" class="s9-modal hidden">
    <div class="s9-modal-box">
      <div class="s9-modal-title" id="s9-modal-title">Titulo</div>
      <div class="s9-modal-msg" id="s9-modal-msg"></div>
      <input type="text" id="s9-modal-input" class="ed-input" autocomplete="off" spellcheck="false">
      <div class="s9-modal-actions">
        <button class="btn btn-ghost" id="s9-modal-cancel">Cancelar</button>
        <button class="btn btn-primary" id="s9-modal-ok">Confirmar</button>
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
"##;

// ─── Frontend JavaScript ─────────────────────────────────────────────────────

const FRONTEND_JS: &str = r##"
const API = window.location.origin;
let currentSite = null;
let pendingFiles = [];

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  loadSites();
  setupDragDrop();
  document.getElementById('site-name').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') createSite();
  });
});

// ── Create Site ──
async function createSite() {
  const nameInput = document.getElementById('site-name');
  const name = nameInput.value.trim().toLowerCase();
  if (!name) { showMsg('create-msg', 'Digite um nome para o site', 'error'); return; }

  const btn = document.getElementById('create-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Criando...';

  try {
    const res = await fetch(API + '/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    const data = await res.json();

    if (data.ok && data.site) {
      currentSite = data.site.name;
      nameInput.value = '';
      loadSites();
      openEditor(data.site.name);          // abre o editor visual com pagina inicial
    } else {
      showMsg('create-msg', data.msg || 'Erro ao criar site', 'error');
    }
  } catch (e) {
    showMsg('create-msg', 'Erro de conexao: ' + e.message, 'error');
  }

  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Criar Site';
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
      toast('Arquivo ' + file.name + ' excede 5 MB');
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
        '<button class="file-remove" onclick="removeFile(' + i + ')" title="Remover">&times;</button>' +
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
  if (pendingFiles.length === 0) { showMsg('create-msg', 'Adicione pelo menos um arquivo', 'error'); return; }

  const btn = document.getElementById('publish-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Publicando...';

  const prog = document.getElementById('upload-progress');
  prog.classList.remove('hidden');
  const total = pendingFiles.length;
  let uploaded = 0;
  let lastSite = null;

  for (const file of pendingFiles) {
    prog.innerHTML = '<div class="prog-text">Enviando ' + escapeHtml(file.name) + ' (' + (uploaded+1) + '/' + total + ')</div>' +
      '<div class="prog-bar"><div class="prog-fill" style="width:' + Math.round((uploaded/total)*100) + '%"></div></div>';

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(API + '/api/upload/' + currentSite, { method: 'POST', body: formData });
      const data = await res.json();
      if (data.ok && data.site) lastSite = data.site;
      uploaded++;
    } catch (e) {
      showMsg('create-msg', 'Erro ao enviar ' + file.name + ': ' + e.message, 'error');
    }
  }

  prog.innerHTML = '<div class="prog-text">Concluido! ' + uploaded + '/' + total + ' arquivos enviados</div>' +
    '<div class="prog-bar"><div class="prog-fill" style="width:100%"></div></div>';

  pendingFiles = [];
  document.getElementById('file-list').innerHTML = '';
  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/></svg> Publicar na HidraNet';

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
    container.innerHTML = '<div class="empty-state">Nenhum site criado ainda. Crie o seu primeiro acima!</div>';
    return;
  }

  container.innerHTML = sites.map(s =>
    '<div class="site-item">' +
      '<div class="site-info">' +
        '<div class="site-name">' + escapeHtml(s.hidra_address) + '</div>' +
        '<div class="site-meta">' +
          s.files.length + ' arquivo(s) &middot; ' + formatSize(s.size_bytes) + ' &middot; ' +
          s.visits + ' visita(s) &middot; ' + new Date(s.created_at).toLocaleDateString('pt-BR') +
        '</div>' +
      '</div>' +
      '<div class="site-actions">' +
        '<button class="btn btn-primary btn-sm" onclick="openEditor(\'' + escapeHtml(s.name) + '\')">Editar</button>' +
        '<a href="/sites/' + escapeHtml(s.name) + '/" target="_blank" class="btn btn-ghost btn-sm">Abrir</a>' +
        '<button class="btn btn-ghost btn-sm" onclick="uploadTo(\'' + escapeHtml(s.name) + '\')">Upload</button>' +
        '<button class="btn btn-danger btn-sm" onclick="deleteSite(\'' + escapeHtml(s.name) + '\')">Excluir</button>' +
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
  if (!await askConfirm('Excluir o site "' + name + '.hidra"? Esta acao e irreversivel.')) return;

  try {
    await fetch(API + '/api/sites/' + name, { method: 'DELETE' });
    loadSites();
    toast('Site excluido.');
  } catch (e) {
    toast('Erro: ' + e.message);
  }
}

// ── Templates: criam o site e abrem o editor ja preenchido ──
async function useTemplate(type) {
  const name = await askText({ title: 'Criar site com template', msg: 'Escolha um nome — sera o endereco .hidra do seu site.', placeholder: 'meusite', ok: 'Criar e editar' });
  if (!name) return;
  const clean = name.trim().toLowerCase();
  if (!clean) return;
  try {
    const res = await fetch(API + '/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: clean })
    });
    const data = await res.json();
    if (data.ok && data.site) {
      currentSite = data.site.name;
      loadSites();
      openEditor(data.site.name, type);   // abre o editor com os blocos do template
    } else {
      showMsg('create-msg', data.msg || 'Erro ao criar site', 'error');
    }
  } catch (e) {
    showMsg('create-msg', 'Erro de conexao: ' + e.message, 'error');
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

// ═══════════════════ Editor Visual de Paginas (estilo WordPress) ═══════════════════

var ed = { site:null, theme:'hidra', font:'system', brand:'', social:{whatsapp:'',instagram:'',email:''}, pages:[], cur:0 };
var edPreviewTimer = null;
var edDevice = 'desktop';

function curPage(){ return ed.pages[ed.cur] || {blocks:[]}; }
function curBlocks(){ return curPage().blocks; }
function newPage(id,name,blocks){ return { id:id, name:name, blocks:blocks }; }
function fileFor(p){ return p.id==='index' ? 'index.html' : p.id+'.html'; }
function slugify(s){ s=(s||'').toLowerCase(); try{ s=s.normalize('NFD').replace(/[̀-ͯ]/g,''); }catch(e){} return s.replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); }
function uniquePageId(base){ if(!base||base==='index') base='pagina'; var id=base,n=2,ids=ed.pages.map(function(p){return p.id;}); while(ids.indexOf(id)>=0){ id=base+'-'+n; n++; } return id; }
function isListBlock(t){ return ['features','products','articles','pricing','testimonials','gallery'].indexOf(t)>=0; }

var THEMES = {
  hidra:    { name:'Hidra',      mode:'dark',  primary:'#00d4aa', primary2:'#00a888', bg:'#06060b', card:'#10101c', border:'#1a1a2e', text:'#e8e8f0', muted:'#8a8aa0' },
  meianoite:{ name:'Meia-noite', mode:'dark',  primary:'#4f8cff', primary2:'#2f6fe0', bg:'#0a0e1a', card:'#121a2e', border:'#1e2a44', text:'#e6ebf5', muted:'#8a93a8' },
  nebulosa: { name:'Nebulosa',   mode:'dark',  primary:'#a06bff', primary2:'#7b46d6', bg:'#0c0814', card:'#181226', border:'#271b3d', text:'#ece6f5', muted:'#9a8ab0' },
  carvao:   { name:'Carvao',     mode:'dark',  primary:'#f5a623', primary2:'#d68a10', bg:'#121212', card:'#1c1c1c', border:'#2a2a2a', text:'#f0f0f0', muted:'#9a9a9a' },
  clean:    { name:'Clean',      mode:'light', primary:'#2563eb', primary2:'#1d4ed8', bg:'#ffffff', card:'#f4f6fb', border:'#e2e8f0', text:'#1a1f2e', muted:'#667085' },
  menta:    { name:'Menta',      mode:'light', primary:'#0f9d77', primary2:'#0b7d5e', bg:'#f2fbf7', card:'#ffffff', border:'#d6ece2', text:'#10241d', muted:'#5d7d70' },
  sepia:    { name:'Sepia',      mode:'light', primary:'#b4612f', primary2:'#8f4a22', bg:'#f7f1e6', card:'#fffaf2', border:'#e6dcc8', text:'#2e261c', muted:'#8a7a63' },
  coral:    { name:'Coral',      mode:'light', primary:'#e8536b', primary2:'#c63a52', bg:'#fff5f6', card:'#ffffff', border:'#f6dbe0', text:'#2c1419', muted:'#8a6066' }
};

var FONTS = {
  system: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  serif:  "Georgia, 'Times New Roman', serif",
  mono:   "'SF Mono', 'Fira Code', Consolas, monospace",
  round:  "'Trebuchet MS', 'Segoe UI', Verdana, sans-serif"
};

var PALETTE_BLOCKS = [
  { type:'hero',         label:'Capa',        icon:'★' },
  { type:'heading',      label:'Titulo',      icon:'H' },
  { type:'text',         label:'Texto',       icon:'¶' },
  { type:'image',        label:'Imagem',      icon:'▣' },
  { type:'button',       label:'Botao',       icon:'▭' },
  { type:'features',     label:'Destaques',   icon:'⊞' },
  { type:'products',     label:'Produtos',    icon:'🛍' },
  { type:'articles',     label:'Noticias',    icon:'📰' },
  { type:'pricing',      label:'Precos',      icon:'$' },
  { type:'testimonials', label:'Depoimentos', icon:'❝' },
  { type:'gallery',      label:'Galeria',     icon:'▦' },
  { type:'cta',          label:'Chamada',     icon:'➤' },
  { type:'contact',      label:'Contato',     icon:'✉' },
  { type:'divider',      label:'Divisor',     icon:'—' }
];

function defaultItem(type){
  if(type==='features') return {icon:'✦',title:'Recurso',text:'Descricao do recurso'};
  if(type==='products') return {img:'',name:'Produto',price:'99,90',desc:'Descricao do produto.',url:'#',label:'Comprar'};
  if(type==='articles') return {img:'',cat:'Geral',title:'Titulo da noticia',date:'Hoje',excerpt:'Resumo da noticia em uma ou duas linhas.',url:'#'};
  if(type==='pricing') return {plan:'Plano',price:'0',period:'/mes',feats:'Recurso incluso\nOutro recurso',button:'Escolher',url:'#',featured:false};
  if(type==='testimonials') return {quote:'Servico excelente, recomendo muito!',author:'Cliente',role:'Cargo'};
  if(type==='gallery') return {url:''};
  return {};
}
function itemName(type){
  return {features:'Destaque',products:'Produto',articles:'Noticia',pricing:'Plano',testimonials:'Depoimento',gallery:'Imagem'}[type] || 'Item';
}

function defaultBlock(type) {
  switch(type) {
    case 'hero': return { type:type, title:'Bem-vindo ao meu site', subtitle:'Hospedado na rede descentralizada HidraNet.', button:'Saiba mais', url:'#' };
    case 'heading': return { type:type, text:'Um titulo de secao' };
    case 'text': return { type:type, text:'Escreva aqui o seu conteudo. Conte sobre voce, seu projeto ou suas ideias.' };
    case 'image': return { type:type, url:'', alt:'Descricao da imagem' };
    case 'button': return { type:type, text:'Clique aqui', url:'#' };
    case 'features': return { type:type, title:'', items:[ {icon:'🔒',title:'Seguro',text:'Criptografia de ponta a ponta'}, {icon:'🕵',title:'Anonimo',text:'Sem rastreamento'}, {icon:'🌐',title:'Descentralizado',text:'Sem servidor central'} ] };
    case 'products': return { type:type, title:'Nossos Produtos', currency:'R$', items:[ {img:'',name:'Produto 1',price:'99,90',desc:'Otimo produto com qualidade garantida.',url:'#',label:'Comprar'}, {img:'',name:'Produto 2',price:'149,90',desc:'Mais vendido da loja.',url:'#',label:'Comprar'}, {img:'',name:'Produto 3',price:'199,90',desc:'Edicao especial.',url:'#',label:'Comprar'} ] };
    case 'articles': return { type:type, title:'Ultimas Noticias', items:[ {img:'',cat:'Destaque',title:'Primeira manchete do portal',date:'Hoje',excerpt:'Um resumo curto da noticia para atrair o leitor.',url:'#'}, {img:'',cat:'Geral',title:'Segunda noticia importante',date:'Ontem',excerpt:'Outro resumo informativo aqui.',url:'#'} ] };
    case 'pricing': return { type:type, title:'Planos', items:[ {plan:'Basico',price:'29',period:'/mes',feats:'1 site\nSuporte por email\nDominio .hidra',button:'Comecar',url:'#',featured:false}, {plan:'Pro',price:'79',period:'/mes',feats:'Sites ilimitados\nSuporte prioritario\nEstatisticas',button:'Assinar',url:'#',featured:true} ] };
    case 'testimonials': return { type:type, title:'O que dizem', items:[ {quote:'Melhor decisao que tomei. Recomendo!',author:'Maria S.',role:'Empreendedora'}, {quote:'Rapido, seguro e facil de usar.',author:'Joao P.',role:'Desenvolvedor'} ] };
    case 'gallery': return { type:type, title:'Galeria', items:[ {url:''},{url:''},{url:''} ] };
    case 'cta': return { type:type, title:'Pronto para comecar?', text:'Junte-se a nos hoje mesmo e faca parte da rede.', button:'Comecar agora', url:'#' };
    case 'contact': return { type:type, title:'Fale Conosco', email:'contato@exemplo.hidra', phone:'', whatsapp:'', address:'' };
    case 'divider': return { type:type };
    default: return { type:'text', text:'' };
  }
}

function starterBlocks() { return [ defaultBlock('hero'), defaultBlock('features') ]; }

function applyTemplate(type) {
  if (type === 'loja') {
    ed.theme='clean'; ed.font='system';
    ed.pages=[
      newPage('index','Inicio',[ {type:'hero',title:(ed.brand||'Minha Loja'),subtitle:'Produtos de qualidade com entrega para todo o Brasil.',button:'Ver produtos',url:'produtos.html'}, defaultBlock('products'), defaultBlock('testimonials'), {type:'cta',title:'Ofertas por tempo limitado',text:'Aproveite os descontos da semana.',button:'Comprar agora',url:'produtos.html'} ]),
      newPage('produtos','Produtos',[ {type:'heading',text:'Catalogo completo'}, defaultBlock('products') ]),
      newPage('contato','Contato',[ {type:'contact',title:'Fale Conosco',email:'loja@exemplo.hidra',phone:'',whatsapp:'',address:''} ])
    ];
  } else if (type === 'noticias' || type === 'blog') {
    ed.theme=(type==='noticias')?'clean':'sepia'; ed.font=(type==='noticias')?'system':'serif';
    ed.pages=[
      newPage('index','Inicio',[ {type:'hero',title:(ed.brand||'Meu Portal'),subtitle:'Noticias, artigos e analises atualizadas.',button:'Ler agora',url:'#'}, defaultBlock('articles') ]),
      newPage('sobre','Sobre',[ {type:'heading',text:'Sobre o portal'}, {type:'text',text:'Um espaco independente para informacao livre, sem censura e sem rastreamento, na rede HidraNet.'} ])
    ];
  } else if (type === 'portfolio') {
    ed.theme='meianoite'; ed.font='system';
    ed.pages=[ newPage('index','Inicio',[ {type:'hero',title:(ed.brand||'Meu Portfolio'),subtitle:'Design & Desenvolvimento',button:'Ver trabalhos',url:'#'}, defaultBlock('gallery'), defaultBlock('features'), {type:'contact',title:'Fale comigo',email:'eu@exemplo.hidra',phone:'',whatsapp:'',address:''} ]) ];
  } else if (type === 'docs') {
    ed.theme='hidra'; ed.font='mono';
    ed.pages=[ newPage('index','Inicio',[ {type:'heading',text:'Documentacao'}, {type:'text',text:'Bem-vindo a documentacao do projeto.'} ]), newPage('guia','Guia',[ {type:'heading',text:'Inicio rapido'}, {type:'text',text:'1. Baixe o programa\n2. Execute o instalador\n3. Pronto para usar'} ]) ];
  } else {
    ed.theme='hidra'; ed.font='system';
    ed.pages=[ newPage('index','Inicio',[ defaultBlock('hero'), defaultBlock('features'), defaultBlock('cta') ]) ];
  }
  ed.cur=0;
}

async function openEditor(name, template) {
  ed.site=name; ed.theme='hidra'; ed.font='system'; ed.brand=name;
  ed.social={whatsapp:'',instagram:'',email:''};
  ed.pages=[ newPage('index','Inicio', starterBlocks()) ]; ed.cur=0;
  try {
    const res = await fetch(API + '/api/page/' + name);
    const src = await res.json();
    if (src && src.pages && src.pages.length) {
      ed.theme=src.theme||'hidra'; ed.font=src.font||'system'; ed.brand=src.brand||name;
      ed.social=src.social||ed.social; ed.pages=src.pages; ed.cur=0;
    } else if (src && src.blocks) {
      ed.theme=src.theme||'hidra'; ed.font=src.font||'system'; ed.brand=src.title||name;
      ed.pages=[ newPage('index','Inicio', src.blocks) ];
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

// ── Paginas ──
function renderPageTabs() {
  var el = document.getElementById('ed-pages');
  var tabs = ed.pages.map(function(p, i){
    var del = (i===0) ? '' : '<span class="pg-edit" title="Excluir" onclick="event.stopPropagation();deletePage('+i+')">&times;</span>';
    return '<div class="ed-page-tab'+(i===ed.cur?' active':'')+'" onclick="switchPage('+i+')">' +
      '<span>'+esc(p.name)+'</span>' +
      '<span class="pg-edit" title="Renomear" onclick="event.stopPropagation();renamePage('+i+')">&#9998;</span>' + del + '</div>';
  }).join('');
  el.innerHTML = tabs + '<div class="ed-page-add" onclick="addPage()">+ Pagina</div>';
}
function switchPage(i){ ed.cur=i; renderPageTabs(); renderCanvas(); updatePreview(); }
async function addPage(){
  var name = await askText({ title: 'Nova pagina', msg: 'Ex.: Loja, Produtos, Sobre, Contato.', placeholder: 'Loja', ok: 'Criar pagina' }); if(!name) return;
  name = name.trim(); if(!name) return;
  var id = uniquePageId(slugify(name) || 'pagina');
  ed.pages.push(newPage(id, name, [ defaultBlock('heading'), defaultBlock('text') ]));
  ed.cur = ed.pages.length - 1;
  renderPageTabs(); renderCanvas(); updatePreview();
}
async function renamePage(i){
  var name = await askText({ title: 'Renomear pagina', value: ed.pages[i].name, ok: 'Salvar' }); if(!name) return;
  ed.pages[i].name = name.trim() || ed.pages[i].name;
  renderPageTabs(); updatePreview();
}
async function deletePage(i){
  if(i===0){ toast('A pagina inicial nao pode ser excluida.'); return; }
  if(!await askConfirm('Excluir a pagina "'+ed.pages[i].name+'"?')) return;
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
  var m = {hero:'Capa', heading:'Titulo', text:'Texto', image:'Imagem', button:'Botao', features:'Destaques', products:'Produtos', articles:'Noticias', pricing:'Precos', testimonials:'Depoimentos', gallery:'Galeria', cta:'Chamada', contact:'Contato', divider:'Divisor'};
  return m[type] || type;
}

function renderCanvas() {
  var el = document.getElementById('ed-canvas');
  var blocks = curBlocks();
  if (blocks.length === 0) { el.innerHTML = '<div class="ed-canvas-empty">Pagina vazia. Adicione blocos no painel a esquerda.</div>'; return; }
  el.innerHTML = blocks.map(function(b, i){ return blockCard(b, i); }).join('');
}

function blockCard(b, i) {
  var body = '';
  if (b.type === 'hero') {
    body = field('Titulo', b.title, i, 'title') + field('Subtitulo', b.subtitle, i, 'subtitle') +
      '<div class="row2">' + field('Texto do botao', b.button, i, 'button') + field('Link do botao', b.url, i, 'url') + '</div>';
  } else if (b.type === 'heading') { body = field('Titulo', b.text, i, 'text'); }
  else if (b.type === 'text') { body = area('Texto', b.text, i, 'text'); }
  else if (b.type === 'image') { body = field('URL da imagem (https://...)', b.url, i, 'url') + field('Descricao', b.alt, i, 'alt'); }
  else if (b.type === 'button') { body = '<div class="row2">' + field('Texto', b.text, i, 'text') + field('Link', b.url, i, 'url') + '</div>'; }
  else if (b.type === 'cta') {
    body = field('Titulo', b.title, i, 'title') + area('Texto', b.text, i, 'text') +
      '<div class="row2">' + field('Texto do botao', b.button, i, 'button') + field('Link', b.url, i, 'url') + '</div>';
  } else if (b.type === 'contact') {
    body = field('Titulo', b.title, i, 'title') +
      '<div class="row2">' + field('E-mail', b.email, i, 'email') + field('Telefone', b.phone, i, 'phone') + '</div>' +
      '<div class="row2">' + field('WhatsApp (numero)', b.whatsapp, i, 'whatsapp') + field('Endereco', b.address, i, 'address') + '</div>';
  } else if (b.type === 'divider') { body = '<div style="color:var(--text3);font-size:0.85em">Linha divisoria (sem opcoes)</div>'; }
  else if (isListBlock(b.type)) { body = listBlockBody(b, i); }
  return '<div class="ed-card">' +
    '<div class="ed-card-head"><span class="ed-card-type">'+blockLabel(b.type)+'</span>' +
      '<div class="ed-card-tools">' +
        '<button class="ed-tool" onclick="moveBlock('+i+',-1)" title="Subir">&uarr;</button>' +
        '<button class="ed-tool" onclick="moveBlock('+i+',1)" title="Descer">&darr;</button>' +
        '<button class="ed-tool del" onclick="delBlock('+i+')" title="Remover">&#128465;</button>' +
      '</div></div>' +
    '<div class="ed-card-body">'+body+'</div></div>';
}

function listBlockBody(b, i) {
  var head = '';
  if (b.type === 'products') head = field('Titulo da secao', b.title, i, 'title') + field('Moeda (R$, US$...)', b.currency, i, 'currency');
  else if (b.type !== 'features') head = field('Titulo da secao', b.title, i, 'title');
  var items = (b.items||[]).map(function(it, j){
    return '<div class="ed-item"><button class="ed-item-rm" onclick="rmItem('+i+','+j+')" title="Remover">&times;</button>' +
      '<div class="ed-item-n">'+itemName(b.type)+' '+(j+1)+'</div>' + itemFields(b.type, it, i, j) + '</div>';
  }).join('');
  return head + '<div class="ed-items">'+items+'</div><button class="ed-mini-btn" onclick="addItem('+i+')">+ Adicionar '+itemName(b.type)+'</button>';
}

function itemFields(type, it, bi, ii) {
  if (type === 'features') return iField('Icone (emoji)', it.icon, bi, ii, 'icon') + iField('Titulo', it.title, bi, ii, 'title') + iField('Texto', it.text, bi, ii, 'text');
  if (type === 'products') return iField('URL da imagem', it.img, bi, ii, 'img') + iField('Nome', it.name, bi, ii, 'name') + '<div class="row2">' + iField('Preco', it.price, bi, ii, 'price') + iField('Texto do botao', it.label, bi, ii, 'label') + '</div>' + iField('Descricao', it.desc, bi, ii, 'desc') + iField('Link de compra', it.url, bi, ii, 'url');
  if (type === 'articles') return iField('URL da imagem', it.img, bi, ii, 'img') + '<div class="row2">' + iField('Categoria', it.cat, bi, ii, 'cat') + iField('Data', it.date, bi, ii, 'date') + '</div>' + iField('Titulo', it.title, bi, ii, 'title') + iArea('Resumo', it.excerpt, bi, ii, 'excerpt') + iField('Link', it.url, bi, ii, 'url');
  if (type === 'pricing') return iField('Plano', it.plan, bi, ii, 'plan') + '<div class="row2">' + iField('Preco', it.price, bi, ii, 'price') + iField('Periodo', it.period, bi, ii, 'period') + '</div>' + iArea('Recursos (1 por linha)', it.feats, bi, ii, 'feats') + '<div class="row2">' + iField('Texto do botao', it.button, bi, ii, 'button') + iField('Link', it.url, bi, ii, 'url') + '</div>' + iCheck('Destacar este plano', it.featured, bi, ii, 'featured');
  if (type === 'testimonials') return iArea('Depoimento', it.quote, bi, ii, 'quote') + '<div class="row2">' + iField('Autor', it.author, bi, ii, 'author') + iField('Cargo', it.role, bi, ii, 'role') + '</div>';
  if (type === 'gallery') return iField('URL da imagem', it.url, bi, ii, 'url');
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
  document.getElementById('ed-devtoggle').innerHTML = (edDevice==='desktop') ? '🖥 Desktop' : '📱 Celular';
}

async function publishEditor(){
  var btn = document.getElementById('ed-publish');
  btn.disabled = true; var old = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span> Publicando...';
  var files = ed.pages.map(function(p){ return { path: fileFor(p), html: renderPageHTML(p, false) }; });
  var source = { brand: ed.brand, theme: ed.theme, font: ed.font, social: ed.social, pages: ed.pages };
  try {
    var res = await fetch(API + '/api/publish/' + ed.site, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: source, files: files })
    });
    var data = await res.json();
    if (data.ok) { btn.innerHTML = '✓ Publicado!'; setTimeout(function(){ btn.disabled=false; btn.innerHTML=old; }, 1600); }
    else { toast('Erro ao publicar: ' + (data.msg||'')); btn.disabled=false; btn.innerHTML=old; }
  } catch(e) { toast('Erro de conexao: ' + e.message); btn.disabled=false; btn.innerHTML=old; }
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
    '<div class="s9-foot-bottom">Feito com <strong>SevenNine.hidra</strong> &middot; rede HidraNet</div></footer>';
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
  var t = THEMES[ed.theme] || THEMES.hidra;
  var font = FONTS[ed.font] || FONTS.system;
  var title = esc((ed.brand ? ed.brand + ' — ' : '') + (page.name || 'Site'));
  var body = (page.blocks||[]).map(function(b,i){ return blockHTML(b, t, em, i); }).join('\n');
  return '<!DOCTYPE html><html lang="pt"><head><meta charset="UTF-8">' +
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
  return '<div class="'+cls+' s9-ph">'+esc(ph||'Imagem')+'</div>';
}

function blockHTML(b, t, em, bi){
  if (b.type === 'hero') {
    var btn = b.button ? '<a class="s9-btn" href="' + safeUrl(b.url) + '"'+ce(em)+de(em,bi+':button')+'>' + esc(b.button) + '</a>' : '';
    return '<section class="s9-hero"'+db(em,bi)+'><div><h1'+ce(em)+de(em,bi+':title')+'>' + esc(b.title) + '</h1><p'+ce(em)+de(em,bi+':subtitle')+' data-multi="1">' + esc(b.subtitle) + '</p>' + btn + '</div></section>';
  }
  if (b.type === 'heading') return '<div class="s9-wrap"'+db(em,bi)+'><h2 class="s9-h"'+ce(em)+de(em,bi+':text')+'>' + esc(b.text) + '</h2></div>';
  if (b.type === 'text') return '<div class="s9-wrap"'+db(em,bi)+'><p class="s9-p"'+ce(em)+de(em,bi+':text')+' data-multi="1">' + esc(b.text) + '</p></div>';
  if (b.type === 'image') {
    var inner = (b.url && /^(https?:|\/)/i.test(b.url)) ? '<img class="s9-img" src="' + safeUrl(b.url) + '" alt="' + attr(b.alt) + '">' : '<div class="s9-img s9-imgph s9-ph">' + (esc(b.alt) || 'Imagem') + '</div>';
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
      var buy = it.url ? '<a class="s9-btn s9-btn-sm" href="'+safeUrl(it.url)+'"'+ce(em)+de(em,bi+'.'+ii+':label')+'>'+esc(it.label||'Comprar')+'</a>' : '';
      return '<div class="s9-prod">' + imgOr(it.img,'s9-prod-img',it.name,'Sem imagem') +
        '<div class="s9-prod-b"><h3'+ce(em)+de(em,bi+'.'+ii+':name')+'>'+esc(it.name)+'</h3><div class="s9-price">'+esc(b.currency||'')+' <span'+ce(em)+de(em,bi+'.'+ii+':price')+'>'+esc(it.price||'')+'</span></div><p'+ce(em)+de(em,bi+'.'+ii+':desc')+'>'+esc(it.desc)+'</p>'+buy+'</div></div>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-prod-grid">'+cards+'</div></section>';
  }
  if (b.type === 'articles') {
    var arts = (b.items||[]).map(function(it,ii){
      return '<a class="s9-art" href="'+safeUrl(it.url)+'">' + imgOr(it.img,'s9-art-img',it.title,'Sem imagem') +
        '<div class="s9-art-b"><span class="s9-cat">'+esc(it.cat||'Geral')+'</span><h3'+ce(em)+de(em,bi+'.'+ii+':title')+'>'+esc(it.title)+'</h3><div class="s9-date">'+esc(it.date)+'</div><p'+ce(em)+de(em,bi+'.'+ii+':excerpt')+'>'+esc(it.excerpt)+'</p></div></a>';
    }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-art-grid">'+arts+'</div></section>';
  }
  if (b.type === 'pricing') {
    var plans = (b.items||[]).map(function(it,ii){
      var feats = (it.feats||'').split('\n').filter(function(x){return x.trim();}).map(function(f){ return '<li>'+esc(f)+'</li>'; }).join('');
      var bt = it.url ? '<a class="s9-btn" href="'+safeUrl(it.url)+'"'+ce(em)+de(em,bi+'.'+ii+':button')+'>'+esc(it.button||'Escolher')+'</a>' : '';
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
    var imgs = (b.items||[]).map(function(it){ return imgOr(it.url,'','','Imagem'); }).join('');
    return '<section class="s9-sec"'+db(em,bi)+'>' + secTitle(b,em,bi) + '<div class="s9-gal">'+imgs+'</div></section>';
  }
  if (b.type === 'cta') {
    var cb = b.button ? '<a class="s9-btn" href="'+safeUrl(b.url)+'"'+ce(em)+de(em,bi+':button')+'>'+esc(b.button)+'</a>' : '';
    return '<section class="s9-cta"'+db(em,bi)+'><h2'+ce(em)+de(em,bi+':title')+'>'+esc(b.title)+'</h2><p'+ce(em)+de(em,bi+':text')+' data-multi="1">'+esc(b.text)+'</p>'+cb+'</section>';
  }
  if (b.type === 'contact') {
    var rows = '';
    if (b.email) rows += '<div class="s9-cd"><b>E-mail:</b> <a href="mailto:'+attr(b.email)+'">'+esc(b.email)+'</a></div>';
    if (b.phone) rows += '<div class="s9-cd"><b>Telefone:</b> '+esc(b.phone)+'</div>';
    if (b.whatsapp) rows += '<div class="s9-cd"><b>WhatsApp:</b> <a href="https://wa.me/'+b.whatsapp.replace(/\D/g,'')+'">'+esc(b.whatsapp)+'</a></div>';
    if (b.address) rows += '<div class="s9-cd"><b>Endereco:</b> '+esc(b.address)+'</div>';
    return '<section class="s9-sec"'+db(em,bi)+'><h2 class="s9-sec-h"'+ce(em)+de(em,bi+':title')+'>'+esc(b.title)+'</h2><div class="s9-contact">'+rows+'</div></section>';
  }
  if (b.type === 'divider') return '<hr class="s9-hr"'+db(em,bi)+'>';
  return '';
}

function esc(s){ s=(s==null?'':String(s)); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function attr(s){ s=(s==null?'':String(s)); return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
function safeUrl(u){ u=(u==null?'#':String(u).trim()); if(/^(https?:|mailto:|#|\/)/i.test(u)) return attr(u); return '#'; }

// ── Modal proprio (prompt/confirm/alert nao funcionam no Electron) ──
function askText(opts){
  return new Promise(function(resolve){
    var m=document.getElementById('s9-modal');
    document.getElementById('s9-modal-title').textContent=opts.title||'';
    document.getElementById('s9-modal-msg').textContent=opts.msg||'';
    var inp=document.getElementById('s9-modal-input');
    inp.style.display=''; inp.placeholder=opts.placeholder||''; inp.value=opts.value||'';
    document.getElementById('s9-modal-ok').textContent=opts.ok||'Confirmar';
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
    document.getElementById('s9-modal-title').textContent='Confirmar';
    document.getElementById('s9-modal-msg').textContent=message;
    var inp=document.getElementById('s9-modal-input'); inp.style.display='none';
    document.getElementById('s9-modal-ok').textContent='Excluir';
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
