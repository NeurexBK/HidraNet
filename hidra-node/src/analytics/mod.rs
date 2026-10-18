pub mod storage {
    use rusqlite::{Connection, params};
    use std::path::Path;
    use std::sync::Mutex;

    pub struct AnalyticsDb {
        conn: Mutex<Connection>,
    }

    impl AnalyticsDb {
        pub fn open(db_path: &Path) -> crate::error::Result<Self> {
            let conn = Connection::open(db_path).map_err(|e| {
                crate::error::HidraError::Protocol(format!("sqlite open: {e}"))
            })?;
            conn.execute_batch(SCHEMA).map_err(|e| {
                crate::error::HidraError::Protocol(format!("sqlite schema: {e}"))
            })?;
            Ok(Self { conn: Mutex::new(conn) })
        }

        pub fn insert_snapshot(&self, snap: &NetworkSnapshot) -> crate::error::Result<()> {
            let conn = self.conn.lock().map_err(|e| {
                crate::error::HidraError::Protocol(format!("db lock: {e}"))
            })?;
            conn.execute(
                "INSERT INTO snapshots (ts, active_users, active_relays, circuits_per_sec, \
                 bytes_sent, bytes_recv, latency_avg_ms, traffic_gb_day) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    snap.ts,
                    snap.active_users,
                    snap.active_relays,
                    snap.circuits_per_sec,
                    snap.bytes_sent,
                    snap.bytes_recv,
                    snap.latency_avg_ms,
                    snap.traffic_gb_day,
                ],
            ).map_err(|e| crate::error::HidraError::Protocol(format!("insert: {e}")))?;

            for geo in &snap.geo {
                conn.execute(
                    "INSERT INTO geo_distribution (ts, country_code, user_count) VALUES (?1,?2,?3)",
                    params![snap.ts, geo.country_code, geo.user_count],
                ).map_err(|e| crate::error::HidraError::Protocol(format!("insert geo: {e}")))?;
            }
            Ok(())
        }

        pub fn query_snapshots(&self, since_ts: &str, limit: usize) -> crate::error::Result<Vec<NetworkSnapshot>> {
            let conn = self.conn.lock().map_err(|e| {
                crate::error::HidraError::Protocol(format!("db lock: {e}"))
            })?;
            let mut stmt = conn.prepare(
                "SELECT ts, active_users, active_relays, circuits_per_sec, \
                 bytes_sent, bytes_recv, latency_avg_ms, traffic_gb_day \
                 FROM snapshots WHERE ts >= ?1 ORDER BY ts DESC LIMIT ?2"
            ).map_err(|e| crate::error::HidraError::Protocol(format!("query: {e}")))?;

            let rows = stmt.query_map(params![since_ts, limit as i64], |row| {
                Ok(NetworkSnapshot {
                    ts: row.get(0)?,
                    active_users: row.get(1)?,
                    active_relays: row.get(2)?,
                    circuits_per_sec: row.get(3)?,
                    bytes_sent: row.get(4)?,
                    bytes_recv: row.get(5)?,
                    latency_avg_ms: row.get(6)?,
                    traffic_gb_day: row.get(7)?,
                    geo: Vec::new(),
                })
            }).map_err(|e| crate::error::HidraError::Protocol(format!("query map: {e}")))?;

            let mut snaps = Vec::new();
            for row in rows {
                if let Ok(s) = row {
                    snaps.push(s);
                }
            }
            snaps.reverse();
            Ok(snaps)
        }

        pub fn query_geo(&self, since_ts: &str) -> crate::error::Result<Vec<GeoEntry>> {
            let conn = self.conn.lock().map_err(|e| {
                crate::error::HidraError::Protocol(format!("db lock: {e}"))
            })?;
            let mut stmt = conn.prepare(
                "SELECT country_code, SUM(user_count) as total \
                 FROM geo_distribution WHERE ts >= ?1 \
                 GROUP BY country_code ORDER BY total DESC"
            ).map_err(|e| crate::error::HidraError::Protocol(format!("query geo: {e}")))?;

            let rows = stmt.query_map(params![since_ts], |row| {
                Ok(GeoEntry {
                    country_code: row.get(0)?,
                    user_count: row.get(1)?,
                })
            }).map_err(|e| crate::error::HidraError::Protocol(format!("geo map: {e}")))?;

            let mut entries = Vec::new();
            for row in rows {
                if let Ok(g) = row {
                    entries.push(g);
                }
            }
            Ok(entries)
        }

        pub fn latest_snapshot(&self) -> crate::error::Result<Option<NetworkSnapshot>> {
            let snaps = self.query_snapshots("1970-01-01T00:00:00Z", 1)?;
            Ok(snaps.into_iter().last())
        }

        pub fn cleanup_old(&self, before_ts: &str) -> crate::error::Result<()> {
            let conn = self.conn.lock().map_err(|e| {
                crate::error::HidraError::Protocol(format!("db lock: {e}"))
            })?;
            conn.execute("DELETE FROM snapshots WHERE ts < ?1", params![before_ts])
                .map_err(|e| crate::error::HidraError::Protocol(format!("cleanup: {e}")))?;
            conn.execute("DELETE FROM geo_distribution WHERE ts < ?1", params![before_ts])
                .map_err(|e| crate::error::HidraError::Protocol(format!("cleanup geo: {e}")))?;
            Ok(())
        }
    }

    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            active_users INTEGER NOT NULL DEFAULT 0,
            active_relays INTEGER NOT NULL DEFAULT 0,
            circuits_per_sec REAL NOT NULL DEFAULT 0.0,
            bytes_sent INTEGER NOT NULL DEFAULT 0,
            bytes_recv INTEGER NOT NULL DEFAULT 0,
            latency_avg_ms REAL NOT NULL DEFAULT 0.0,
            traffic_gb_day REAL NOT NULL DEFAULT 0.0
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);

        CREATE TABLE IF NOT EXISTS geo_distribution (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            country_code TEXT NOT NULL,
            user_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_geo_ts ON geo_distribution(ts);
    ";

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct NetworkSnapshot {
        pub ts: String,
        pub active_users: i64,
        pub active_relays: i64,
        pub circuits_per_sec: f64,
        pub bytes_sent: i64,
        pub bytes_recv: i64,
        pub latency_avg_ms: f64,
        pub traffic_gb_day: f64,
        pub geo: Vec<GeoEntry>,
    }

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct GeoEntry {
        pub country_code: String,
        pub user_count: i64,
    }
}

pub mod collector {
    use super::storage::{AnalyticsDb, NetworkSnapshot, GeoEntry};
    use std::sync::Arc;
    use chrono::Utc;
    use tracing::info;

    pub async fn run_collector(db: Arc<AnalyticsDb>, interval_secs: u64) {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(interval_secs),
        );

        info!(interval_secs, "analytics collector started");

        loop {
            interval.tick().await;
            let snap = collect_metrics().await;
            if let Err(e) = db.insert_snapshot(&snap) {
                tracing::warn!(error = %e, "failed to store analytics snapshot");
            }

            let cutoff = (Utc::now() - chrono::Duration::days(31))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let _ = db.cleanup_old(&cutoff);
        }
    }

    /// What this node can actually see: which of its local relays answer,
    /// and how long a connection to them takes.
    ///
    /// This used to report users, traffic, circuits and a breakdown by
    /// country, all of it computed from a formula, the hour of the day and a
    /// random jitter, with nothing measured behind it. A dashboard for an
    /// anonymity network that shows made-up numbers is worse than none, and a
    /// node has no business counting its users or where they are: it cannot
    /// do it honestly and should not do it at all. So those stay at zero, and
    /// the page says they are not collected.
    async fn collect_metrics() -> NetworkSnapshot {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let (relays, latency_avg_ms) = probe_local_relays().await;
        NetworkSnapshot {
            ts: now,
            active_users: 0,
            active_relays: relays,
            circuits_per_sec: 0.0,
            bytes_sent: 0,
            bytes_recv: 0,
            latency_avg_ms,
            traffic_gb_day: 0.0,
            geo: Vec::<GeoEntry>::new(),
        }
    }

    /// The local relays that accept a connection, and the mean time to
    /// connect to them, in milliseconds (0 when none answer).
    async fn probe_local_relays() -> (i64, f64) {
        let mut up = 0i64;
        let mut total_ms = 0.0f64;
        for port in [7001u16, 7002, 7003] {
            let addr = format!("127.0.0.1:{port}");
            let t0 = std::time::Instant::now();
            let ok = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            if ok {
                up += 1;
                total_ms += t0.elapsed().as_secs_f64() * 1000.0;
            }
        }
        let avg = if up > 0 { total_ms / up as f64 } else { 0.0 };
        (up, avg)
    }

    #[cfg(test)]
    mod tests {
        #[tokio::test]
        async fn nothing_is_made_up() {
            let a = super::collect_metrics().await;
            let b = super::collect_metrics().await;
            assert_eq!(a.active_users, 0);
            assert_eq!((a.bytes_sent, a.bytes_recv), (0, 0));
            assert!(a.geo.is_empty());
            assert_eq!(a.circuits_per_sec, 0.0);
            // No jitter: with nothing listening, two snapshots agree exactly.
            assert_eq!(a.active_relays, b.active_relays);
        }
    }
}

pub mod dashboard {
    use super::storage::AnalyticsDb;
    use std::sync::Arc;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tracing::info;

    pub async fn run_dashboard(
        addr: SocketAddr,
        db: Arc<AnalyticsDb>,
    ) -> crate::error::Result<()> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            crate::error::HidraError::Protocol(format!("dashboard bind: {e}"))
        })?;

        info!(addr = %addr, "analytics dashboard started");

        loop {
            let (mut stream, _peer) = listener.accept().await.map_err(|e| {
                crate::error::HidraError::Protocol(format!("accept: {e}"))
            })?;

            let db = Arc::clone(&db);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]);

                // The dashboard reports relay counts, traffic and the geo
                // breakdown of this node. Wildcard CORS made all of it
                // readable by any page open in any browser on the machine.
                let allowed_origin = match crate::local_guard::screen(&request) {
                    crate::local_guard::Access::Allow(origin) => origin,
                    crate::local_guard::Access::Deny => {
                        let (code, text) = crate::local_guard::DENIED_STATUS;
                        let body = crate::local_guard::DENIED_BODY;
                        let response = format!(
                            "HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            crate::local_guard::response_headers(None),
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };

                let path = request.split_whitespace().nth(1).unwrap_or("/");

                let (status, content_type, body) = match path {
                    "/api/stats" => handle_stats(&db),
                    "/api/traffic" => handle_traffic(&db),
                    "/api/geo" => handle_geo(&db),
                    // Chart.js came from cdn.jsdelivr.net until now. On a
                    // dashboard whose whole point is that nobody watches
                    // this node, that announced the node to a CDN on every
                    // page load and gave whoever controls that CDN — or
                    // anyone who can tamper with the response — script
                    // execution inside it.
                    "/vendor/chart.umd.min.js" => (
                        "200 OK",
                        "text/javascript; charset=utf-8",
                        VENDOR_CHART_JS.to_string(),
                    ),
                    _ => handle_dashboard_page(),
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{}Cache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                    crate::local_guard::response_headers(allowed_origin.as_deref())
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }

    /// Chart.js, bundled rather than fetched.
    const VENDOR_CHART_JS: &str = include_str!("../../assets/vendor/chart.umd.min.js");

    fn handle_stats(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
        let snap = db.latest_snapshot().ok().flatten();
        let json = match snap {
            Some(s) => serde_json::to_string(&s).unwrap_or_else(|_| "{}".into()),
            None => r#"{"active_users":0,"active_relays":0,"circuits_per_sec":0,"latency_avg_ms":0,"traffic_gb_day":0,"bytes_sent":0,"bytes_recv":0,"geo":[]}"#.into(),
        };
        ("200 OK", "application/json", json)
    }

    fn handle_traffic(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
        let since = (chrono::Utc::now() - chrono::Duration::hours(24))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let snaps = db.query_snapshots(&since, 288).unwrap_or_default();
        let json = serde_json::to_string(&snaps).unwrap_or_else(|_| "[]".into());
        ("200 OK", "application/json", json)
    }

    fn handle_geo(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
        let since = (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let geo = db.query_geo(&since).unwrap_or_default();
        let json = serde_json::to_string(&geo).unwrap_or_else(|_| "[]".into());
        ("200 OK", "application/json", json)
    }

    fn handle_dashboard_page() -> (&'static str, &'static str, String) {
        ("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.to_string())
    }

    pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraNet — Analytics Dashboard</title>
<script src="/vendor/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#06060b;--bg-card:#10101c;--bg-hover:#14142a;
  --text:#e0e0e8;--text-dim:#8888a0;--text-muted:#555570;
  --accent:#00d4aa;--accent-dim:#00a888;--accent-glow:rgba(0,212,170,0.15);
  --danger:#ff4466;--warning:#ffaa33;--blue:#4488ff;
  --border:#1a1a2e;--radius:10px;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:24px}
.dashboard{max-width:1200px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.header h1{font-size:24px;font-weight:300;letter-spacing:4px;color:var(--accent);text-transform:uppercase}
.header .live{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-dim)}
.header .live .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;transition:border-color .2s}
.stat-card:hover{border-color:var(--accent)}
.stat-card .label{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-muted);margin-bottom:8px}
.stat-card .value{font-size:28px;font-weight:600;color:var(--text)}
.stat-card .value.accent{color:var(--accent)}
.stat-card .delta{font-size:11px;margin-top:4px;color:var(--text-dim)}
.stat-card .delta.up{color:var(--accent)}
.stat-card .delta.down{color:var(--danger)}
.charts-row{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.chart-card h3{font-size:14px;font-weight:500;color:var(--text-dim);margin-bottom:16px;text-transform:uppercase;letter-spacing:1px}
.chart-wrap{position:relative;height:280px}
.geo-section{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:24px}
.geo-section h3{font-size:14px;font-weight:500;color:var(--text-dim);margin-bottom:16px;text-transform:uppercase;letter-spacing:1px}
.geo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.geo-item{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg);border-radius:6px;border:1px solid var(--border)}
.geo-flag{font-size:20px}
.geo-info .country{font-size:12px;font-weight:600;color:var(--text)}
.geo-info .count{font-size:11px;color:var(--text-dim)}
.geo-bar{flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden;min-width:30px}
.geo-bar-fill{height:100%;background:var(--accent);border-radius:2px;transition:width .6s}
.time-filter{display:flex;gap:8px;margin-bottom:16px}
.time-btn{padding:6px 14px;border:1px solid var(--border);background:var(--bg);color:var(--text-dim);border-radius:16px;cursor:pointer;font-size:12px;transition:all .2s}
.time-btn.active,.time-btn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-glow)}
.footer{text-align:center;padding:16px;font-size:11px;color:var(--text-muted);border-top:1px solid var(--border)}
@media(max-width:768px){.charts-row{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="dashboard">
  <div class="header">
<h1>HidraNet Analytics</h1>
<div class="live"><span class="dot"></span> Live updates</div>
  </div>

  <p style="color:#8888a0;font-size:13px;line-height:1.6;margin:0 0 18px">This page shows only what this node measures on this machine: which of its local relays answer, and how long a connection to them takes. HidraNet does not count its users, their traffic or where they are, so those are not collected.</p>
  <div class="stats-grid">
<div class="stat-card"><div class="label">Users</div><div class="value accent" id="s-users">—</div><div class="delta" id="d-users"></div></div>
<div class="stat-card"><div class="label">Local relays answering</div><div class="value" id="s-relays">—</div><div class="delta" id="d-relays"></div></div>
<div class="stat-card"><div class="label">Circuits/sec</div><div class="value" id="s-circuits">—</div></div>
<div class="stat-card"><div class="label">Connect time to them</div><div class="value" id="s-latency">—</div></div>
<div class="stat-card"><div class="label">Traffic (GB/day)</div><div class="value" id="s-traffic">—</div></div>
<div class="stat-card"><div class="label">Countries</div><div class="value" id="s-countries">—</div></div>
  </div>

  <div class="charts-row">
<div class="chart-card">
  <h3>Network traffic</h3>
  <div class="time-filter">
    <button class="time-btn active" data-range="24h">24h</button>
    <button class="time-btn" data-range="7d">7 days</button>
    <button class="time-btn" data-range="30d">30 days</button>
  </div>
  <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
</div>
<div class="chart-card">
  <h3>Users by region — not collected</h3>
  <div class="chart-wrap"><canvas id="geoChart"></canvas></div>
</div>
  </div>

  <div class="geo-section">
<h3>Geographic distribution — not collected</h3>
<div class="geo-grid" id="geoGrid"></div>
  </div>

  <div class="footer">HidraNet Analytics — local data, aggregated and anonymised</div>
</div>

<script>
const FLAGS={AF:'🇦🇫',AL:'🇦🇱',DZ:'🇩🇿',AR:'🇦🇷',AU:'🇦🇺',AT:'🇦🇹',BE:'🇧🇪',BR:'🇧🇷',CA:'🇨🇦',CL:'🇨🇱',CN:'🇨🇳',CO:'🇨🇴',CZ:'🇨🇿',DK:'🇩🇰',EG:'🇪🇬',FI:'🇫🇮',FR:'🇫🇷',DE:'🇩🇪',GR:'🇬🇷',HK:'🇭🇰',HU:'🇭🇺',IN:'🇮🇳',ID:'🇮🇩',IE:'🇮🇪',IL:'🇮🇱',IT:'🇮🇹',JP:'🇯🇵',KR:'🇰🇷',MY:'🇲🇾',MX:'🇲🇽',NL:'🇳🇱',NZ:'🇳🇿',NG:'🇳🇬',NO:'🇳🇴',PK:'🇵🇰',PE:'🇵🇪',PH:'🇵🇭',PL:'🇵🇱',PT:'🇵🇹',RO:'🇷🇴',RU:'🇷🇺',SA:'🇸🇦',SG:'🇸🇬',ZA:'🇿🇦',ES:'🇪🇸',SE:'🇸🇪',CH:'🇨🇭',TW:'🇹🇼',TH:'🇹🇭',TR:'🇹🇷',UA:'🇺🇦',AE:'🇦🇪',GB:'🇬🇧',US:'🇺🇸',VN:'🇻🇳'};
const NAMES={BR:'Brazil',US:'USA',DE:'Germany',FR:'France',GB:'United Kingdom',JP:'Japan',CA:'Canada',NL:'Netherlands',AU:'Australia',KR:'South Korea',IN:'India',SE:'Sweden',CH:'Switzerland',PL:'Poland',ES:'Spain',PT:'Portugal',IT:'Italy',RU:'Russia',AR:'Argentina',MX:'Mexico'};

let trafficChart, geoChart;
let prevStats = null;

function initCharts(){
  const tCtx=document.getElementById('trafficChart').getContext('2d');
  trafficChart=new Chart(tCtx,{type:'line',data:{labels:[],datasets:[
{label:'Sent (MB)',data:[],borderColor:'#00d4aa',backgroundColor:'rgba(0,212,170,0.1)',fill:true,tension:0.4,pointRadius:0},
{label:'Received (MB)',data:[],borderColor:'#4488ff',backgroundColor:'rgba(68,136,255,0.1)',fill:true,tension:0.4,pointRadius:0}
  ]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#8888a0',font:{size:11}}}},scales:{x:{ticks:{color:'#555570',maxTicksLimit:8},grid:{color:'#1a1a2e'}},y:{ticks:{color:'#555570',callback:v=>v.toFixed(1)+'MB'},grid:{color:'#1a1a2e'}}}}});

  const gCtx=document.getElementById('geoChart').getContext('2d');
  geoChart=new Chart(gCtx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#00d4aa','#4488ff','#ffaa33','#ff4466','#b388ff','#00bcd4','#8bc34a','#ff9800','#e91e63','#9c27b0'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8888a0',font:{size:11},padding:8}}},cutout:'65%'}});
}

async function fetchStats(){
  try{
const r=await fetch('/api/stats');
const s=await r.json();
document.getElementById('s-users').textContent='not counted';
document.getElementById('s-relays').textContent=s.active_relays||0;
document.getElementById('s-circuits').textContent='not measured';
document.getElementById('s-latency').textContent=(s.latency_avg_ms||0).toFixed(0)+'ms';
document.getElementById('s-traffic').textContent='not measured';

if(prevStats){
  setDelta('d-relays',s.active_relays,prevStats.active_relays);
}
prevStats=s;
  }catch(e){console.error('stats fetch:',e)}
}

function setDelta(id,curr,prev){
  const el=document.getElementById(id);
  const diff=curr-prev;
  if(diff>0){el.textContent='▲ +'+diff;el.className='delta up'}
  else if(diff<0){el.textContent='▼ '+diff;el.className='delta down'}
  else{el.textContent='— steady';el.className='delta'}
}

async function fetchTraffic(){
  try{
const r=await fetch('/api/traffic');
const data=await r.json();
const labels=data.map(d=>{const t=new Date(d.ts);return t.getHours().toString().padStart(2,'0')+':'+t.getMinutes().toString().padStart(2,'0')});
trafficChart.data.labels=labels;
trafficChart.data.datasets[0].data=data.map(d=>(d.bytes_sent||0)/1048576);
trafficChart.data.datasets[1].data=data.map(d=>(d.bytes_recv||0)/1048576);
trafficChart.update('none');
  }catch(e){console.error('traffic fetch:',e)}
}

async function fetchGeo(){
  try{
const r=await fetch('/api/geo');
const data=await r.json();
document.getElementById('s-countries').textContent='not collected';
const top=data.slice(0,10);
geoChart.data.labels=top.map(g=>NAMES[g.country_code]||g.country_code);
geoChart.data.datasets[0].data=top.map(g=>g.user_count);
geoChart.update('none');

const grid=document.getElementById('geoGrid');
const maxCount=data.length>0?data[0].user_count:1;
grid.innerHTML=data.map(g=>{
  const pct=Math.round((g.user_count/maxCount)*100);
  return '<div class="geo-item">'
    +'<span class="geo-flag">'+(FLAGS[g.country_code]||'🌍')+'</span>'
    +'<div class="geo-info"><div class="country">'+(NAMES[g.country_code]||g.country_code)+'</div>'
    +'<div class="count">'+g.user_count+' users</div></div>'
    +'<div class="geo-bar"><div class="geo-bar-fill" style="width:'+pct+'%"></div></div>'
    +'</div>';
}).join('');
  }catch(e){console.error('geo fetch:',e)}
}

document.querySelectorAll('.time-btn').forEach(btn=>{
  btn.addEventListener('click',function(){
document.querySelectorAll('.time-btn').forEach(b=>b.classList.remove('active'));
this.classList.add('active');
fetchTraffic();
  });
});

initCharts();
fetchStats();
fetchTraffic();
fetchGeo();
setInterval(fetchStats,10000);
setInterval(fetchTraffic,30000);
setInterval(fetchGeo,60000);
</script>
</body>
</html>"##;
}
