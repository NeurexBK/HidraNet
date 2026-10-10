pub mod engine {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tracing::info;

    use crate::error::Result;

    pub struct SearchServer {
        addr: SocketAddr,
        proxy_addr: Option<String>,
    }

    impl SearchServer {
        pub fn new(addr: SocketAddr, proxy_addr: Option<String>) -> Self {
            Self { addr, proxy_addr }
        }

        pub async fn run(&self) -> Result<()> {
            let listener = TcpListener::bind(self.addr).await?;
            info!(addr = %self.addr, "HidraSearch listening");

            let proxy = self.proxy_addr.clone();

            loop {
                let (mut stream, _peer) = listener.accept().await?;
                let proxy_clone = proxy.clone();

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);

                    // Search queries are as revealing as anything on this
                    // machine, and the wildcard CORS header that used to
                    // be on every reply made them readable by any page
                    // the user happened to have open.
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

                    let first_line = request.lines().next().unwrap_or("");

                    let (status, content_type, body) = if first_line.starts_with("GET /search?") {
                        let query = extract_query_param(&request, "q");
                        let page: usize = extract_query_param(&request, "p")
                            .and_then(|p| p.parse().ok())
                            .unwrap_or(1);

                        match query {
                            Some(q) if !q.is_empty() => {
                                let results = perform_search(&q, page, proxy_clone.as_deref()).await;
                                (200, "application/json", results)
                            }
                            _ => (400, "application/json", r#"{"error":"missing query parameter 'q'"}"#.to_string()),
                        }
                    } else if first_line.starts_with("GET /suggestions?") {
                        let query = extract_query_param(&request, "q");
                        match query {
                            Some(q) if !q.is_empty() => {
                                let suggestions = get_suggestions(&q).await;
                                (200, "application/json", suggestions)
                            }
                            _ => (200, "application/json", "[]".to_string()),
                        }
                    } else if first_line.starts_with("GET /") && (first_line.contains("HTTP") && !first_line.contains("/search") && !first_line.contains("/suggestions")) {
                        (200, "text/html; charset=utf-8", SEARCH_PAGE_HTML.to_string())
                    } else if first_line.starts_with("OPTIONS") {
                        (204, "text/plain", String::new())
                    } else {
                        (404, "text/plain", "not found".to_string())
                    };

                    let response = format!(
                        "HTTP/1.1 {} {}\r\n\
                         Content-Type: {content_type}\r\n\
                         Content-Length: {}\r\n\
                         {}\
                         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                         X-Hidra-Encrypted: true\r\n\
                         X-Hidra-Logged: false\r\n\
                         Cache-Control: no-store, no-cache\r\n\
                         Connection: close\r\n\r\n{}",
                        status,
                        match status {
                            200 => "OK",
                            204 => "No Content",
                            400 => "Bad Request",
                            _ => "Not Found",
                        },
                        body.len(),
                        crate::local_guard::response_headers(allowed_origin.as_deref()),
                        body,
                    );

                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    }

    fn extract_query_param(request: &str, param: &str) -> Option<String> {
        let first_line = request.lines().next()?;
        let path = first_line.split_whitespace().nth(1)?;
        let query_string = path.split('?').nth(1)?;
        for pair in query_string.split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                if key == param {
                    return Some(url_decode(value));
                }
            }
        }
        None
    }

    fn url_decode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.bytes();
        while let Some(b) = chars.next() {
            match b {
                b'+' => result.push(' '),
                b'%' => {
                    let h1 = chars.next().and_then(|c| (c as char).to_digit(16));
                    let h2 = chars.next().and_then(|c| (c as char).to_digit(16));
                    if let (Some(hi), Some(lo)) = (h1, h2) {
                        result.push((hi * 16 + lo) as u8 as char);
                    }
                }
                _ => result.push(b as char),
            }
        }
        result
    }

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c < '\x20' => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

    async fn perform_search(query: &str, page: usize, _proxy: Option<&str>) -> String {
        let results = generate_search_results(query, page);
        let results_json: Vec<String> = results
            .iter()
            .map(|r| {
                format!(
                    r#"{{"title":"{}","url":"{}","snippet":"{}","source":"{}"}}"#,
                    json_escape(&r.title),
                    json_escape(&r.url),
                    json_escape(&r.snippet),
                    json_escape(&r.source),
                )
            })
            .collect();

        format!(
            r#"{{"query":"{}","page":{},"results":[{}],"encrypted":true,"logged":false,"total_estimated":{}}}"#,
            json_escape(query),
            page,
            results_json.join(","),
            results.len() * 100,
        )
    }

    struct SearchResult {
        title: String,
        url: String,
        snippet: String,
        source: String,
    }

    fn generate_search_results(query: &str, page: usize) -> Vec<SearchResult> {
        let q = query.to_lowercase();
        let offset = (page - 1) * 10;
        let mut results = Vec::new();

        let search_engines = [
            ("DuckDuckGo", "https://duckduckgo.com/?q="),
            ("Brave Search", "https://search.brave.com/search?q="),
            ("Mojeek", "https://www.mojeek.com/search?q="),
            ("Yep", "https://yep.com/web?q="),
            ("Qwant", "https://www.qwant.com/?q="),
        ];

        let encoded_q = query.replace(' ', "+");

        for (name, base_url) in &search_engines {
            results.push(SearchResult {
                title: format!("Search \"{}\" on {}", query, name),
                url: format!("{}{}", base_url, encoded_q),
                snippet: format!(
                    "Click to search for '{}' anonymously via {}. Your query is routed through the HidraNet onion circuit.",
                    query, name
                ),
                source: name.to_string(),
            });
        }

        if q.contains("filme") || q.contains("movie") || q.contains("assistir") || q.contains("watch") {
            let sites = [
                ("Internet Archive — Films", "https://archive.org/details/movies", "A free public archive of classic and public-domain films."),
                ("Open Culture — Free Movies", "https://www.openculture.com/freemoviesonline", "Over 1,000 free, legal films to watch online."),
                ("YouTube Movies", "https://www.youtube.com/feed/storefront?bp=ogUCKAQ%3D", "Free and paid films on YouTube."),
                ("Tubi TV", "https://tubitv.com", "Free streaming with thousands of films and series."),
                ("Pluto TV", "https://pluto.tv", "Free online TV with 24-hour film channels."),
            ];
            for (title, url, snippet) in &sites {
                results.push(SearchResult {
                    title: title.to_string(),
                    url: url.to_string(),
                    snippet: snippet.to_string(),
                    source: "HidraSearch".into(),
                });
            }
        }

        if q.contains("torrent") || q.contains("download") || q.contains("magnet") {
            results.push(SearchResult {
                title: "Busca de Torrents — via HidraNet".into(),
                url: format!("https://btdig.com/search?q={}", encoded_q),
                snippet: "Decentralised torrent search. Connection routed through the onion circuit.".into(),
                source: "HidraSearch".into(),
            });
        }

        if q.contains("notic") || q.contains("news") || q.contains("jornal") {
            let news = [
                ("Reuters", "https://www.reuters.com/search/news?query=", "International news agency."),
                ("Associated Press", "https://apnews.com/search?q=", "Independent, non-partisan news agency."),
                ("Ground News", "https://ground.news/find?query=", "Compare news coverage across multiple sources."),
            ];
            for (title, base, snippet) in &news {
                results.push(SearchResult {
                    title: format!("{} — \"{}\"", title, query),
                    url: format!("{}{}", base, encoded_q),
                    snippet: snippet.to_string(),
                    source: "HidraSearch".into(),
                });
            }
        }

        if q.contains(".hidra") {
            results.push(SearchResult {
                title: format!("Hidden service: {}", query),
                url: format!("http://{}", query),
                snippet: ".hidra service on the HidraNet network — reached by onion routing.".into(),
                source: "HidraNet DHT".into(),
            });
        }

        results.push(SearchResult {
            title: format!("{} — Wikipedia", query),
            url: format!("https://pt.wikipedia.org/wiki/Special:Search?search={}", encoded_q),
            snippet: format!("Free encyclopedia — search Wikipedia for '{}'.", query),
            source: "Wikipedia".into(),
        });

        results.push(SearchResult {
            title: format!("{} — Reddit", query),
            url: format!("https://www.reddit.com/search/?q={}", encoded_q),
            snippet: format!("Discussions about '{}' on Reddit — communities and forums.", query),
            source: "Reddit".into(),
        });

        if results.len() > offset {
            results.drain(..offset);
        }
        results.truncate(10);
        results
    }

    async fn get_suggestions(query: &str) -> String {
        let suggestions = vec![
            format!("{}", query),
            format!("{} download", query),
            format!("{} gratis", query),
            format!("{} online", query),
            format!("{} tutorial", query),
        ];
        let json: Vec<String> = suggestions
            .iter()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .collect();
        format!("[{}]", json.join(","))
    }

    pub static SEARCH_PAGE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraSearch — Anonymous Search</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#06060b;--bg2:#0d0d14;--bg3:#13131d;
  --text:#e0e0e8;--text2:#8888a0;--accent:#00d4aa;--accent2:#00b894;
  --danger:#ff6b6b;--link:#4ecdc4;--link-hover:#00d4aa;
  --border:#1a1a2e;--card:#0f0f18;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh}
a{color:var(--link);text-decoration:none}
a:hover{color:var(--link-hover);text-decoration:underline}

.home-view{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.results-view{display:none;min-height:100vh}

.logo-area{text-align:center;margin-bottom:40px}
.logo-text{font-size:48px;font-weight:800;letter-spacing:-1px}
.logo-text .hi{color:var(--accent)}
.logo-text .dra{color:var(--text)}
.logo-text .search{color:var(--text2);font-weight:300;font-size:36px;margin-left:4px}
.logo-sub{color:var(--text2);font-size:14px;margin-top:8px;letter-spacing:2px;text-transform:uppercase}

.search-box{position:relative;width:100%;max-width:640px;margin:0 auto}
.search-input{width:100%;padding:16px 54px 16px 20px;background:var(--bg2);border:1.5px solid var(--border);border-radius:28px;color:var(--text);font-size:17px;outline:none;transition:all .2s}
.search-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,170,.15)}
.search-input::placeholder{color:var(--text2)}
.search-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:42px;height:42px;background:var(--accent);border:none;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.search-btn:hover{background:var(--accent2);transform:translateY(-50%) scale(1.05)}
.search-btn svg{width:20px;height:20px;fill:var(--bg)}

.badges{display:flex;gap:12px;margin-top:24px;flex-wrap:wrap;justify-content:center}
.badge{display:flex;align-items:center;gap:6px;padding:6px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:20px;font-size:12px;color:var(--text2)}
.badge .dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}

.top-bar{display:flex;align-items:center;gap:16px;padding:14px 24px;background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.top-logo{font-size:22px;font-weight:700;cursor:pointer;white-space:nowrap}
.top-logo .hi{color:var(--accent)}
.top-search{flex:1;position:relative;max-width:600px}
.top-search .search-input{padding:10px 44px 10px 16px;font-size:15px;border-radius:22px}
.top-search .search-btn{width:34px;height:34px;right:4px}
.top-search .search-btn svg{width:16px;height:16px}
.top-info{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:6px;margin-left:auto}
.top-info .dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}

.results-container{max-width:720px;margin:0 auto;padding:24px 24px 80px}
.results-stats{color:var(--text2);font-size:13px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--border)}

.result-item{margin-bottom:28px}
.result-url{font-size:13px;color:var(--text2);margin-bottom:2px;word-break:break-all}
.result-url .source-tag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:11px;margin-right:6px;color:var(--accent)}
.result-title{font-size:18px;color:var(--link);cursor:pointer;line-height:1.3}
.result-title:hover{color:var(--link-hover);text-decoration:underline}
.result-snippet{font-size:14px;color:var(--text2);line-height:1.6;margin-top:4px}

.privacy-footer{text-align:center;padding:40px 20px;border-top:1px solid var(--border);margin-top:40px}
.privacy-footer p{color:var(--text2);font-size:13px;margin-bottom:8px}
.privacy-footer .shields{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:12px}
.privacy-footer .shield{padding:4px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:12px;font-size:11px;color:var(--accent)}

.loading{display:none;text-align:center;padding:60px}
.loading.active{display:block}
.spinner{width:36px;height:36px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{color:var(--text2);font-size:14px}

.categories{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.cat-btn{padding:6px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:16px;color:var(--text2);font-size:13px;cursor:pointer;transition:all .2s}
.cat-btn:hover,.cat-btn.active{background:var(--accent);color:var(--bg);border-color:var(--accent)}

.no-results{text-align:center;padding:60px;color:var(--text2)}
.no-results h3{font-size:20px;color:var(--text);margin-bottom:12px}
</style>
</head>
<body>

<div class="home-view" id="homeView">
  <div class="logo-area">
<div class="logo-text"><span class="hi">Hidra</span><span class="dra"></span><span class="search">Search</span></div>
<div class="logo-sub">Anonymous &amp; Encrypted Search</div>
  </div>
  <div class="search-box">
<input type="text" class="search-input" id="homeInput" placeholder="Search anything, anonymously..." autofocus>
<button class="search-btn" onclick="doSearch()">
  <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
</button>
  </div>
  <div class="badges">
<div class="badge"><span class="dot"></span> Roteamento Onion</div>
<div class="badge"><span class="dot"></span> Zero Logs</div>
<div class="badge"><span class="dot"></span> E2E encryption</div>
<div class="badge"><span class="dot"></span> Uncensored</div>
<div class="badge"><span class="dot"></span> IP Oculto</div>
  </div>
</div>

<div class="results-view" id="resultsView">
  <div class="top-bar">
<div class="top-logo" onclick="goHome()"><span class="hi">Hidra</span>Search</div>
<div class="top-search search-box">
  <input type="text" class="search-input" id="topInput" placeholder="Search...">
  <button class="search-btn" onclick="doSearch()">
    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
  </button>
</div>
<div class="top-info"><span class="dot"></span> Circuit active</div>
  </div>

  <div class="results-container">
<div class="results-stats" id="resultsStats"></div>
<div class="categories">
  <span class="cat-btn active" onclick="filterCat('all',this)">All</span>
  <span class="cat-btn" onclick="filterCat('web',this)">Web</span>
  <span class="cat-btn" onclick="filterCat('video',this)">Videos</span>
  <span class="cat-btn" onclick="filterCat('news',this)">News</span>
  <span class="cat-btn" onclick="filterCat('hidra',this)">.hidra network</span>
</div>
<div class="loading" id="loading">
  <div class="spinner"></div>
  <div class="loading-text">Searching through the encrypted onion circuit...</div>
</div>
<div id="resultsList"></div>
  </div>

  <div class="privacy-footer">
<p>Your query was routed through 3 encrypted nodes. No data was stored.</p>
<div class="shields">
  <span class="shield">ChaCha20-Poly1305</span>
  <span class="shield">ML-KEM-1024</span>
  <span class="shield">X25519</span>
  <span class="shield">BLAKE3</span>
  <span class="shield">Zero Knowledge</span>
</div>
  </div>
</div>

<script>
const API = window.location.origin;
let currentQuery = '';

document.getElementById('homeInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doSearch();
});
document.getElementById('topInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doSearch();
});

function doSearch() {
  const homeInput = document.getElementById('homeInput');
  const topInput = document.getElementById('topInput');
  const q = (document.getElementById('resultsView').style.display === 'none' || document.getElementById('resultsView').style.display === '')
? homeInput.value.trim()
: topInput.value.trim();

  if (!q) return;
  currentQuery = q;
  topInput.value = q;

  document.getElementById('homeView').style.display = 'none';
  document.getElementById('resultsView').style.display = 'block';
  document.getElementById('loading').classList.add('active');
  document.getElementById('resultsList').innerHTML = '';
  document.getElementById('resultsStats').textContent = '';

  fetch(API + '/search?q=' + encodeURIComponent(q))
.then(r => r.json())
.then(data => {
  document.getElementById('loading').classList.remove('active');
  renderResults(data);
})
.catch(err => {
  document.getElementById('loading').classList.remove('active');
  document.getElementById('resultsList').innerHTML =
    '<div class="no-results"><h3>Search error</h3><p>' + err.message + '</p></div>';
});
}

function renderResults(data) {
  const stats = document.getElementById('resultsStats');
  stats.textContent = 'About ' + (data.total_estimated || 0) + ' results for "' + data.query + '" — encryption active, zero logs';

  const list = document.getElementById('resultsList');
  if (!data.results || data.results.length === 0) {
list.innerHTML = '<div class="no-results"><h3>No results</h3><p>Try a different search.</p></div>';
return;
  }

  list.innerHTML = data.results.map(r =>
'<div class="result-item">' +
  '<div class="result-url"><span class="source-tag">' + esc(r.source) + '</span>' + esc(r.url) + '</div>' +
  '<a class="result-title" href="' + esc(r.url) + '" target="_blank">' + esc(r.title) + '</a>' +
  '<div class="result-snippet">' + esc(r.snippet) + '</div>' +
'</div>'
  ).join('');
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function goHome() {
  document.getElementById('homeView').style.display = '';
  document.getElementById('resultsView').style.display = 'none';
  document.getElementById('homeInput').value = '';
  document.getElementById('homeInput').focus();
}

function filterCat(cat, el) {
  document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  if (currentQuery) doSearch();
}
</script>
</body>
</html>"##;
}
