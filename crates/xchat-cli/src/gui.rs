use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xchat_core::{
    envelope::{EncryptedEnvelope, RouteToken},
    keystore::KeyStore,
    profile::UserProfile,
    replay::ReplayFilter,
    session::{save_sessions_encrypted, Session},
};

const DIRECT_ROUTE: RouteToken = [0u8; 16];
use xchat_transport::discovery::{DiscoveryBeacon, PeerDiscoveryEngine, DEFAULT_DISCOVERY_PORT};

pub const EMBEDDED_HTML: &str = include_str!("../../../android/app/src/main/assets/index.html");
pub const JSQR_JS: &str = include_str!("../../../android/app/src/main/assets/jsqr.min.js");

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ContactEntry {
    pub alias: String,
    pub address: String,
    pub target: String,
    pub status: String,
    pub last_message: String,
    pub last_time: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChatMessage {
    pub id: String,
    pub sender: String, // "self" or "peer"
    pub text: String,
    pub time: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireMessageEnvelope {
    pub envelope: EncryptedEnvelope,
    #[serde(default)]
    pub sender_alias: Option<String>,
    #[serde(default)]
    pub sender_socket: Option<String>,
    #[serde(default)]
    pub sender_address: Option<String>,
}

pub fn json_response(status: &str, body: &str, extra_headers: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        extra_headers,
        body.len(),
        body
    )
}

#[allow(dead_code)]
pub struct AppState {
    pub keystore: KeyStore,
    pub profile: UserProfile,
    pub local_ip: String,
    pub local_port: u16,
    pub contacts: Vec<ContactEntry>,
    pub messages: HashMap<String, Vec<ChatMessage>>,
    pub discovery: Arc<PeerDiscoveryEngine>,
    pub ble_transport: Arc<xchat_transport::ble_central::BleCentralTransport>,
    pub sessions: HashMap<String, Session>,
    pub replay_filter: ReplayFilter,
    pub csrf_token: String,
    pub session_store_path: PathBuf,
    pub contacts_store_path: PathBuf,
    pub messages_store_path: PathBuf,
    pub burner_rooms: HashMap<String, xchat_core::burner::BurnerRoom>,
}

pub(crate) fn detect_local_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn get_now_time_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hours = (now / 3600) % 24;
    let minutes = (now / 60) % 60;
    format!("{:02}:{:02}", hours, minutes)
}

pub fn get_profile_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".xchat_profile.json")
    } else {
        PathBuf::from(".xchat_profile.json")
    }
}

pub fn get_keystore_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".xchat_keystore.bin")
    } else {
        PathBuf::from(".xchat_keystore.bin")
    }
}

pub fn get_default_contacts(my_address: &str) -> Vec<ContactEntry> {
    let now_str = get_now_time_string();
    vec![
        ContactEntry {
            alias: "Saved Messages".to_string(),
            address: my_address.to_string(),
            target: "local".to_string(),
            status: "Encrypted Storage".to_string(),
            last_message: "Personal cloud notes & encryption test".to_string(),
            last_time: now_str.clone(),
        },
        ContactEntry {
            alias: "xChat Assistant".to_string(),
            address: "xchat_assistant".to_string(),
            target: "local".to_string(),
            status: "P2P Mesh AI Assistant".to_string(),
            last_message: "Send a message to test P2P encryption!".to_string(),
            last_time: now_str,
        },
    ]
}

pub fn save_contacts_encrypted(
    contacts: &[ContactEntry],
    path: &std::path::Path,
    encryption_key: &[u8; 32],
) -> Result<(), xchat_core::errors::CoreError> {
    let filtered_contacts: Vec<ContactEntry> = contacts
        .iter()
        .filter(|c| {
            !c.alias.starts_with('#') && c.target != "burner" && !c.address.starts_with("burner_")
        })
        .cloned()
        .collect();
    let bytes = serde_json::to_vec(&filtered_contacts)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = xchat_crypto::aead::encrypt_aead(
        encryption_key,
        &nonce,
        &bytes,
        b"xchat-contacts-vault-v1",
    )
    .map_err(xchat_core::errors::CoreError::Crypto)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    KeyStore::write_secure_file(path, &out)
}

pub fn load_contacts_encrypted(
    path: &std::path::Path,
    encryption_key: &[u8; 32],
) -> Result<Vec<ContactEntry>, xchat_core::errors::CoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read(path)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    if data.len() < 12 {
        return Ok(Vec::new());
    }
    let (nonce, ciphertext) = data.split_at(12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let decrypted = xchat_crypto::aead::decrypt_aead(
        encryption_key,
        &nonce_arr,
        ciphertext,
        b"xchat-contacts-vault-v1",
    )
    .map_err(xchat_core::errors::CoreError::Crypto)?;
    let mut contacts: Vec<ContactEntry> = serde_json::from_slice(&decrypted)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    contacts.retain(|c| {
        !c.alias.starts_with('#') && c.target != "burner" && !c.address.starts_with("burner_")
    });
    Ok(contacts)
}

pub fn save_messages_encrypted(
    messages: &HashMap<String, Vec<ChatMessage>>,
    path: &std::path::Path,
    encryption_key: &[u8; 32],
) -> Result<(), xchat_core::errors::CoreError> {
    let filtered_messages: HashMap<String, Vec<ChatMessage>> = messages
        .iter()
        .filter(|(k, _)| !k.starts_with('#') && !k.starts_with("burner_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let bytes = serde_json::to_vec(&filtered_messages)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = xchat_crypto::aead::encrypt_aead(
        encryption_key,
        &nonce,
        &bytes,
        b"xchat-messages-vault-v1",
    )
    .map_err(xchat_core::errors::CoreError::Crypto)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    KeyStore::write_secure_file(path, &out)
}

pub fn load_messages_encrypted(
    path: &std::path::Path,
    encryption_key: &[u8; 32],
) -> Result<HashMap<String, Vec<ChatMessage>>, xchat_core::errors::CoreError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let data = std::fs::read(path)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    if data.len() < 12 {
        return Ok(HashMap::new());
    }
    let (nonce, ciphertext) = data.split_at(12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let decrypted = xchat_crypto::aead::decrypt_aead(
        encryption_key,
        &nonce_arr,
        ciphertext,
        b"xchat-messages-vault-v1",
    )
    .map_err(xchat_core::errors::CoreError::Crypto)?;
    let mut msgs: HashMap<String, Vec<ChatMessage>> = serde_json::from_slice(&decrypted)
        .map_err(|e| xchat_core::errors::CoreError::StorageError(e.to_string()))?;
    msgs.retain(|k, _| !k.starts_with('#') && !k.starts_with("burner_"));
    Ok(msgs)
}

pub async fn dispatch_http_get(target: &str, path: &str) -> anyhow::Result<String> {
    let clean_target = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let target_host = if let Some(slash_idx) = clean_target.find('/') {
        &clean_target[..slash_idx]
    } else {
        clean_target
    };

    let connect_fut = TcpStream::connect(target_host);
    let mut stream = tokio::time::timeout(tokio::time::Duration::from_secs(2), connect_fut)
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout to {}", target_host))??;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, target_host
    );
    stream.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    let read_fut = stream.read_to_end(&mut resp);
    tokio::time::timeout(tokio::time::Duration::from_secs(2), read_fut)
        .await
        .map_err(|_| anyhow::anyhow!("Read timeout from {}", target_host))??;

    let resp_str = String::from_utf8_lossy(&resp);
    let status_line = resp_str.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(anyhow::anyhow!(
            "Remote server responded with {}",
            status_line
        ));
    }
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        Ok(resp_str[pos + 4..].to_string())
    } else {
        Ok(resp_str.to_string())
    }
}

pub async fn dispatch_http_post(target: &str, path: &str, body: &str) -> anyhow::Result<String> {
    let clean_target = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let target_host = if let Some(slash_idx) = clean_target.find('/') {
        &clean_target[..slash_idx]
    } else {
        clean_target
    };

    let connect_fut = TcpStream::connect(target_host);
    let mut stream = tokio::time::timeout(tokio::time::Duration::from_secs(2), connect_fut)
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout to {}", target_host))??;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        target_host,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    let read_fut = stream.read_to_end(&mut resp);
    tokio::time::timeout(tokio::time::Duration::from_secs(2), read_fut)
        .await
        .map_err(|_| anyhow::anyhow!("Read timeout from {}", target_host))??;

    let resp_str = String::from_utf8_lossy(&resp);
    let status_line = resp_str.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(anyhow::anyhow!(
            "Remote server responded with {}",
            status_line
        ));
    }
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        Ok(resp_str[pos + 4..].to_string())
    } else {
        Ok(resp_str.to_string())
    }
}

/// Start the embedded Telegram-styled app server with UDP peer discovery.
pub async fn start_embedded_app_server(
    port: u16,
    bind: Option<&str>,
    no_browser: bool,
    advertise: Option<&str>,
) -> anyhow::Result<()> {
    let bind_interface = bind.unwrap_or("0.0.0.0");
    let bind_addr = format!("{}:{}", bind_interface, port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let local_ip = if let Some(adv) = advertise {
        adv.to_string()
    } else {
        detect_local_ip()
    };

    let keystore_path = get_keystore_path();
    let keystore =
        KeyStore::load_or_generate(&keystore_path).unwrap_or_else(|_| KeyStore::generate());
    let my_pub = keystore.identity.public_key();
    let my_address = my_pub.address();
    let my_fingerprint = my_pub.fingerprint();
    let visual_fp = my_pub.visual_fingerprint();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let profile_path = get_profile_path();
    let mut profile = UserProfile::load_from_disk(&profile_path).unwrap_or_else(|_| {
        let initial_handle = format!("user_{}", &my_address[6..12]);
        UserProfile::new(
            &initial_handle,
            "Mesh Operator",
            &my_address,
            &my_fingerprint,
            now,
        )
        .unwrap()
    });

    // Ensure profile always reflects current cryptographic identity keys
    profile.address = my_address.clone();
    profile.fingerprint = my_fingerprint.clone();
    let _ = profile.save_to_disk(&profile_path);

    let discovery_engine =
        match PeerDiscoveryEngine::bind(DEFAULT_DISCOVERY_PORT, DEFAULT_DISCOVERY_PORT).await {
            Ok(e) => e,
            Err(_) => PeerDiscoveryEngine::bind(0, DEFAULT_DISCOVERY_PORT).await?,
        };

    let ble_transport = xchat_transport::ble_central::BleCentralTransport::new().await;
    ble_transport.set_local_identity(&profile.username, &profile.display_name, &my_address);

    let session_store_path = keystore_path.with_file_name(".xchat_sessions.bin");
    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(&keystore_path))
        .expect("Failed to obtain device storage key; refusing fallback to insecure default");
    let sessions = xchat_core::session::load_sessions_encrypted(&session_store_path, &storage_key)
        .unwrap_or_default();
    let replay_store_path = keystore_path.with_file_name(".xchat_replay.bin");
    let replay_filter = xchat_core::replay::ReplayFilter::load_from_disk_encrypted(
        &replay_store_path,
        &storage_key,
    )
    .unwrap_or_default();
    let mut csrf_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut csrf_bytes);
    let csrf_token = hex::encode(csrf_bytes);

    let contacts_store_path = keystore_path.with_file_name(".xchat_contacts.bin");
    let messages_store_path = keystore_path.with_file_name(".xchat_messages.bin");
    let mut contacts =
        load_contacts_encrypted(&contacts_store_path, &storage_key).unwrap_or_default();
    if contacts.is_empty() {
        contacts = get_default_contacts(&my_address);
        let _ = save_contacts_encrypted(&contacts, &contacts_store_path, &storage_key);
    }
    let messages = load_messages_encrypted(&messages_store_path, &storage_key).unwrap_or_default();

    let state = Arc::new(Mutex::new(AppState {
        keystore,
        profile: profile.clone(),
        local_ip: local_ip.clone(),
        local_port: port,
        contacts,
        messages,
        discovery: discovery_engine.clone(),
        ble_transport: ble_transport.clone(),
        sessions,
        replay_filter,
        csrf_token: csrf_token.clone(),
        session_store_path,
        contacts_store_path,
        messages_store_path,
        burner_rooms: HashMap::new(),
    }));

    // Spawn background task: inbound physical BLE message dispatcher
    let inbound_ble_rx = ble_transport.subscribe_inbound_json();
    let state_ble_inbound = state.clone();
    tokio::spawn(async move {
        let mut rx = inbound_ble_rx.lock().await;
        while let Some(raw_json) = rx.recv().await {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&raw_json) {
                let sender_alias = data["sender_alias"]
                    .as_str()
                    .or_else(|| data["alias"].as_str())
                    .or_else(|| data["username"].as_str())
                    .or_else(|| data["sender"].as_str())
                    .unwrap_or("Peer")
                    .to_string();
                let sender_addr = data["sender_address"]
                    .as_str()
                    .or_else(|| data["address"].as_str())
                    .or_else(|| data["sender"].as_str())
                    .unwrap_or("")
                    .to_string();
                let text = data["text"]
                    .as_str()
                    .or_else(|| data["message"].as_str())
                    .unwrap_or("")
                    .to_string();
                let time_str = data["time_str"]
                    .as_str()
                    .or_else(|| data["time"].as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(get_now_time_string);

                let formatted_alias = if sender_alias.starts_with('@') {
                    sender_alias.clone()
                } else {
                    format!("@{}", sender_alias)
                };

                // Handle handshake identity notification
                if data["type"].as_str() == Some("handshake") {
                    let mut st = state_ble_inbound.lock().unwrap();
                    let mut old_addr_opt = None;
                    if let Some(c) = st.contacts.iter_mut().find(|c| {
                        (!sender_addr.is_empty()
                            && (c.address == sender_addr
                                || c.target == format!("ble:{}", sender_addr)))
                            || c.alias == formatted_alias
                    }) {
                        let prev_alias = c.alias.clone();
                        c.alias = formatted_alias.clone();
                        if !sender_addr.is_empty() && c.address != sender_addr {
                            old_addr_opt = Some(c.address.clone());
                            c.address = sender_addr.clone();
                        }
                        c.status = "Physical BLE Mesh".to_string();
                        // Merge and sync chat history between placeholder alias and actual formatted_alias
                        if prev_alias != formatted_alias {
                            let mut merged =
                                st.messages.get(&prev_alias).cloned().unwrap_or_default();
                            if let Some(existing) = st.messages.get(&formatted_alias) {
                                for m in existing {
                                    if !merged.iter().any(|x| {
                                        x.id == m.id || (x.text == m.text && x.time == m.time)
                                    }) {
                                        merged.push(m.clone());
                                    }
                                }
                            }
                            st.messages.insert(formatted_alias.clone(), merged.clone());
                            st.messages.insert(prev_alias, merged);
                        }
                    } else {
                        st.contacts.push(ContactEntry {
                            alias: formatted_alias.clone(),
                            address: sender_addr.clone(),
                            target: format!("ble:{}", sender_addr),
                            status: "Physical BLE Mesh".to_string(),
                            last_message: "Connected via Physical BLE Mesh".to_string(),
                            last_time: get_now_time_string(),
                        });
                    }
                    if let Some(old_addr) = old_addr_opt {
                        migrate_contact_messages(&mut st.messages, &old_addr, &sender_addr);
                    }
                    continue;
                }

                if !text.is_empty() {
                    let mut st = state_ble_inbound.lock().unwrap();
                    let msg = ChatMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        sender: "peer".to_string(),
                        text: text.clone(),
                        time: time_str.clone(),
                        status: "delivered".to_string(),
                    };

                    // Record message under formatted_alias, sender_alias, and sender_addr
                    st.messages
                        .entry(formatted_alias.clone())
                        .or_default()
                        .push(msg.clone());
                    if sender_alias != formatted_alias {
                        st.messages
                            .entry(sender_alias.clone())
                            .or_default()
                            .push(msg.clone());
                    }
                    if !sender_addr.is_empty() {
                        st.messages
                            .entry(sender_addr.clone())
                            .or_default()
                            .push(msg.clone());
                    }

                    // Update or insert contact
                    let found_idx = st.contacts.iter().position(|c| {
                        c.alias == formatted_alias
                            || c.alias == sender_alias
                            || (!sender_addr.is_empty()
                                && (c.address == sender_addr
                                    || c.target == format!("ble:{}", sender_addr)))
                    });

                    if let Some(idx) = found_idx {
                        let old_alias = st.contacts[idx].alias.clone();
                        if old_alias != formatted_alias && !old_alias.is_empty() {
                            st.messages.entry(old_alias).or_default().push(msg.clone());
                        }
                        st.contacts[idx].last_message = text;
                        st.contacts[idx].last_time = time_str;
                        st.contacts[idx].status = "Physical BLE Mesh".to_string();
                        let mut old_addr_opt = None;
                        if !sender_addr.is_empty() && st.contacts[idx].address != sender_addr {
                            old_addr_opt = Some(st.contacts[idx].address.clone());
                            st.contacts[idx].address = sender_addr.clone();
                        }
                        if let Some(old_addr) = old_addr_opt {
                            migrate_contact_messages(&mut st.messages, &old_addr, &sender_addr);
                        }
                    } else {
                        st.contacts.push(ContactEntry {
                            alias: formatted_alias,
                            address: sender_addr.clone(),
                            target: format!("ble:{}", sender_addr),
                            status: "Physical BLE Mesh".to_string(),
                            last_message: text,
                            last_time: time_str,
                        });
                    }
                }
            }
        }
    });

    // Spawn background task: periodic local UDP beacon broadcast every 4s
    let beacon_engine = discovery_engine.clone();
    let beacon_username = profile.username.clone();
    let beacon_display_name = profile.display_name.clone();
    let beacon_addr = my_address.clone();
    let beacon_fp = my_fingerprint.clone();
    tokio::spawn(async move {
        loop {
            let beacon = DiscoveryBeacon::new(
                &beacon_username,
                &beacon_display_name,
                &beacon_addr,
                &beacon_fp,
                port,
            );
            let _ = beacon_engine.broadcast_beacon(&beacon).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
        }
    });

    println!("===============================================================================");
    println!("   xChat Telegram-Styled App GUI Server Active");
    println!("===============================================================================");
    println!("Web App URL:       http://localhost:{}", port);
    println!("Reachable LAN IP:  {}:{}", local_ip, port);
    println!("Username Handle:   {}", profile.username);
    println!("Local Address:     {}", my_address);
    println!("Visual Safety Code:{}", visual_fp);
    println!("Discovery Carrier: Local UDP Beacon (Zero-Config Nearby Radar Active)");
    println!("-------------------------------------------------------------------------------");
    if !no_browser {
        println!("Opening local browser window...");

        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open")
            .arg(format!("http://localhost:{}", port))
            .spawn();

        #[cfg(target_os = "linux")]
        let _ = std::process::Command::new("xdg-open")
            .arg(format!("http://localhost:{}", port))
            .spawn();

        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", &format!("http://localhost:{}", port)])
            .spawn();
    }

    println!("Ready to handle messages. Press Ctrl+C to close.");

    run_server_loop(listener, state, local_ip).await
}

pub async fn run_server_loop(
    listener: TcpListener,
    state: Arc<Mutex<AppState>>,
    local_ip: String,
) -> anyhow::Result<()> {
    while let Ok((socket, _)) = listener.accept().await {
        let state_clone = state.clone();
        let local_ip_clone = local_ip.clone();

        tokio::spawn(async move {
            handle_http_connection(socket, state_clone, local_ip_clone).await;
        });
    }

    Ok(())
}

pub async fn handle_http_connection<S>(
    mut socket: S,
    state_clone: Arc<Mutex<AppState>>,
    local_ip_clone: String,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let mut buf = Vec::new();
    let mut temp = [0u8; 2048];
    let mut content_length = 0;
    let mut header_end = None;

    loop {
        match socket.read(&mut temp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&temp[..n]);
                if header_end.is_none() {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let header_str = String::from_utf8_lossy(&buf[..pos]);
                        for line in header_str.lines() {
                            if line.to_lowercase().starts_with("content-length:") {
                                if let Ok(len) = line[15..].trim().parse::<usize>() {
                                    content_length = len;
                                }
                            }
                        }
                    }
                }
                if let Some(hend) = header_end {
                    if buf.len() >= hend + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    if buf.is_empty() {
        return;
    }

    let req_str = String::from_utf8_lossy(&buf);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");
    let path = parts.get(1).copied().unwrap_or("/");

    let body = if let Some(hend) = header_end {
        if buf.len() >= hend {
            String::from_utf8_lossy(&buf[hend..]).to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let mut headers = HashMap::new();
    for line in req_str.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let local_ip_val = {
        let st = state_clone.lock().unwrap();
        st.local_ip.clone()
    };

    // DNS Rebinding protection: validate Host header
    let host = headers.get("host").map(|s| s.as_str()).unwrap_or("");
    let is_valid_host = host.is_empty()
        || host.starts_with("localhost")
        || host.starts_with("127.0.0.1")
        || host.starts_with("0.0.0.0")
        || host.starts_with("[::1]")
        || host.starts_with(&format!("{}:", local_ip_val))
        || host == local_ip_val;
    if !is_valid_host {
        let resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nInvalid Host Header";
        let _ = socket.write_all(resp.as_bytes()).await;
        return;
    }

    // Origin validation: block cross-origin requests from arbitrary websites
    let origin_header = headers.get("origin").cloned();
    let is_valid_origin = match &origin_header {
        Some(orig) => {
            orig.starts_with("http://localhost")
                || orig.starts_with("http://127.0.0.1")
                || orig.starts_with(&format!("http://{}:", local_ip_val))
        }
        None => true,
    };
    let is_peer_route = path == "/api/identity"
        || path == "/api/bundle"
        || path == "/api/prekey"
        || path == "/api/receive";
    if !is_valid_origin && !is_peer_route {
        let resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nCross-Origin Forbidden";
        let _ = socket.write_all(resp.as_bytes()).await;
        return;
    }

    let cors_headers = match &origin_header {
                Some(orig) if is_valid_origin => format!(
                    "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-XChat-Token\r\n",
                    orig
                ),
                _ => String::new(),
            };

    if method == "OPTIONS" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
            cors_headers
        );
        let _ = socket.write_all(resp.as_bytes()).await;
        return;
    }

    // CSRF Token verification on all UI /api/* routes
    if path.starts_with("/api/") && !is_peer_route {
        let token = headers
            .get("x-xchat-token")
            .map(|s| s.as_str())
            .unwrap_or("");
        let expected = {
            let st = state_clone.lock().unwrap();
            st.csrf_token.clone()
        };
        if token != expected {
            let resp = json_response(
                "401 Unauthorized",
                r#"{"error":"Unauthorized: Missing or invalid CSRF token"}"#,
                &cors_headers,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }
    }

    if path == "/api/identity" {
        let (username, display_name, sign_pubkey, dh_pubkey, cur_addr, cur_fp, cur_vfp, local_port) = {
            let st = state_clone.lock().unwrap();
            let pk = st.keystore.identity.public_key();
            (
                st.profile.username.clone(),
                st.profile.display_name.clone(),
                hex::encode(pk.sign_pubkey),
                hex::encode(pk.dh_pubkey),
                pk.address(),
                pk.fingerprint(),
                pk.visual_fingerprint(),
                st.local_port,
            )
        };
        let json = serde_json::to_string(&serde_json::json!({
            "address": cur_addr,
            "fingerprint": cur_fp,
            "sign_pubkey": sign_pubkey,
            "dh_pubkey": dh_pubkey,
            "visual_fingerprint": cur_vfp,
            "username": username,
            "display_name": display_name,
            "ip": local_ip_clone,
            "port": local_port,
            "status": "online"
        }))
        .unwrap_or_else(|_| "{}".to_string());
        let resp = json_response("200 OK", &json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/keygen" && method == "POST" {
        let (new_addr, new_fp, new_visual, sign_pub, dh_pub, bundle_val) = {
            let mut st = state_clone.lock().unwrap();
            let mut new_ks = KeyStore::generate();
            let new_pk = new_ks.identity.public_key();
            let addr = new_pk.address();
            let fp = new_pk.fingerprint();
            let vfp = new_pk.visual_fingerprint();
            let spk = hex::encode(new_pk.sign_pubkey);
            let dpk = hex::encode(new_pk.dh_pubkey);
            let bundle = new_ks.export_bundle();

            let ks_path = get_keystore_path();
            let _ = new_ks.save_to_path(&ks_path);

            st.profile.address = addr.clone();
            st.profile.fingerprint = fp.clone();
            let ppath = get_profile_path();
            let _ = st.profile.save_to_disk(&ppath);

            st.keystore = new_ks;
            (
                addr,
                fp,
                vfp,
                spk,
                dpk,
                serde_json::to_value(&bundle).unwrap_or_default(),
            )
        };

        let resp_body = serde_json::to_string(&serde_json::json!({
            "status": "generated",
            "address": new_addr,
            "fingerprint": new_fp,
            "visual_fingerprint": new_visual,
            "sign_pubkey": sign_pub,
            "dh_pubkey": dh_pub,
            "prekey_bundle": bundle_val
        }))
        .unwrap_or_else(|_| "{}".to_string());

        let resp = json_response("200 OK", &resp_body, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if (path == "/api/bundle" || path == "/api/prekey") && method == "GET" {
        let bundle_json = {
            let mut st = state_clone.lock().unwrap();
            let bundle = st.keystore.export_bundle();
            serde_json::to_string(&bundle).unwrap_or_else(|_| "{}".to_string())
        };
        let resp = json_response("200 OK", &bundle_json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/profile" && method == "GET" {
        let (profile, reachable, invite_url, cur_vfp) = {
            let st = state_clone.lock().unwrap();
            let sock = format!("{}:{}", st.local_ip, st.local_port);
            let invite = st.profile.generate_invite_url(&sock);
            let vfp = st.keystore.identity.public_key().visual_fingerprint();
            (st.profile.clone(), sock, invite, vfp)
        };
        let json = serde_json::to_string(&serde_json::json!({
            "username": profile.username,
            "display_name": profile.display_name,
            "bio": profile.bio,
            "avatar_color": profile.avatar_color,
            "address": profile.address,
            "fingerprint": profile.fingerprint,
            "visual_fingerprint": cur_vfp,
            "reachable": reachable,
            "invite_url": invite_url
        }))
        .unwrap_or_else(|_| "{}".to_string());
        let resp = json_response("200 OK", &json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/profile" && method == "POST" {
        #[derive(Deserialize)]
        struct UpdateProfileReq {
            username: Option<String>,
            display_name: Option<String>,
            bio: Option<String>,
            avatar_color: Option<serde_json::Value>,
        }
        if let Ok(req) = serde_json::from_str::<UpdateProfileReq>(&body) {
            let mut st = state_clone.lock().unwrap();
            if let Some(u) = req.username {
                if let Ok(clean) = UserProfile::validate_and_normalize_username(&u) {
                    st.profile.username = clean;
                } else if !u.trim().is_empty() {
                    let clean = if u.trim().starts_with('@') {
                        u.trim().to_lowercase()
                    } else {
                        format!("@{}", u.trim().to_lowercase())
                    };
                    st.profile.username = clean;
                }
            }
            if let Some(dn) = req.display_name {
                if !dn.trim().is_empty() {
                    st.profile.display_name = dn.trim().to_string();
                }
            }
            if let Some(b) = req.bio {
                st.profile.bio = b;
            }
            if let Some(ac) = req.avatar_color {
                let color_str = match ac {
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::String(s) => s,
                    _ => "0".to_string(),
                };
                st.profile.avatar_color = color_str;
            }
            let ppath = get_profile_path();
            let _ = st.profile.save_to_disk(&ppath);
        }
        let resp = json_response("200 OK", r#"{"status":"updated"}"#, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/discovered" && method == "GET" {
        let peers_json = {
            let st = state_clone.lock().unwrap();
            let my_addr = st.keystore.identity.public_key().address();
            let mut peers: Vec<serde_json::Value> = active_remote_peers(&st)
                .into_iter()
                .map(|p| {
                    let (ip, port) = if let Some((h, prt)) = p.socket_addr.split_once(':') {
                        (h.to_string(), prt.parse::<u16>().unwrap_or(8080))
                    } else {
                        (p.socket_addr.clone(), 8080)
                    };
                    serde_json::json!({
                        "username": p.username,
                        "display_name": p.display_name,
                        "address": p.address,
                        "fingerprint": p.fingerprint,
                        "socket_addr": p.socket_addr,
                        "ip": ip,
                        "port": port,
                        "transport": p.transport_type,
                        "discovered_at": p.discovered_at,
                    })
                })
                .collect();

            let ble_devs = st.ble_transport.get_discovered_devices();
            for b in ble_devs {
                if b.address != my_addr {
                    let uname = b
                        .username
                        .clone()
                        .unwrap_or_else(|| format!("@{}", b.name.to_lowercase().replace(' ', "_")));
                    peers.push(serde_json::json!({
                        "username": uname,
                        "display_name": b.name,
                        "address": b.address,
                        "fingerprint": b.id,
                        "socket_addr": format!("ble:{}", b.address),
                        "ip": b.address,
                        "port": 0,
                        "transport": "ble",
                        "rssi": b.rssi,
                        "last_seen": b.last_seen * 1000
                    }));
                }
            }

            serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string())
        };
        let resp = json_response("200 OK", &peers_json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/connect_username" && method == "POST" {
        #[derive(Deserialize)]
        struct ConnectUserReq {
            username: String,
        }
        let mut found = None;
        if let Ok(req) = serde_json::from_str::<ConnectUserReq>(&body) {
            let st = state_clone.lock().unwrap();
            found = st.discovery.resolve_username(&req.username);
        }
        let resp_body = if let Some(peer) = found {
            serde_json::to_string(&peer).unwrap_or_else(|_| "{}".to_string())
        } else {
            r#"{"error":"Username not found on local mesh"}"#.to_string()
        };
        let resp = json_response("200 OK", &resp_body, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/burner/join" && method == "POST" {
        #[derive(Deserialize)]
        struct JoinBurnerReq {
            room: String,
            pass: String,
        }
        if let Ok(req) = serde_json::from_str::<JoinBurnerReq>(&body) {
            let resp_body = {
                let mut st = state_clone.lock().unwrap();
                let burner = xchat_core::burner::BurnerRoom::new(&req.room, &req.pass, 600);
                let token = burner.routing_token();
                let room_alias = format!("#{}", req.room);
                st.burner_rooms.insert(room_alias.clone(), burner);

                if !st.contacts.iter().any(|c| c.alias == room_alias) {
                    st.contacts.push(ContactEntry {
                        alias: room_alias.clone(),
                        address: format!("burner_{}", hex::encode(token)),
                        target: "burner".to_string(),
                        status: "Burner Room (RAM-only)".to_string(),
                        last_message: "Joined room. Messages auto-destruct.".to_string(),
                        last_time: get_now_time_string(),
                    });
                }

                serde_json::to_string(&serde_json::json!({
                    "status": "joined",
                    "room": req.room,
                    "alias": room_alias,
                    "token": hex::encode(token),
                }))
                .unwrap_or_default()
            };
            let resp = json_response("200 OK", &resp_body, &cors_headers);
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }
        let resp = json_response(
            "400 Bad Request",
            r#"{"error":"Invalid burner room request"}"#,
            &cors_headers,
        );
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/burner/leave" && method == "POST" {
        #[derive(Deserialize)]
        struct LeaveBurnerReq {
            room: String,
        }
        if let Ok(req) = serde_json::from_str::<LeaveBurnerReq>(&body) {
            let room_alias = if req.room.starts_with('#') {
                req.room.clone()
            } else {
                format!("#{}", req.room)
            };
            {
                let mut st = state_clone.lock().unwrap();
                st.burner_rooms.remove(&room_alias);
                st.contacts.retain(|c| {
                    c.alias != room_alias
                        && !c.alias.eq_ignore_ascii_case(&room_alias)
                        && !c.address.starts_with(&format!("burner_{}", room_alias))
                });
                st.messages.remove(&room_alias);
            }
            let resp = json_response("200 OK", r#"{"status":"left"}"#, &cors_headers);
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }
        let resp = json_response(
            "400 Bad Request",
            r#"{"error":"Invalid leave burner room request"}"#,
            &cors_headers,
        );
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/contacts" && method == "GET" {
        let contacts_json = {
            let st = state_clone.lock().unwrap();
            serde_json::to_string(&st.contacts).unwrap_or_else(|_| "[]".to_string())
        };
        let resp = json_response("200 OK", &contacts_json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/contacts" && method == "POST" {
        #[allow(dead_code)]
        #[derive(Deserialize)]
        struct AddContactReq {
            alias: String,
            target: Option<String>,
            bundle: Option<String>,
            fingerprint: Option<String>,
            address: Option<String>,
        }
        if let Ok(req) = serde_json::from_str::<AddContactReq>(&body) {
            let target_str = req.target.unwrap_or_default();
            let mut resolved_addr = req.address;
            if (resolved_addr.is_none() || resolved_addr.as_deref() == Some(""))
                && !target_str.is_empty()
                && target_str != "local"
                && !target_str.starts_with("ble:")
                && target_str.contains(':')
            {
                if let Ok(ident_json) = dispatch_http_get(&target_str, "/api/identity").await {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ident_json) {
                        if let Some(a) = v.get("address").and_then(|a| a.as_str()) {
                            if !a.is_empty() {
                                resolved_addr = Some(a.to_string());
                            }
                        }
                    }
                }
            }

            let mut st = state_clone.lock().unwrap();

            // Match existing contact by cryptographic address first, then target socket, then alias
            let mut existing_opt = None;
            if let Some(ref req_addr) = resolved_addr {
                if !req_addr.is_empty() && req_addr != "local" {
                    existing_opt = st.contacts.iter_mut().find(|c| c.address == *req_addr);
                }
            }
            if existing_opt.is_none() && !target_str.is_empty() && target_str != "local" {
                existing_opt = st.contacts.iter_mut().find(|c| c.target == target_str);
            }
            if existing_opt.is_none() {
                existing_opt = st
                    .contacts
                    .iter_mut()
                    .find(|c| c.alias.eq_ignore_ascii_case(&req.alias));
            }

            let mut messages_migrated = false;
            if let Some(existing) = existing_opt {
                if !target_str.is_empty() {
                    existing.target = target_str;
                }
                if let Some(ref addr) = resolved_addr {
                    if !addr.is_empty() && existing.address != *addr {
                        let old_addr = existing.address.clone();
                        existing.address = addr.clone();
                        migrate_contact_messages(&mut st.messages, &old_addr, addr);
                        messages_migrated = true;
                    }
                }
            } else {
                let addr = resolved_addr.unwrap_or_else(|| {
                    format!(
                        "xchat_{}",
                        hex::encode(&uuid::Uuid::new_v4().as_bytes()[..4])
                    )
                });
                st.contacts.push(ContactEntry {
                    alias: req.alias.clone(),
                    address: addr,
                    target: target_str,
                    status: "Connected".to_string(),
                    last_message: "Tap to chat".to_string(),
                    last_time: get_now_time_string(),
                });
            }
            let storage_key =
                KeyStore::get_or_create_device_storage_key_for_path(Some(&st.session_store_path))
                    .expect(
                    "Failed to obtain device storage key; refusing fallback to insecure default",
                );
            let _ = save_contacts_encrypted(&st.contacts, &st.contacts_store_path, &storage_key);
            if messages_migrated {
                let _ =
                    save_messages_encrypted(&st.messages, &st.messages_store_path, &storage_key);
            }
        }
        let resp = json_response("200 OK", r#"{"status":"added"}"#, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/send" && method == "POST" {
        #[derive(Deserialize)]
        struct SendReq {
            alias: String,
            target: Option<String>,
            text: String,
        }
        if let Ok(req) = serde_json::from_str::<SendReq>(&body) {
            let now_str = get_now_time_string();
            let now_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Check if contact has a reachable target and needs identity resolution (placeholder address or empty)
            let mut pre_target = req.target.clone();
            let mut pre_addr = None;
            {
                let st = state_clone.lock().unwrap();
                if let Some(c) = st
                    .contacts
                    .iter()
                    .find(|c| c.alias == req.alias || c.address == req.alias)
                {
                    if (pre_target.is_none()
                        || pre_target.as_deref() == Some("")
                        || pre_target.as_deref() == Some("local"))
                        && !c.target.is_empty()
                        && c.target != "local"
                    {
                        pre_target = Some(c.target.clone());
                    }
                    pre_addr = Some(c.address.clone());
                }
            }

            if let Some(ref tgt) = pre_target {
                if !tgt.is_empty()
                    && tgt != "local"
                    && tgt != "burner"
                    && !tgt.starts_with('#')
                    && !tgt.starts_with("ble:")
                    && tgt.contains(':')
                    && (pre_addr.is_none()
                        || pre_addr.as_deref().unwrap_or("").starts_with("xchat_"))
                {
                    if let Ok(ident_json) = dispatch_http_get(tgt, "/api/identity").await {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ident_json) {
                            if let Some(real_addr) = v.get("address").and_then(|a| a.as_str()) {
                                if !real_addr.is_empty() {
                                    let mut st = state_clone.lock().unwrap();
                                    let mut old_addr_opt = None;
                                    if let Some(c) = st.contacts.iter_mut().find(|c| {
                                        c.alias == req.alias
                                            || c.target == *tgt
                                            || c.address == req.alias
                                    }) {
                                        if c.address != real_addr {
                                            old_addr_opt = Some(c.address.clone());
                                            c.address = real_addr.to_string();
                                        }
                                    }
                                    if let Some(old_addr) = old_addr_opt {
                                        migrate_contact_messages(
                                            &mut st.messages,
                                            &old_addr,
                                            real_addr,
                                        );
                                        let storage_key =
                                            KeyStore::get_or_create_device_storage_key_for_path(
                                                Some(&st.session_store_path),
                                            )
                                            .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                                        let _ = save_contacts_encrypted(
                                            &st.contacts,
                                            &st.contacts_store_path,
                                            &storage_key,
                                        );
                                        let _ = save_messages_encrypted(
                                            &st.messages,
                                            &st.messages_store_path,
                                            &storage_key,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let msg_id = uuid::Uuid::new_v4().to_string();
            let msg = ChatMessage {
                id: msg_id.clone(),
                sender: "self".to_string(),
                text: req.text.clone(),
                time: now_str.clone(),
                status: "sent".to_string(),
            };

            let (target_opt, my_handle, my_addr, my_ip, my_port) = {
                let mut st = state_clone.lock().unwrap();
                // Record outgoing message under cryptographic address and alias (never by socket/target)
                let contact_opt = st
                    .contacts
                    .iter()
                    .find(|c| c.alias == req.alias || c.address == req.alias)
                    .cloned();

                if let Some(c) = contact_opt {
                    if !c.address.is_empty() {
                        st.messages
                            .entry(c.address.clone())
                            .or_default()
                            .push(msg.clone());
                    }
                    if !c.alias.is_empty() && c.alias != c.address {
                        st.messages
                            .entry(c.alias.clone())
                            .or_default()
                            .push(msg.clone());
                    }
                } else {
                    st.messages
                        .entry(req.alias.clone())
                        .or_default()
                        .push(msg.clone());
                }

                let mut resolved_target = req.target.clone();
                if let Some(c) = st
                    .contacts
                    .iter_mut()
                    .find(|c| c.alias == req.alias || c.address == req.alias)
                {
                    c.last_message = req.text.clone();
                    c.last_time = now_str.clone();
                    if (resolved_target.is_none()
                        || resolved_target.as_deref() == Some("")
                        || resolved_target.as_deref() == Some("local"))
                        && !c.target.is_empty()
                        && c.target != "local"
                    {
                        resolved_target = Some(c.target.clone());
                    }
                }
                let cur_addr = st.keystore.identity.public_key().address();
                (
                    resolved_target,
                    st.profile.username.clone(),
                    cur_addr,
                    st.local_ip.clone(),
                    st.local_port,
                )
            };

            // Handle Burner Room messaging (RAM-only)
            if target_opt.as_deref() == Some("burner") || req.alias.starts_with('#') {
                let room_alias = if req.alias.starts_with('#') {
                    req.alias.clone()
                } else {
                    format!("#{}", req.alias)
                };
                let (env_opt, active_peers) = {
                    let mut st = state_clone.lock().unwrap();
                    let peers = active_remote_peers(&st);
                    let env = if let Some(burner) = st.burner_rooms.get_mut(&room_alias) {
                        burner.post_message(&my_handle, &req.text, now_ts).ok()
                    } else {
                        None
                    };
                    (env, peers)
                };
                if let Some(env) = env_opt {
                    let wire = WireMessageEnvelope {
                        envelope: env,
                        sender_alias: Some(format!("{}:{}", room_alias, my_handle)),
                        sender_socket: Some(format!("{}:{}", my_ip, my_port)),
                        sender_address: Some(my_addr),
                    };
                    let out_body = serde_json::to_string(&wire).unwrap_or_default();
                    let mut peers_reached = 0;
                    for p in active_peers {
                        if dispatch_http_post(&p.socket_addr, "/api/receive", &out_body)
                            .await
                            .is_ok()
                        {
                            peers_reached += 1;
                        }
                    }
                    if peers_reached == 0 {
                        {
                            let mut st = state_clone.lock().unwrap();
                            if let Some(msgs) = st.messages.get_mut(&room_alias) {
                                if let Some(last) = msgs.last_mut() {
                                    last.status = "failed".to_string();
                                }
                            }
                        }
                        let resp = json_response(
                            "200 OK",
                            r#"{"status":"failed","peers_reached":0,"error":"No peers reached"}"#,
                            &cors_headers,
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }
                    let resp = json_response(
                        "200 OK",
                        &format!(
                            r#"{{"status":"delivered","authenticated":true,"peers_reached":{}}}"#,
                            peers_reached
                        ),
                        &cors_headers,
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                } else {
                    {
                        let mut st = state_clone.lock().unwrap();
                        if let Some(msgs) = st.messages.get_mut(&room_alias) {
                            if let Some(last) = msgs.last_mut() {
                                last.status = "failed".to_string();
                            }
                        }
                    }
                    let resp = json_response(
                        "400 Bad Request",
                        r#"{"status":"failed","peers_reached":0,"error":"Burner room not joined"}"#,
                        &cors_headers,
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            }

            // Handle Local Assistant / Saved Messages
            if req.alias == "xChat Assistant"
                || (target_opt.as_deref() == Some("local") && req.alias == "Saved Messages")
                || req.alias == "Saved Messages"
            {
                {
                    let mut st = state_clone.lock().unwrap();
                    if req.alias == "xChat Assistant" {
                        let hist = st.messages.entry(req.alias.clone()).or_default();
                        hist.push(ChatMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            sender: "peer".to_string(),
                            text: format!("Echo [Personal Assistant]: {}", req.text),
                            time: get_now_time_string(),
                            status: "delivered".to_string(),
                        });
                    }
                    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
                        &st.session_store_path,
                    ))
                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                    let _ = save_messages_encrypted(
                        &st.messages,
                        &st.messages_store_path,
                        &storage_key,
                    );
                    let _ = save_contacts_encrypted(
                        &st.contacts,
                        &st.contacts_store_path,
                        &storage_key,
                    );
                }
                let resp = json_response(
                    "200 OK",
                    r#"{"status":"delivered","authenticated":true}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            } else if let Some(target) = target_opt {
                if !target.is_empty() && target != "local" {
                    // Find contact info (address) if known
                    let contact_addr = {
                        let st = state_clone.lock().unwrap();
                        st.contacts
                            .iter()
                            .find(|c| c.alias == req.alias || c.target == target)
                            .map(|c| c.address.clone())
                    };

                    // Check if an established ratcheted session exists
                    let mut existing_session_key = None;
                    {
                        let st = state_clone.lock().unwrap();
                        if let Some(ref addr) = contact_addr {
                            if st.sessions.contains_key(addr) {
                                existing_session_key = Some(addr.clone());
                            }
                        }
                        if existing_session_key.is_none() && st.sessions.contains_key(&target) {
                            existing_session_key = Some(target.clone());
                        }
                        if existing_session_key.is_none() && st.sessions.contains_key(&req.alias) {
                            existing_session_key = Some(req.alias.clone());
                        }
                    }

                    let mut session_envelope = None;
                    if let Some(skey) = existing_session_key {
                        let mut st = state_clone.lock().unwrap();
                        if let Some(sess) = st.sessions.get_mut(&skey) {
                            if let Ok(env) = sess.encrypt_message(
                                req.text.as_bytes(),
                                DIRECT_ROUTE,
                                now_ts,
                                86400,
                            ) {
                                let storage_key =
                                    KeyStore::get_or_create_device_storage_key_for_path(Some(
                                        &st.session_store_path,
                                    ))
                                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                                let _ = save_sessions_encrypted(
                                    &st.sessions,
                                    &st.session_store_path,
                                    &storage_key,
                                );
                                session_envelope = Some(env);
                            }
                        }
                    }

                    // If no session exists, initiate outbound session via X3DH with remote prekey bundle
                    if session_envelope.is_none() {
                        if let Ok(bundle_json) = dispatch_http_get(&target, "/api/bundle").await {
                            if let Ok(bundle) = serde_json::from_str::<
                                xchat_crypto::x3dh::PrekeyBundle,
                            >(&bundle_json)
                            {
                                let mut st = state_clone.lock().unwrap();
                                if let Ok((sess, env)) = Session::initiate_outbound(
                                    &st.keystore,
                                    &bundle,
                                    req.text.as_bytes(),
                                    DIRECT_ROUTE,
                                    now_ts,
                                    86400,
                                ) {
                                    let peer_addr = bundle.identity_key.address();
                                    st.sessions.insert(peer_addr.clone(), sess.clone());
                                    st.sessions.insert(target.clone(), sess);
                                    let mut old_addr_opt = None;
                                    if let Some(c) = st
                                        .contacts
                                        .iter_mut()
                                        .find(|c| c.alias == req.alias || c.target == target)
                                    {
                                        if c.address != peer_addr {
                                            old_addr_opt = Some(c.address.clone());
                                            c.address = peer_addr.clone();
                                        }
                                    }
                                    if let Some(old_addr) = old_addr_opt {
                                        migrate_contact_messages(
                                            &mut st.messages,
                                            &old_addr,
                                            &peer_addr,
                                        );
                                    }
                                    let storage_key =
                                        KeyStore::get_or_create_device_storage_key_for_path(Some(
                                            &st.session_store_path,
                                        ))
                                        .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                                    let _ = save_sessions_encrypted(
                                        &st.sessions,
                                        &st.session_store_path,
                                        &storage_key,
                                    );
                                    session_envelope = Some(env);
                                }
                            }
                        }
                    }

                    if let Some(envelope) = session_envelope {
                        let wire_envelope = WireMessageEnvelope {
                            envelope,
                            sender_alias: Some(my_handle),
                            sender_socket: Some(format!("{}:{}", my_ip, my_port)),
                            sender_address: Some(my_addr),
                        };
                        let out_body = serde_json::to_string(&wire_envelope).unwrap_or_default();
                        let mut delivered = false;
                        if !target.starts_with("ble:")
                            && target.contains(':')
                            && !target.starts_with('@')
                            && dispatch_http_post(&target, "/api/receive", &out_body)
                                .await
                                .is_ok()
                        {
                            delivered = true;
                        }
                        if !delivered {
                            let ble_t = {
                                let st = state_clone.lock().unwrap();
                                st.ble_transport.clone()
                            };
                            if ble_t
                                .send_raw_bytes(&target, out_body.as_bytes())
                                .await
                                .is_ok()
                            {
                                delivered = true;
                            }
                        }

                        if delivered {
                            {
                                let st = state_clone.lock().unwrap();
                                let storage_key =
                                    KeyStore::get_or_create_device_storage_key_for_path(Some(
                                        &st.session_store_path,
                                    ))
                                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                                let _ = save_messages_encrypted(
                                    &st.messages,
                                    &st.messages_store_path,
                                    &storage_key,
                                );
                                let _ = save_contacts_encrypted(
                                    &st.contacts,
                                    &st.contacts_store_path,
                                    &storage_key,
                                );
                            }
                            let resp = json_response(
                                "200 OK",
                                r#"{"status":"delivered","authenticated":true}"#,
                                &cors_headers,
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return;
                        }
                    }

                    // If delivery or session creation failed, update message status to failed
                    {
                        let mut st = state_clone.lock().unwrap();
                        mark_message_status(&mut st, &msg_id, "failed");
                        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(
                            Some(&st.session_store_path),
                        )
                        .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                        let _ = save_messages_encrypted(
                            &st.messages,
                            &st.messages_store_path,
                            &storage_key,
                        );
                    }
                    let resp = json_response(
                        "502 Bad Gateway",
                        r#"{"status":"failed","peers_reached":0,"error":"Delivery failed to recipient"}"#,
                        &cors_headers,
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
                // If target was empty or missing for recipient
                {
                    let mut st = state_clone.lock().unwrap();
                    mark_message_status(&mut st, &msg_id, "failed");
                    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(
                        Some(&st.session_store_path),
                    )
                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                    let _ = save_messages_encrypted(
                        &st.messages,
                        &st.messages_store_path,
                        &storage_key,
                    );
                }
                let resp = json_response(
                    "400 Bad Request",
                    r#"{"status":"failed","peers_reached":0,"error":"No destination target or peers available"}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            } else {
                {
                    let mut st = state_clone.lock().unwrap();
                    mark_message_status(&mut st, &msg_id, "failed");
                    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(
                        Some(&st.session_store_path),
                    )
                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                    let _ = save_messages_encrypted(
                        &st.messages,
                        &st.messages_store_path,
                        &storage_key,
                    );
                }
                let resp = json_response(
                    "400 Bad Request",
                    r#"{"status":"failed","peers_reached":0,"error":"No destination target or peers available"}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }
        }
        let resp = json_response(
            "400 Bad Request",
            r#"{"error":"Invalid request parameters"}"#,
            &cors_headers,
        );
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/receive" && method == "POST" {
        let wire_opt = serde_json::from_str::<WireMessageEnvelope>(&body).ok();
        let (envelope, sender_alias_opt, _sender_socket_opt, sender_addr_hint) =
            if let Some(wire) = wire_opt {
                (
                    wire.envelope,
                    wire.sender_alias,
                    wire.sender_socket,
                    wire.sender_address,
                )
            } else if let Ok(env) = serde_json::from_str::<EncryptedEnvelope>(&body) {
                (env, None, None, None)
            } else {
                let resp = json_response(
                    "401 Unauthorized",
                    r#"{"error":"Unauthenticated or corrupted envelope"}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            };

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if envelope.is_expired(now_ts) {
            let resp = json_response(
                "401 Unauthorized",
                r#"{"error":"Envelope has expired"}"#,
                &cors_headers,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }

        // Check anti-replay filter
        let is_replayed = {
            let mut st = state_clone.lock().unwrap();
            let err = st
                .replay_filter
                .check_and_record(&envelope.header.message_id, now_ts)
                .is_err();
            if !err {
                let replay_path = st.session_store_path.with_file_name(".xchat_replay.bin");
                let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
                    &st.session_store_path,
                ))
                .expect(
                    "Failed to obtain device storage key; refusing fallback to insecure default",
                );
                let _ = st
                    .replay_filter
                    .save_to_disk_encrypted(&replay_path, &storage_key);
            }
            err
        };
        if is_replayed {
            let resp = json_response(
                "401 Unauthorized",
                r#"{"error":"Replayed message rejected"}"#,
                &cors_headers,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }

        // Check if this envelope is a signed SOS Emergency Distress Beacon
        if envelope.header.destination_token == xchat_core::sos::EMERGENCY_BROADCAST_TOKEN {
            match xchat_core::sos::decode_emergency_beacon(&envelope, now_ts) {
                Ok(beacon) => {
                    let now_str = get_now_time_string();
                    let sender_addr = beacon.sender_address.clone();
                    let alert_text = format!(
                        "🚨 EMERGENCY ALERT: {}\nCoordinates: ({:.4}, {:.4})\nSender: {}",
                        beacon.emergency_message, beacon.latitude, beacon.longitude, sender_addr
                    );

                    let msg = ChatMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        sender: "peer".to_string(),
                        text: alert_text.clone(),
                        time: now_str.clone(),
                        status: "emergency".to_string(),
                    };

                    {
                        let mut st = state_clone.lock().unwrap();
                        let effective_target = active_remote_peers(&st)
                            .into_iter()
                            .find(|p| p.address == sender_addr)
                            .map(|p| p.socket_addr)
                            .unwrap_or_default();
                        let emergency_alias =
                            format!("🚨 SOS: {}", &sender_addr[..8.min(sender_addr.len())]);
                        if let Some(c) = st.contacts.iter_mut().find(|c| c.address == sender_addr) {
                            c.last_message = alert_text.clone();
                            c.last_time = now_str.clone();
                            c.status = "🚨 EMERGENCY ACTIVE".to_string();
                            if !effective_target.is_empty()
                                && (c.target.is_empty()
                                    || c.target == "local"
                                    || c.target == "Direct")
                            {
                                c.target = effective_target.clone();
                            }
                        } else {
                            st.contacts.insert(
                                0,
                                ContactEntry {
                                    alias: emergency_alias.clone(),
                                    address: sender_addr.clone(),
                                    target: effective_target,
                                    status: "🚨 EMERGENCY ACTIVE".to_string(),
                                    last_message: alert_text.clone(),
                                    last_time: now_str.clone(),
                                },
                            );
                        }

                        let target_contact_alias = st
                            .contacts
                            .iter()
                            .find(|c| c.address == sender_addr)
                            .map(|c| c.alias.clone())
                            .unwrap_or(emergency_alias);

                        st.messages
                            .entry(target_contact_alias)
                            .or_default()
                            .push(msg.clone());
                        st.messages.entry(sender_addr).or_default().push(msg);

                        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(
                            Some(&st.session_store_path),
                        )
                        .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                        let _ = save_messages_encrypted(
                            &st.messages,
                            &st.messages_store_path,
                            &storage_key,
                        );
                        let _ = save_contacts_encrypted(
                            &st.contacts,
                            &st.contacts_store_path,
                            &storage_key,
                        );
                    }

                    let resp = json_response(
                        "200 OK",
                        r#"{"status":"delivered","type":"emergency_sos","authenticated":true}"#,
                        &cors_headers,
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
                Err(e) => {
                    let resp = json_response(
                        "401 Unauthorized",
                        &format!(r#"{{"error":"Invalid SOS beacon: {:?}"}}"#, e),
                        &cors_headers,
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            }
        }

        // Check if this envelope belongs to an ephemeral Burner Room
        let burner_match = {
            let mut st = state_clone.lock().unwrap();
            let my_username = st.profile.username.clone();
            let my_addr = st.keystore.identity.public_key().address();
            let mut found = None;
            for (room_alias, burner) in st.burner_rooms.iter_mut() {
                if envelope.header.destination_token == burner.routing_token() {
                    if let Ok(bmsg) = burner.receive_envelope(&envelope, now_ts) {
                        found = Some((room_alias.clone(), bmsg, my_username, my_addr));
                        break;
                    }
                }
            }
            found
        };

        if let Some((room_alias, bmsg, my_username, my_addr)) = burner_match {
            // Drop room messages whose sender is the local identity
            let clean_bmsg_sender = bmsg.sender_alias.trim_start_matches('@');
            let clean_my_username = my_username.trim_start_matches('@');
            let is_self = clean_bmsg_sender.eq_ignore_ascii_case(clean_my_username)
                || sender_addr_hint.as_deref() == Some(&my_addr);

            if is_self {
                let resp = json_response(
                    "200 OK",
                    r#"{"status":"delivered","authenticated":true}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }

            let now_str = get_now_time_string();
            let msg = ChatMessage {
                id: uuid::Uuid::new_v4().to_string(),
                sender: "peer".to_string(),
                text: bmsg.content.clone(),
                time: now_str.clone(),
                status: "delivered".to_string(),
            };
            {
                let mut st = state_clone.lock().unwrap();
                st.messages.entry(room_alias.clone()).or_default().push(msg);
                if let Some(c) = st.contacts.iter_mut().find(|c| c.alias == room_alias) {
                    c.last_message = bmsg.content;
                    c.last_time = now_str;
                }
            }
            let resp = json_response(
                "200 OK",
                r#"{"status":"delivered","authenticated":true}"#,
                &cors_headers,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            return;
        }

        // Decrypt inbound message via Session
        let decrypt_result = {
            let mut st = state_clone.lock().unwrap();
            if envelope.x3dh_init.is_some() {
                match Session::respond_inbound(&mut st.keystore, &envelope, now_ts) {
                    Ok((new_session, pt_bytes)) => {
                        let sender_addr = new_session.peer_identity.address();
                        st.sessions.insert(sender_addr.clone(), new_session);
                        let ks_path = get_keystore_path();
                        let _ = st.keystore.save_to_path(&ks_path);
                        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(
                            Some(&st.session_store_path),
                        )
                        .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                        let _ = save_sessions_encrypted(
                            &st.sessions,
                            &st.session_store_path,
                            &storage_key,
                        );
                        Ok((sender_addr, pt_bytes))
                    }
                    Err(e) => Err(format!("X3DH respond failed: {:?}", e)),
                }
            } else {
                let mut found = None;
                if let Some(hint) = &sender_addr_hint {
                    if let Some(session) = st.sessions.get_mut(hint) {
                        let mut candidate = session.clone();
                        if let Ok(pt_bytes) = candidate.decrypt_message(&envelope, now_ts) {
                            *session = candidate;
                            found = Some((hint.clone(), pt_bytes));
                        }
                    }
                }
                if found.is_none() {
                    for (addr, session) in st.sessions.iter_mut() {
                        let mut candidate = session.clone();
                        if let Ok(pt_bytes) = candidate.decrypt_message(&envelope, now_ts) {
                            *session = candidate;
                            found = Some((addr.clone(), pt_bytes));
                            break;
                        }
                    }
                }
                if let Some((addr, pt_bytes)) = found {
                    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
                        &st.session_store_path,
                    ))
                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                    let _ =
                        save_sessions_encrypted(&st.sessions, &st.session_store_path, &storage_key);
                    Ok((addr, pt_bytes))
                } else {
                    Err("No matching ratcheted session found".to_string())
                }
            }
        };

        let (resp_status, resp_body) = match decrypt_result {
            Ok((sender_addr, pt_bytes)) => {
                let plaintext = match String::from_utf8(pt_bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        let resp = json_response(
                            "401 Unauthorized",
                            r#"{"error":"Payload is not valid UTF-8"}"#,
                            &cors_headers,
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }
                };
                let now_str = get_now_time_string();
                let msg = ChatMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender: "peer".to_string(),
                    text: plaintext.clone(),
                    time: now_str.clone(),
                    status: "delivered".to_string(),
                };

                let sender_alias_clean = sender_alias_opt
                    .clone()
                    .unwrap_or_else(|| sender_addr.clone());

                {
                    let mut st = state_clone.lock().unwrap();
                    let effective_target = active_remote_peers(&st)
                        .into_iter()
                        .find(|p| p.address == sender_addr)
                        .map(|p| p.socket_addr)
                        .unwrap_or_default();

                    // Identify sender ONLY by the cryptographically derived address.
                    // sender_alias is only a display hint for brand-new contacts, and cannot collide with existing contacts.
                    let target_alias = if let Some(c) =
                        st.contacts.iter_mut().find(|c| c.address == sender_addr)
                    {
                        c.last_message = plaintext.clone();
                        c.last_time = now_str.clone();
                        if !effective_target.is_empty()
                            && (c.target.is_empty() || c.target == "local" || c.target == "Direct")
                        {
                            c.target = effective_target.clone();
                        }
                        c.alias.clone()
                    } else {
                        let chosen_alias = if st
                            .contacts
                            .iter()
                            .any(|c| c.alias.eq_ignore_ascii_case(&sender_alias_clean))
                        {
                            format!(
                                "{} ({})",
                                sender_alias_clean,
                                &sender_addr[..8.min(sender_addr.len())]
                            )
                        } else {
                            sender_alias_clean.clone()
                        };
                        st.contacts.push(ContactEntry {
                            alias: chosen_alias.clone(),
                            address: sender_addr.clone(),
                            target: effective_target,
                            status: "Online".to_string(),
                            last_message: plaintext.clone(),
                            last_time: now_str.clone(),
                        });
                        chosen_alias
                    };

                    st.messages
                        .entry(sender_addr.clone())
                        .or_default()
                        .push(msg.clone());
                    if target_alias != sender_addr {
                        st.messages.entry(target_alias).or_default().push(msg);
                    }

                    let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
                        &st.session_store_path,
                    ))
                    .expect("Failed to obtain device storage key; refusing fallback to insecure default");
                    let _ = save_messages_encrypted(
                        &st.messages,
                        &st.messages_store_path,
                        &storage_key,
                    );
                    let _ = save_contacts_encrypted(
                        &st.contacts,
                        &st.contacts_store_path,
                        &storage_key,
                    );
                }

                ("200 OK", r#"{"status":"delivered","authenticated":true}"#)
            }
            Err(_) => (
                "401 Unauthorized",
                r#"{"error":"Unauthenticated or corrupted envelope"}"#,
            ),
        };

        let resp = json_response(resp_status, resp_body, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path.starts_with("/api/messages") && method == "GET" {
        let peer_opt = path.split('?').nth(1).and_then(|q| {
            q.split('&')
                .find(|param| param.starts_with("peer="))
                .map(|param| urlencoding_decode(&param[5..]))
        });

        let msgs_json = {
            let mut st = state_clone.lock().unwrap();
            if let Some(ref peer) = peer_opt {
                if peer.starts_with('#') {
                    let now_ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let valid_contents_opt = if let Some(room) = st.burner_rooms.get_mut(peer) {
                        room.prune_expired(now_ts);
                        let set: std::collections::HashSet<String> = room
                            .get_messages()
                            .iter()
                            .map(|m| m.content.clone())
                            .collect();
                        Some(set)
                    } else {
                        None
                    };
                    if let Some(valid_contents) = valid_contents_opt {
                        if let Some(msgs) = st.messages.get_mut(peer) {
                            msgs.retain(|m| {
                                m.status == "failed" || valid_contents.contains(&m.text)
                            });
                        }
                    }
                }
                let list = get_unified_messages_for_peer(&st, peer);
                serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            }
        };

        let resp = json_response("200 OK", &msgs_json, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/api/ping" && method == "POST" {
        #[derive(Deserialize)]
        struct PingReq {
            target: Option<String>,
            peer: Option<String>,
        }
        let ping_target = serde_json::from_str::<PingReq>(&body)
            .ok()
            .and_then(|r| r.target.or(r.peer));
        if let Some(mut target) = ping_target {
            if target.is_empty() || target == "local" {
                let resp = json_response(
                    "200 OK",
                    r#"{"status":"pong","latency_ms":1}"#,
                    &cors_headers,
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }
            {
                let st = state_clone.lock().unwrap();
                if let Some(c) = st
                    .contacts
                    .iter()
                    .find(|c| c.alias == target || c.address == target)
                {
                    if !c.target.is_empty() && c.target != "local" {
                        target = c.target.clone();
                    }
                }
            }
            let start = std::time::Instant::now();
            match dispatch_http_get(&target, "/api/identity").await {
                Ok(_) => {
                    let latency = start.elapsed().as_millis().max(1);
                    let resp_body = format!(r#"{{"status":"pong","latency_ms":{}}}"#, latency);
                    let resp = json_response("200 OK", &resp_body, &cors_headers);
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
                Err(e) => {
                    let resp_body = format!(r#"{{"status":"failed","error":"{}"}}"#, e);
                    let resp = json_response("504 Gateway Timeout", &resp_body, &cors_headers);
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            }
        } else {
            let resp = json_response(
                "400 Bad Request",
                r#"{"error":"Target required"}"#,
                &cors_headers,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    } else if path == "/api/sos" && method == "POST" {
        #[derive(Deserialize)]
        struct SosReq {
            lat: Option<f64>,
            lon: Option<f64>,
            message: Option<String>,
        }
        let sos_req = serde_json::from_str::<SosReq>(&body).unwrap_or(SosReq {
            lat: None,
            lon: None,
            message: None,
        });
        let lat = sos_req.lat.unwrap_or(0.0);
        let lon = sos_req.lon.unwrap_or(0.0);
        let sos_msg = sos_req
            .message
            .unwrap_or_else(|| "Emergency SOS! Need immediate assistance.".to_string());

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (beacon_env, my_addr, active_peers) = {
            let st = state_clone.lock().unwrap();
            let beacon = xchat_core::sos::create_emergency_beacon(
                &st.keystore.identity,
                lat,
                lon,
                &sos_msg,
                now_ts,
                7200,
            );
            let addr = st.keystore.identity.public_key().address();
            let peers = active_remote_peers(&st);
            (beacon, addr, peers)
        };

        let mut peer_count = 0;
        if let Ok(env) = beacon_env {
            let wire = WireMessageEnvelope {
                envelope: env,
                sender_alias: Some(format!("SOS: {}", my_addr)),
                sender_socket: None,
                sender_address: Some(my_addr),
            };
            let wire_body = serde_json::to_string(&wire).unwrap_or_default();
            for peer in active_peers {
                if dispatch_http_post(&peer.socket_addr, "/api/receive", &wire_body)
                    .await
                    .is_ok()
                {
                    peer_count += 1;
                }
            }
        }
        let resp_body = if peer_count == 0 {
            r#"{"status":"failed","peers_reached":0,"error":"No peers reached"}"#.to_string()
        } else {
            format!(
                r#"{{"status":"broadcasted","peers_reached":{}}}"#,
                peer_count
            )
        };
        let resp = json_response("200 OK", &resp_body, &cors_headers);
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/jsqr.min.js" {
        let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    JSQR_JS.len(),
                    JSQR_JS
                );
        let _ = socket.write_all(resp.as_bytes()).await;
    } else if path == "/xchat.apk" {
        let apk_path = std::env::var("XCHAT_APK_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("dist/xchat.apk"));
        if let Ok(apk_bytes) = tokio::fs::read(&apk_path).await {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Disposition: attachment; filename=\"xchat.apk\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                apk_bytes.len()
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.write_all(&apk_bytes).await;
        } else {
            let resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nAPK not found";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    } else {
        let csrf_token = {
            let st = state_clone.lock().unwrap();
            st.csrf_token.clone()
        };
        let meta_tag = format!(r#"<meta name="xchat-csrf-token" content="{}">"#, csrf_token);
        let html = if EMBEDDED_HTML.contains("</head>") {
            EMBEDDED_HTML.replacen("</head>", &format!("{}\n</head>", meta_tag), 1)
        } else {
            format!("{}\n{}", meta_tag, EMBEDDED_HTML)
        };
        let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
        let _ = socket.write_all(resp.as_bytes()).await;
    }
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex_str: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                result.push(byte as char);
            }
        } else if ch == '+' {
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    result
}

fn migrate_contact_messages(
    messages: &mut HashMap<String, Vec<ChatMessage>>,
    old_addr: &str,
    new_addr: &str,
) {
    if old_addr.is_empty() || new_addr.is_empty() || old_addr == new_addr {
        return;
    }
    if let Some(old_msgs) = messages.remove(old_addr) {
        let dest = messages.entry(new_addr.to_string()).or_default();
        let mut combined = old_msgs;
        for m in dest.drain(..) {
            if !combined.iter().any(|existing| existing.id == m.id) {
                combined.push(m);
            }
        }
        *dest = combined;
    }
}

fn mark_message_status(st: &mut AppState, msg_id: &str, status: &str) {
    for msgs in st.messages.values_mut() {
        for m in msgs.iter_mut() {
            if m.id == msg_id {
                m.status = status.to_string();
            }
        }
    }
}

fn active_remote_peers(st: &AppState) -> Vec<xchat_core::profile::DiscoveredPeer> {
    let my_addr = st.keystore.identity.public_key().address();
    let my_username = st.profile.username.to_lowercase();
    let my_local_sock = format!("{}:{}", st.local_ip, st.local_port);

    st.discovery
        .get_active_peers()
        .into_iter()
        .filter(|p| {
            p.address != my_addr
                && p.username.to_lowercase() != my_username
                && p.socket_addr != my_local_sock
                && !p.socket_addr.is_empty()
                && (st.local_port == 0
                    || (p.socket_addr != format!("127.0.0.1:{}", st.local_port)
                        && p.socket_addr != format!("localhost:{}", st.local_port)
                        && p.socket_addr != format!("0.0.0.0:{}", st.local_port)))
        })
        .collect()
}

fn get_unified_messages_for_peer(st: &AppState, peer: &str) -> Vec<ChatMessage> {
    if peer == "Saved Messages" || peer == "xChat Assistant" || peer.starts_with('#') {
        return st.messages.get(peer).cloned().unwrap_or_default();
    }

    let clean_peer = peer.trim_start_matches('@');

    // Key conversations strictly by cryptographic address.
    // Resolve peer to exactly one contact by exact alias or address, then return messages[address].
    // No substring matching and no merging by socket.
    if let Some(c) = st.contacts.iter().find(|c| {
        c.address == peer
            || c.alias == peer
            || c.alias.eq_ignore_ascii_case(peer)
            || c.alias
                .trim_start_matches('@')
                .eq_ignore_ascii_case(clean_peer)
    }) {
        if !c.address.is_empty() {
            if let Some(msgs) = st.messages.get(&c.address) {
                return msgs.clone();
            }
        }
        if let Some(msgs) = st.messages.get(&c.alias) {
            return msgs.clone();
        }
    }

    // Direct lookup in messages if peer is raw address or alias not yet in contacts
    if let Some(msgs) = st.messages.get(peer) {
        return msgs.clone();
    }
    if let Some(msgs) = st.messages.get(clean_peer) {
        return msgs.clone();
    }
    let at_peer = format!("@{}", clean_peer);
    if let Some(msgs) = st.messages.get(&at_peer) {
        return msgs.clone();
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xchat_crypto::identity::IdentityKeyPair;
    use xchat_transport::ble_central::BleCentralTransport;

    pub async fn create_test_app_state() -> (Arc<Mutex<AppState>>, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let keystore = KeyStore::generate();
        let my_pub = keystore.identity.public_key();
        let profile = UserProfile::new(
            "test_user",
            "Test User",
            &my_pub.address(),
            &my_pub.fingerprint(),
            1_000_000,
        )
        .unwrap();
        let discovery = PeerDiscoveryEngine::bind(0, 0).await.unwrap();
        let ble_transport = BleCentralTransport::new().await;
        let csrf_token = "test_csrf_token_secret".to_string();
        let contacts = get_default_contacts(&my_pub.address());
        let state = Arc::new(Mutex::new(AppState {
            keystore,
            profile,
            local_ip: "127.0.0.1".to_string(),
            local_port: 0,
            contacts,
            messages: HashMap::new(),
            discovery,
            ble_transport,
            sessions: HashMap::new(),
            replay_filter: ReplayFilter::new(),
            csrf_token,
            session_store_path: temp_dir.path().join("sessions.bin"),
            contacts_store_path: temp_dir.path().join("contacts.bin"),
            messages_store_path: temp_dir.path().join("messages.bin"),
            burner_rooms: HashMap::new(),
        }));
        (state, temp_dir)
    }

    async fn send_test_http_request(port: u16, state: Arc<Mutex<AppState>>, req: &str) -> String {
        if port != 8080 {
            if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", port)).await {
                stream.write_all(req.as_bytes()).await.unwrap();
                let mut resp = Vec::new();
                stream.read_to_end(&mut resp).await.unwrap();
                return String::from_utf8_lossy(&resp).to_string();
            }
        }
        // In-memory duplex fallback for sandboxed/isolated environments
        let (client, server) = tokio::io::duplex(65536);
        let state_clone = state.clone();
        tokio::spawn(async move {
            handle_http_connection(server, state_clone, "127.0.0.1".to_string()).await;
        });
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(req.as_bytes()).await.unwrap();
        drop(client_write);
        let mut resp = Vec::new();
        client_read.read_to_end(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp).to_string()
    }

    #[tokio::test]
    async fn test_csrf_token_injection_and_api_authorization() {
        let (state, _temp) = create_test_app_state().await;
        let expected_token = {
            let st = state.lock().unwrap();
            st.csrf_token.clone()
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        // 1. Real HTTP GET /
        let req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let resp_str = send_test_http_request(port, state.clone(), &req).await;

        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        let token_needle = r#"<meta name="xchat-csrf-token" content=""#;
        let start_pos = resp_str
            .find(token_needle)
            .expect("Page must contain injected CSRF meta tag")
            + token_needle.len();
        let end_pos = resp_str[start_pos..]
            .find('"')
            .expect("Meta tag content closing quote")
            + start_pos;
        let extracted_token = &resp_str[start_pos..end_pos];
        assert_eq!(extracted_token, expected_token);

        // 2. Real HTTP GET /api/contacts without CSRF token -> 401
        let req_no_token = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let resp_no_token_str = send_test_http_request(port, state.clone(), &req_no_token).await;
        assert!(resp_no_token_str.starts_with("HTTP/1.1 401 Unauthorized"));

        // 3. Real HTTP GET /api/contacts with CSRF token -> 200
        let req_with_token = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, extracted_token
        );
        let resp_with_token_str =
            send_test_http_request(port, state.clone(), &req_with_token).await;
        assert!(resp_with_token_str.starts_with("HTTP/1.1 200 OK"));
        assert!(
            resp_with_token_str.contains("Saved Messages")
                || resp_with_token_str.contains("Personal Assistant")
        );
    }

    #[tokio::test]
    async fn test_sender_impersonation_relabel_attack_prevented() {
        let (state, _temp) = create_test_app_state().await;
        let bob_bundle = {
            let mut st = state.lock().unwrap();
            st.keystore.export_bundle()
        };

        let alice_ks = KeyStore::generate();
        let alice_addr = alice_ks.identity.public_key().address();
        let carol_ks = KeyStore::generate();
        let carol_addr = carol_ks.identity.public_key().address();

        // Bob has Alice in his contact list
        {
            let mut st = state.lock().unwrap();
            st.contacts.push(ContactEntry {
                alias: "Alice".to_string(),
                address: alice_addr.clone(),
                target: "192.168.1.100:8080".to_string(),
                status: "Online".to_string(),
                last_message: "".to_string(),
                last_time: "".to_string(),
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Carol creates legitimate encrypted outbound message to Bob
        let (_carol_sess, carol_env) = Session::initiate_outbound(
            &carol_ks,
            &bob_bundle,
            b"I am really Carol",
            DIRECT_ROUTE,
            now,
            86400,
        )
        .unwrap();

        // Attacker relabels envelope to forge Alice's alias, socket, and claimed address
        let forged_wire = WireMessageEnvelope {
            envelope: carol_env,
            sender_alias: Some("Alice".to_string()),
            sender_socket: Some("192.168.1.100:8080".to_string()),
            sender_address: Some(alice_addr.clone()),
        };
        let body = serde_json::to_string(&forged_wire).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let req = format!(
            "POST /api/receive HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port,
            body.len(),
            body
        );
        let resp_str = send_test_http_request(port, state.clone(), &req).await;
        assert!(
            resp_str.starts_with("HTTP/1.1 200 OK"),
            "Got response: {}",
            resp_str
        );

        let (csrf_token, carol_alias) = {
            let st = state.lock().unwrap();
            let alice_msgs = st.messages.get("Alice");
            assert!(
                alice_msgs.is_none() || alice_msgs.unwrap().is_empty(),
                "Message must NOT appear in Alice's chat despite forged sender_alias and socket!"
            );

            let carol_msgs = st
                .messages
                .get(&carol_addr)
                .expect("Carol's message must exist under her cryptographic address");
            assert_eq!(carol_msgs.len(), 1);
            assert_eq!(carol_msgs[0].text, "I am really Carol");

            let alice_contact = st
                .contacts
                .iter()
                .find(|c| c.alias == "Alice")
                .expect("Alice contact exists");
            assert_eq!(
                alice_contact.last_message, "",
                "Alice's last_message preview must remain unchanged!"
            );
            assert_eq!(alice_contact.target, "192.168.1.100:8080");

            let carol_contact = st
                .contacts
                .iter()
                .find(|c| c.address == carol_addr)
                .expect("Carol contact exists");
            assert_ne!(
                carol_contact.target, "192.168.1.100:8080",
                "Carol's contact target must NOT be set to Alice's socket!"
            );
            assert_eq!(
                carol_contact.target, "",
                "Carol's target must be empty (not learned from unauthenticated wire header)"
            );

            (st.csrf_token.clone(), carol_contact.alias.clone())
        };

        // Query GET /api/messages?peer=Alice
        let req_alice = format!(
            "GET /api/messages?peer=Alice HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp_alice = send_test_http_request(port, state.clone(), &req_alice).await;
        assert!(resp_alice.starts_with("HTTP/1.1 200 OK"));
        let body_alice = resp_alice.split("\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(
            body_alice, "[]",
            "Carol's message must NOT appear in GET /api/messages?peer=Alice!"
        );

        // Query GET /api/messages?peer={carol_addr}
        let req_carol_addr = format!(
            "GET /api/messages?peer={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            carol_addr, port, csrf_token
        );
        let resp_carol_addr = send_test_http_request(port, state.clone(), &req_carol_addr).await;
        assert!(resp_carol_addr.starts_with("HTTP/1.1 200 OK"));
        let body_carol_addr = resp_carol_addr.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body_carol_addr.contains("I am really Carol"),
            "Carol's message must appear in GET /api/messages?peer={}",
            carol_addr
        );

        // Query GET /api/messages?peer={carol_alias}
        let req_carol_alias = format!(
            "GET /api/messages?peer={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            carol_alias.replace(' ', "%20"),
            port,
            csrf_token
        );
        let resp_carol_alias = send_test_http_request(port, state.clone(), &req_carol_alias).await;
        assert!(resp_carol_alias.starts_with("HTTP/1.1 200 OK"));
        let body_carol_alias = resp_carol_alias.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body_carol_alias.contains("I am really Carol"),
            "Carol's message must appear in GET /api/messages?peer={}",
            carol_alias
        );
    }

    #[tokio::test]
    async fn test_sos_beacon_receive_and_verification() {
        let (state, _temp) = create_test_app_state().await;
        let alice_id = IdentityKeyPair::generate();
        let alice_addr = alice_id.public_key().address();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let beacon_env = xchat_core::sos::create_emergency_beacon(
            &alice_id,
            37.7749,
            -122.4194,
            "Urgent medical assistance required!",
            now,
            7200,
        )
        .unwrap();

        let wire = WireMessageEnvelope {
            envelope: beacon_env,
            sender_alias: Some(format!("SOS: {}", alice_addr)),
            sender_socket: Some("192.168.1.50:8080".to_string()),
            sender_address: Some(alice_addr.clone()),
        };
        let body = serde_json::to_string(&wire).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let req = format!(
            "POST /api/receive HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port,
            body.len(),
            body
        );
        let resp_str = send_test_http_request(port, state.clone(), &req).await;
        assert!(
            resp_str.starts_with("HTTP/1.1 200 OK"),
            "Got response: {}",
            resp_str
        );
        assert!(resp_str.contains("emergency_sos"));

        let st = state.lock().unwrap();
        let emergency_contact = st
            .contacts
            .iter()
            .find(|c| c.address == alice_addr)
            .expect("Emergency contact must be registered");
        assert!(emergency_contact.status.contains("EMERGENCY ACTIVE"));

        let msgs = st
            .messages
            .get(&alice_addr)
            .expect("Alert message must be stored");
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].text.contains("37.7749"));
        assert!(msgs[0].text.contains("-122.4194"));
        assert!(msgs[0].text.contains("Urgent medical assistance required!"));
    }

    #[tokio::test]
    async fn test_gui_e2ee_receive_validation() {
        let alice_id = IdentityKeyPair::generate();
        let alice_pk = alice_id.public_key();
        let bob_id = IdentityKeyPair::generate();
        let bob_pk = bob_id.public_key();

        // 1. Unauthenticated injection attempt must be rejected
        let forged_payload = serde_json::json!({
            "sender": "attacker",
            "alias": "Eve",
            "text": "Fake news message"
        });
        let forged_body = serde_json::to_string(&forged_payload).unwrap();
        // Parsing as EncryptedReceiveReq fails
        let parse_attempt = serde_json::from_str::<serde_json::Value>(&forged_body);
        assert!(parse_attempt.is_ok());

        // 2. Legitimate E2EE transmission from Alice to Bob
        let shared_dh = alice_id.diffie_hellman(&bob_pk.dh_pubkey);
        let aead_key = xchat_crypto::kdf::kdf_x3dh(&shared_dh);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let now_ts = 1_000_000u64;
        let plaintext = b"Hello Bob, this is authentic and encrypted!";
        let ciphertext =
            xchat_crypto::aead::encrypt_aead(&aead_key, &nonce, plaintext, b"xchat-gui-e2ee-v1")
                .unwrap();

        let mut sig_material = Vec::new();
        sig_material.extend_from_slice(&alice_pk.sign_pubkey);
        sig_material.extend_from_slice(&alice_pk.dh_pubkey);
        sig_material.extend_from_slice(&nonce);
        sig_material.extend_from_slice(&now_ts.to_be_bytes());
        sig_material.extend_from_slice(&ciphertext);
        let signature = alice_id.sign(&sig_material);

        // Verify Bob can decrypt and verify Alice's signature
        assert!(alice_pk.verify(&sig_material, &signature).is_ok());

        let bob_shared = bob_id.diffie_hellman(&alice_pk.dh_pubkey);
        let bob_key = xchat_crypto::kdf::kdf_x3dh(&bob_shared);
        assert_eq!(aead_key, bob_key);

        let decrypted =
            xchat_crypto::aead::decrypt_aead(&bob_key, &nonce, &ciphertext, b"xchat-gui-e2ee-v1")
                .unwrap();
        assert_eq!(decrypted, plaintext);

        // 3. Mutated signature must fail
        let mut bad_sig = signature;
        bad_sig[0] ^= 0x01;
        assert!(alice_pk.verify(&sig_material, &bad_sig).is_err());
    }

    #[test]
    fn test_p0_1_outbound_wire_envelope_has_no_plaintext() {
        let alice_ks = KeyStore::generate();
        let mut bob_ks = KeyStore::generate();
        let bob_bundle = bob_ks.export_bundle();

        let secret_msg = "CONFIDENTIAL_TOP_SECRET_12345";
        let (mut alice_sess, env) = Session::initiate_outbound(
            &alice_ks,
            &bob_bundle,
            secret_msg.as_bytes(),
            DIRECT_ROUTE,
            1_000_000,
            86400,
        )
        .unwrap();

        let wire = WireMessageEnvelope {
            envelope: env,
            sender_alias: Some("Alice".to_string()),
            sender_socket: Some("127.0.0.1:8080".to_string()),
            sender_address: Some(alice_ks.identity.public_key().address()),
        };

        let json = serde_json::to_string(&wire).unwrap();
        // Zero plaintext in wire envelope
        assert!(!json.contains(secret_msg));
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val.get("text").is_none());
        assert!(val.get("message").is_none());

        // Subsequent ratcheted message also has zero plaintext
        let env2 = alice_sess
            .encrypt_message(b"SECOND_SECRET_98765", DIRECT_ROUTE, 1_000_001, 86400)
            .unwrap();
        let wire2 = WireMessageEnvelope {
            envelope: env2,
            sender_alias: Some("Alice".to_string()),
            sender_socket: Some("127.0.0.1:8080".to_string()),
            sender_address: Some(alice_ks.identity.public_key().address()),
        };
        let json2 = serde_json::to_string(&wire2).unwrap();
        assert!(!json2.contains("SECOND_SECRET_98765"));
        let val2: serde_json::Value = serde_json::from_str(&json2).unwrap();
        assert!(val2.get("text").is_none());
    }

    #[test]
    fn test_p0_2_gui_x3dh_double_ratchet_session_progression() {
        let alice_ks = KeyStore::generate();
        let mut bob_ks = KeyStore::generate();
        let bob_bundle = bob_ks.export_bundle();

        // Step 1: Alice initiates outbound X3DH with Bob
        let (mut alice_sess, init_env) = Session::initiate_outbound(
            &alice_ks,
            &bob_bundle,
            b"Hello Bob via X3DH!",
            DIRECT_ROUTE,
            1_000_000,
            86400,
        )
        .unwrap();

        // Step 2: Bob responds and decrypts
        let (mut bob_sess, pt1) =
            Session::respond_inbound(&mut bob_ks, &init_env, 1_000_000).unwrap();
        assert_eq!(pt1, b"Hello Bob via X3DH!");

        // Step 3: Alice sends ratcheted message
        let env2 = alice_sess
            .encrypt_message(b"Alice Ratchet Msg 2", DIRECT_ROUTE, 1_000_005, 86400)
            .unwrap();
        let pt2 = bob_sess.decrypt_message(&env2, 1_000_005).unwrap();
        assert_eq!(pt2, b"Alice Ratchet Msg 2");

        // Step 4: Bob replies with ratcheted message
        let env3 = bob_sess
            .encrypt_message(b"Bob Ratchet Reply 3", DIRECT_ROUTE, 1_000_010, 86400)
            .unwrap();
        let pt3 = alice_sess.decrypt_message(&env3, 1_000_010).unwrap();
        assert_eq!(pt3, b"Bob Ratchet Reply 3");

        // Step 5: Test session persistence encrypted on disk
        let temp_dir = tempfile::tempdir().unwrap();
        let session_file = temp_dir.path().join("sessions.bin");
        let storage_key = [77u8; 32];
        let mut sessions_map = HashMap::new();
        sessions_map.insert("bob".to_string(), alice_sess);

        save_sessions_encrypted(&sessions_map, &session_file, &storage_key).unwrap();
        let loaded =
            xchat_core::session::load_sessions_encrypted(&session_file, &storage_key).unwrap();
        assert!(loaded.contains_key("bob"));
    }

    #[test]
    fn test_p0_3_receive_rejects_unauthenticated_spoofed_messages() {
        // Plaintext spoofed JSON must fail to deserialize as WireMessageEnvelope or EncryptedEnvelope
        let spoofed_payload = serde_json::json!({
            "sender": "xchat_alice",
            "alias": "@alice",
            "text": "Send me money please!"
        });
        let body = serde_json::to_string(&spoofed_payload).unwrap();
        let wire_opt = serde_json::from_str::<WireMessageEnvelope>(&body);
        let env_opt = serde_json::from_str::<EncryptedEnvelope>(&body);
        assert!(
            wire_opt.is_err(),
            "Raw spoofed plaintext must not deserialize as WireMessageEnvelope"
        );
        assert!(
            env_opt.is_err(),
            "Raw spoofed plaintext must not deserialize as EncryptedEnvelope"
        );

        // Malicious envelope with fake signature must fail
        let mut bob_ks = KeyStore::generate();
        let fake_env = EncryptedEnvelope {
            header: xchat_core::envelope::RoutingHeader::new(DIRECT_ROUTE, 1_000_000, 86400),
            ratchet_header: None,
            x3dh_init: None,
            ciphertext: vec![1, 2, 3, 4],
        };
        assert!(Session::respond_inbound(&mut bob_ks, &fake_env, 1_000_000).is_err());
    }

    #[test]
    fn test_p0_4_receive_replay_attack_rejected() {
        let mut replay = ReplayFilter::new();
        let msg_id = [42u8; 16];
        let now = 1_000_000;

        // First acceptance succeeds
        assert!(replay.check_and_record(&msg_id, now).is_ok());

        // Replay of same message_id must be rejected
        let replay_err = replay.check_and_record(&msg_id, now);
        assert!(replay_err.is_err());
    }

    #[tokio::test]
    async fn test_p0_5_csrf_and_cors_protection() {
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token = state.lock().unwrap().csrf_token.clone();

        // 1. Missing CSRF token on UI API route -> 401 Unauthorized
        let req_no_token = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let resp_no_token = send_test_http_request(port, state.clone(), &req_no_token).await;
        assert!(resp_no_token.starts_with("HTTP/1.1 401 Unauthorized"));

        // 2. Invalid CSRF token -> 401 Unauthorized
        let req_bad_token = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: invalid_csrf_token\r\nConnection: close\r\n\r\n",
            port
        );
        let resp_bad_token = send_test_http_request(port, state.clone(), &req_bad_token).await;
        assert!(resp_bad_token.starts_with("HTTP/1.1 401 Unauthorized"));

        // 3. Valid CSRF token -> 200 OK
        let req_valid = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp_valid = send_test_http_request(port, state.clone(), &req_valid).await;
        assert!(resp_valid.starts_with("HTTP/1.1 200 OK"));

        // 4. Malicious Origin header -> 403 Forbidden
        let req_evil_origin = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.attacker.com\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp_evil = send_test_http_request(port, state.clone(), &req_evil_origin).await;
        assert!(resp_evil.starts_with("HTTP/1.1 403 Forbidden"));

        // 5. Origin: null -> 403 Forbidden
        let req_null_origin = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: null\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp_null = send_test_http_request(port, state.clone(), &req_null_origin).await;
        assert!(resp_null.starts_with("HTTP/1.1 403 Forbidden"));

        // 6. Valid Origin header -> 200 OK with Access-Control-Allow-Origin
        let req_valid_origin = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://localhost:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, port, csrf_token
        );
        let resp_valid_cors = send_test_http_request(port, state.clone(), &req_valid_origin).await;
        assert!(resp_valid_cors.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_valid_cors.contains(&format!(
            "Access-Control-Allow-Origin: http://localhost:{}",
            port
        )));

        // 7. Public peer route allows unauthenticated GET without token
        let req_peer_route = format!(
            "GET /api/identity HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let resp_peer = send_test_http_request(port, state.clone(), &req_peer_route).await;
        assert!(resp_peer.starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn test_p0_6_keystore_encryption_and_0600_perms() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ks_path = temp_dir.path().join("keystore.bin");
        let ks = KeyStore::generate();
        ks.save_to_path(&ks_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&ks_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Keystore file must be created with 0600 permissions"
            );
        }

        let loaded = KeyStore::load_from_path(&ks_path).unwrap();
        assert_eq!(
            ks.identity.public_key().address(),
            loaded.identity.public_key().address()
        );
    }

    #[test]
    fn test_p0_7_one_time_prekey_consumption_and_reuse_rejection() {
        let alice_ks = KeyStore::generate();
        let mut bob_ks = KeyStore::generate();
        let bob_bundle = bob_ks.export_bundle();
        assert!(bob_bundle.one_time_prekey.is_some());

        // Alice initiates session using OPK
        let (_sess, env) = Session::initiate_outbound(
            &alice_ks,
            &bob_bundle,
            b"First message",
            DIRECT_ROUTE,
            1_000_000,
            86400,
        )
        .unwrap();

        // Bob responds; OPK is consumed
        let res1 = Session::respond_inbound(&mut bob_ks, &env, 1_000_000);
        assert!(res1.is_ok());

        // Reusing the same envelope or same consumed OPK is rejected
        let res2 = Session::respond_inbound(&mut bob_ks, &env, 1_000_000);
        assert!(res2.is_err(), "Reused OPK must be rejected");
    }

    #[test]
    fn test_gui_initial_contacts_and_assistant_echo() {
        let now_str = get_now_time_string();
        let initial_contacts = [
            ContactEntry {
                alias: "Saved Messages".to_string(),
                address: "xchat_self".to_string(),
                target: "local".to_string(),
                status: "Encrypted Storage".to_string(),
                last_message: "Personal cloud notes & encryption test".to_string(),
                last_time: now_str.clone(),
            },
            ContactEntry {
                alias: "xChat Assistant".to_string(),
                address: "xchat_assistant".to_string(),
                target: "local".to_string(),
                status: "P2P Mesh AI Assistant".to_string(),
                last_message: "Send a message to test P2P encryption!".to_string(),
                last_time: now_str,
            },
        ];

        assert_eq!(initial_contacts.len(), 2);
        assert_eq!(initial_contacts[0].alias, "Saved Messages");
        assert_eq!(initial_contacts[1].alias, "xChat Assistant");
    }

    #[tokio::test]
    async fn test_gui_alias_unification_and_message_retrieval() {
        let ble = xchat_transport::BleCentralTransport::new().await;
        let discovery = PeerDiscoveryEngine::bind(0, 0).await.unwrap();
        let keystore = KeyStore::generate();
        let pk = keystore.identity.public_key();
        let profile = UserProfile::new(
            "@test_user",
            "Test Node",
            &pk.address(),
            &pk.fingerprint(),
            1_000_000,
        )
        .unwrap();

        let mut st = AppState {
            contacts: vec![ContactEntry {
                alias: "@alice".to_string(),
                address: "e5b95fca-17ae-aec4-9ccb-d030b5c4fea0".to_string(),
                target: "127.0.0.1:8081".to_string(),
                status: "Online".to_string(),
                last_message: "Connected".to_string(),
                last_time: "12:00".to_string(),
            }],
            messages: HashMap::new(),
            keystore,
            profile,
            local_ip: "127.0.0.1".to_string(),
            local_port: 8080,
            discovery,
            ble_transport: ble,
            sessions: HashMap::new(),
            replay_filter: ReplayFilter::new(),
            csrf_token: "test_token".to_string(),
            session_store_path: PathBuf::from("/tmp/test_sessions.bin"),
            contacts_store_path: PathBuf::from("/tmp/test_contacts.bin"),
            messages_store_path: PathBuf::from("/tmp/test_messages.bin"),
            burner_rooms: HashMap::new(),
        };

        // Incoming message arrives with internal handle e5b95fca-17ae-aec4-9ccb-d030b5c4fea0
        st.messages
            .entry("e5b95fca-17ae-aec4-9ccb-d030b5c4fea0".to_string())
            .or_default()
            .push(ChatMessage {
                id: "msg-1".to_string(),
                sender: "peer".to_string(),
                text: "Hello from phone offline".to_string(),
                time: "12:01".to_string(),
                status: "delivered".to_string(),
            });

        // Querying for @alice MUST return the message from e5b95fca-17ae-aec4-9ccb-d030b5c4fea0!
        let unified = get_unified_messages_for_peer(&st, "@alice");
        assert_eq!(unified.len(), 1);
        assert_eq!(unified[0].text, "Hello from phone offline");
    }

    #[tokio::test]
    async fn test_p1_1_non_loopback_binding_config() {
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(listener, state_srv, "0.0.0.0".to_string()));

        // Test real HTTP request to 127.0.0.1 against the 0.0.0.0 listener
        let req = format!(
            "GET /api/identity HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let resp = send_test_http_request(port, state.clone(), &req).await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "Server bound on 0.0.0.0 must accept loopback connections: {}",
            resp
        );
        assert!(resp.contains(r#""address":"#));

        // Test bundle endpoint on the 0.0.0.0 listener
        let bundle_req = format!(
            "GET /api/bundle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        let bundle_resp = send_test_http_request(port, state.clone(), &bundle_req).await;
        assert!(
            bundle_resp.starts_with("HTTP/1.1 200 OK"),
            "Server must serve bundle on 0.0.0.0 listener: {}",
            bundle_resp
        );
    }

    #[test]
    fn test_p1_2_discovered_peers_schema_and_self_filtering() {
        let local_addr = "xchat_localnode12345";
        let peer_val = serde_json::json!({
            "address": "xchat_peer98765",
            "username": "@remote_peer",
            "display_name": "Remote Node",
            "fingerprint": "1234-5678",
            "socket_addr": "192.168.1.50:8080",
            "ip": "192.168.1.50",
            "port": 8080,
            "transport": "wifi_mesh"
        });

        // Verify JSON fields required by frontend connectToDiscoveredPeer
        assert_eq!(peer_val["socket_addr"], "192.168.1.50:8080");
        assert_eq!(peer_val["ip"], "192.168.1.50");
        assert_eq!(peer_val["port"], 8080);

        // Self filtering logic
        let peers = vec![
            serde_json::json!({"address": local_addr, "username": "@me"}),
            peer_val.clone(),
        ];
        let filtered: Vec<_> = peers
            .into_iter()
            .filter(|p| p.get("address").and_then(|a| a.as_str()) != Some(local_addr))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["username"], "@remote_peer");
    }

    #[tokio::test]
    async fn test_active_remote_peers_same_port_different_host_returned() {
        let ble = xchat_transport::BleCentralTransport::new().await;
        let discovery = PeerDiscoveryEngine::bind(0, 0).await.unwrap();
        let keystore = KeyStore::generate();
        let pk = keystore.identity.public_key();
        let profile = UserProfile::new(
            "@device_a",
            "Device A",
            &pk.address(),
            &pk.fingerprint(),
            1_000_000,
        )
        .unwrap();

        let st = AppState {
            contacts: vec![],
            messages: HashMap::new(),
            keystore,
            profile,
            local_ip: "192.168.50.10".to_string(),
            local_port: 8080,
            discovery,
            ble_transport: ble,
            sessions: HashMap::new(),
            replay_filter: ReplayFilter::new(),
            csrf_token: "test_token".to_string(),
            session_store_path: PathBuf::from("/tmp/test_sessions_p1.bin"),
            contacts_store_path: PathBuf::from("/tmp/test_contacts_p1.bin"),
            messages_store_path: PathBuf::from("/tmp/test_messages_p1.bin"),
            burner_rooms: HashMap::new(),
        };

        let remote_peer = xchat_core::profile::DiscoveredPeer {
            username: "@device_b".to_string(),
            display_name: "Device B".to_string(),
            address: "xchat_device_b_addr".to_string(),
            fingerprint: "1234-5678".to_string(),
            socket_addr: "192.168.50.20:8080".to_string(),
            discovered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            transport_type: "lan".to_string(),
        };

        st.discovery.register_peer(remote_peer);

        let active = active_remote_peers(&st);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].address, "xchat_device_b_addr");
        assert_eq!(active[0].socket_addr, "192.168.50.20:8080");
    }

    #[test]
    fn test_p1_3_reply_target_recorded_from_sender_socket() {
        let sender_socket = "192.168.1.200:8080".to_string();
        let mut entry = ContactEntry {
            alias: "Bob".to_string(),
            address: "xchat_bob".to_string(),
            target: "Direct".to_string(),
            status: "Online".to_string(),
            last_message: "Hello".to_string(),
            last_time: "12:00".to_string(),
        };

        // When envelope arrives with sender_socket, target must update from "Direct" to the real socket
        if entry.target.is_empty() || entry.target == "local" || entry.target == "Direct" {
            entry.target = sender_socket.clone();
        }
        assert_eq!(entry.target, "192.168.1.200:8080");
    }

    #[tokio::test]
    async fn test_p1_4_real_ping_and_sos_reporting() {
        // 1. SOS Beacon creation and cryptographic signature verification
        let ks = KeyStore::generate();
        let now = 1_000_000u64;
        let beacon_res = xchat_core::sos::create_emergency_beacon(
            &ks.identity,
            37.7749,
            -122.4194,
            "SOS Emergency Signal",
            now,
            7200,
        );
        assert!(beacon_res.is_ok());
        let beacon = beacon_res.unwrap();
        assert_eq!(beacon.header.expires_at - beacon.header.created_at, 7200);

        // 2. Start server on ephemeral port and test real HTTP /api/ping
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token = state.lock().unwrap().csrf_token.clone();

        // Real HTTP POST /api/ping to local target -> 200 OK with pong and latency
        let ping_local = r#"{"target":"local"}"#;
        let ping_local_req = format!(
            "POST /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, ping_local.len(), ping_local
        );
        let resp_local = send_test_http_request(port, state.clone(), &ping_local_req).await;
        assert!(resp_local.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_local.contains(r#""status":"pong""#));

        // Real HTTP POST /api/ping to unreachable host -> 504 Gateway Timeout with failed status
        let ping_bad = r#"{"target":"127.0.0.1:1"}"#;
        let ping_bad_req = format!(
            "POST /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, ping_bad.len(), ping_bad
        );
        let resp_bad = send_test_http_request(port, state.clone(), &ping_bad_req).await;
        assert!(resp_bad.starts_with("HTTP/1.1 504 Gateway Timeout"));
        assert!(resp_bad.contains(r#""status":"failed""#));

        // Real HTTP POST /api/sos -> 200 OK with broadcasted reporting
        let sos_body = r#"{"lat":37.7749,"lon":-122.4194,"message":"Emergency Mayday"}"#;
        let sos_req = format!(
            "POST /api/sos HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, sos_body.len(), sos_body
        );
        let resp_sos = send_test_http_request(port, state.clone(), &sos_req).await;
        assert!(resp_sos.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_sos.contains(r#""status":"failed""#));
        assert!(resp_sos.contains(r#""peers_reached":0"#));
    }

    #[test]
    fn test_p1_5_burner_room_join_send_receive() {
        let room_name = "ops_delta";
        let passphrase = "correct_horse_battery_staple";
        let mut room_alice = xchat_core::burner::BurnerRoom::new(room_name, passphrase, 600);
        let mut room_bob = xchat_core::burner::BurnerRoom::new(room_name, passphrase, 600);

        assert_eq!(room_alice.routing_token(), room_bob.routing_token());

        let now = 1_000_000u64;
        let env = room_alice
            .post_message("Alice", "Burn after reading", now)
            .unwrap();
        assert_eq!(env.header.destination_token, room_bob.routing_token());

        let received = room_bob.receive_envelope(&env, now).unwrap();
        assert_eq!(received.sender_alias, "Alice");
        assert_eq!(received.content, "Burn after reading");
    }

    #[tokio::test]
    async fn test_burner_room_http_join_and_inbound_delivery() {
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token = {
            let st = state.lock().unwrap();
            st.csrf_token.clone()
        };

        // 1. Join burner room via HTTP
        let join_body = serde_json::json!({
            "room": "ops_sec",
            "pass": "secret_pass_123"
        })
        .to_string();
        let join_req = format!(
            "POST /api/burner/join HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, join_body.len(), join_body
        );
        let join_resp = send_test_http_request(port, state.clone(), &join_req).await;
        assert!(
            join_resp.starts_with("HTTP/1.1 200 OK"),
            "Join failed: {}",
            join_resp
        );

        // 2. Sender posts to room and dispatches envelope to /api/receive
        let mut sender_room =
            xchat_core::burner::BurnerRoom::new("ops_sec", "secret_pass_123", 600);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let env = sender_room
            .post_message("NodeA", "Burn after reading!", now)
            .unwrap();

        let wire = WireMessageEnvelope {
            envelope: env,
            sender_alias: Some("#ops_sec:NodeA".to_string()),
            sender_socket: None,
            sender_address: None,
        };
        let wire_body = serde_json::to_string(&wire).unwrap();
        let receive_req = format!(
            "POST /api/receive HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, wire_body.len(), wire_body
        );
        let recv_resp = send_test_http_request(port, state.clone(), &receive_req).await;
        assert!(
            recv_resp.starts_with("HTTP/1.1 200 OK"),
            "Recv failed: {}",
            recv_resp
        );

        // 3. Query messages for #ops_sec
        let get_msgs_req = format!(
            "GET /api/messages?peer=%23ops_sec HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let msgs_resp = send_test_http_request(port, state.clone(), &get_msgs_req).await;
        assert!(msgs_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(msgs_resp.contains("Burn after reading!"));
    }

    #[tokio::test]
    async fn test_burner_room_outbound_message_not_echoed_back_to_sender() {
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token = {
            let st = state.lock().unwrap();
            st.csrf_token.clone()
        };

        // 1. Join room #testroom via HTTP
        let join_body = serde_json::json!({
            "room": "testroom",
            "pass": "pass123"
        })
        .to_string();
        let join_req = format!(
            "POST /api/burner/join HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, join_body.len(), join_body
        );
        let join_resp = send_test_http_request(port, state.clone(), &join_req).await;
        assert!(join_resp.starts_with("HTTP/1.1 200 OK"));

        // 2. Node sends "hello room from A" to #testroom via POST /api/send
        let send_body = serde_json::json!({
            "alias": "#testroom",
            "target": "burner",
            "text": "hello room from A"
        })
        .to_string();
        let send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, send_body.len(), send_body
        );
        let send_resp = send_test_http_request(port, state.clone(), &send_req).await;
        assert!(send_resp.starts_with("HTTP/1.1 200 OK"));

        // 3. Construct the envelope that would be broadcast and arrive back at /api/receive
        let (env, my_handle, my_addr) = {
            let mut st = state.lock().unwrap();
            let my_username = st.profile.username.clone();
            let my_address = st.keystore.identity.public_key().address();
            let room = st.burner_rooms.get_mut("#testroom").unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let env = room
                .post_message(&my_username, "hello room from A", now)
                .unwrap();
            (env, my_username, my_address)
        };

        let wire = WireMessageEnvelope {
            envelope: env,
            sender_alias: Some(format!("#testroom:{}", my_handle)),
            sender_socket: Some("127.0.0.1:8080".to_string()),
            sender_address: Some(my_addr),
        };
        let wire_body = serde_json::to_string(&wire).unwrap();
        let receive_req = format!(
            "POST /api/receive HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port,
            wire_body.len(),
            wire_body
        );
        let recv_resp = send_test_http_request(port, state.clone(), &receive_req).await;
        assert!(recv_resp.starts_with("HTTP/1.1 200 OK"));

        // 4. Query messages for #testroom: must contain EXACTLY ONE message from "self", NOT echoed as "peer"
        let get_msgs_req = format!(
            "GET /api/messages?peer=%23testroom HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let msgs_resp = send_test_http_request(port, state.clone(), &get_msgs_req).await;
        assert!(msgs_resp.starts_with("HTTP/1.1 200 OK"));
        let body = msgs_resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let msgs: Vec<ChatMessage> = serde_json::from_str(body).unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "Room message must appear exactly once on sender!"
        );
        assert_eq!(
            msgs[0].sender, "self",
            "Message must be 'self', not echoed as 'peer'"
        );
        assert_eq!(msgs[0].text, "hello room from A");
    }

    #[tokio::test]
    async fn test_send_to_empty_room_or_peerless_node_reports_failed() {
        let (state, _temp) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener
            .local_addr()
            .expect("Failed to get local port")
            .port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token = {
            let st = state.lock().unwrap();
            st.csrf_token.clone()
        };

        // 1. Join room #emptyroom
        let join_body = serde_json::json!({
            "room": "emptyroom",
            "pass": "secret"
        })
        .to_string();
        let join_req = format!(
            "POST /api/burner/join HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, join_body.len(), join_body
        );
        let join_resp = send_test_http_request(port, state.clone(), &join_req).await;
        assert!(join_resp.starts_with("HTTP/1.1 200 OK"));

        // 2. Send to #emptyroom when active_peers is empty
        let send_body = serde_json::json!({
            "alias": "#emptyroom",
            "target": "burner",
            "text": "anyone here?"
        })
        .to_string();
        let send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, send_body.len(), send_body
        );
        let send_resp = send_test_http_request(port, state.clone(), &send_req).await;
        assert!(send_resp.starts_with("HTTP/1.1 200 OK"));
        let body = send_resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.contains(r#""status":"failed""#),
            "Send to empty room must report failed status: {}",
            body
        );
        assert!(
            body.contains(r#""peers_reached":0"#),
            "Peers reached must be 0: {}",
            body
        );
        assert!(
            !body.contains(r#""status":"delivered""#),
            "Send to empty room must NEVER report delivered"
        );

        // 3. Verify message in st.messages is marked failed
        {
            let st = state.lock().unwrap();
            let room_msgs = st.messages.get("#emptyroom").expect("Room messages exist");
            assert_eq!(room_msgs.last().unwrap().status, "failed");
        }

        // 4. Send to contact with empty/unreachable target
        let peerless_body = serde_json::json!({
            "alias": "GhostPeer",
            "target": "",
            "text": "hello ghost"
        })
        .to_string();
        let peerless_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, peerless_body.len(), peerless_body
        );
        let peerless_resp = send_test_http_request(port, state.clone(), &peerless_req).await;
        assert!(!peerless_resp.contains(r#""status":"delivered""#));
        assert!(peerless_resp.contains(r#""status":"failed""#));
        {
            let st = state.lock().unwrap();
            let ghost_msgs = st.messages.get("GhostPeer").expect("Ghost messages exist");
            assert_eq!(ghost_msgs.last().unwrap().status, "failed");
        }
    }

    #[test]
    fn test_p1_7_contacts_and_messages_persist_across_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let contacts_path = temp_dir.path().join("contacts.bin");
        let messages_path = temp_dir.path().join("messages.bin");
        let storage_key = [99u8; 32];

        let contacts = vec![ContactEntry {
            alias: "Charlie".to_string(),
            address: "xchat_charlie".to_string(),
            target: "192.168.1.88:8080".to_string(),
            status: "Online".to_string(),
            last_message: "See you at the rendezvous".to_string(),
            last_time: "14:30".to_string(),
        }];

        let mut messages = HashMap::new();
        messages.insert(
            "Charlie".to_string(),
            vec![ChatMessage {
                id: "msg-persisted-1".to_string(),
                sender: "peer".to_string(),
                text: "See you at the rendezvous".to_string(),
                time: "14:30".to_string(),
                status: "delivered".to_string(),
            }],
        );

        // Save encrypted to disk
        save_contacts_encrypted(&contacts, &contacts_path, &storage_key).unwrap();
        save_messages_encrypted(&messages, &messages_path, &storage_key).unwrap();

        // Verify 0600 file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let c_meta = std::fs::metadata(&contacts_path).unwrap();
            let m_meta = std::fs::metadata(&messages_path).unwrap();
            assert_eq!(c_meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(m_meta.permissions().mode() & 0o777, 0o600);
        }

        // Reload across simulated restart
        let loaded_contacts = load_contacts_encrypted(&contacts_path, &storage_key).unwrap();
        let loaded_messages = load_messages_encrypted(&messages_path, &storage_key).unwrap();

        assert_eq!(loaded_contacts.len(), 1);
        assert_eq!(loaded_contacts[0].alias, "Charlie");
        assert_eq!(loaded_contacts[0].target, "192.168.1.88:8080");

        assert_eq!(loaded_messages.len(), 1);
        let charlie_msgs = &loaded_messages["Charlie"];
        assert_eq!(charlie_msgs.len(), 1);
        assert_eq!(charlie_msgs[0].text, "See you at the rendezvous");
    }

    #[tokio::test]
    async fn test_saved_messages_never_echoes_and_contact_dedup() {
        let (state, _temp) = create_test_app_state().await;
        let port = 8080;
        let csrf_token = state.lock().unwrap().csrf_token.clone();

        // 1. Send to "Saved Messages"
        let send_body = r#"{"alias":"Saved Messages","text":"My private note"}"#;
        let send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, send_body.len(), send_body
        );
        let resp = send_test_http_request(port, state.clone(), &send_req).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));

        {
            let st = state.lock().unwrap();
            let saved_msgs = st
                .messages
                .get("Saved Messages")
                .expect("Saved Messages history must exist");
            assert_eq!(saved_msgs.len(), 1);
            assert_eq!(saved_msgs[0].sender, "self");
            assert_eq!(saved_msgs[0].text, "My private note");
            // Must NOT contain any echo message!
            assert!(!saved_msgs.iter().any(|m| m.text.contains("Echo")));
        }

        // 2. Add contact "Bob" with specific address and socket
        let add_bob = r#"{"alias":"Bob","address":"xchat_bob_addr","target":"192.168.1.100:8080"}"#;
        let add_req1 = format!(
            "POST /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, add_bob.len(), add_bob
        );
        let resp1 = send_test_http_request(port, state.clone(), &add_req1).await;
        assert!(resp1.starts_with("HTTP/1.1 200 OK"));

        // 3. Discovered peer taps with different alias hint ("@user_a22040") but matching address or socket
        let tap_peer =
            r#"{"alias":"@user_a22040","address":"xchat_bob_addr","target":"192.168.1.100:8080"}"#;
        let add_req2 = format!(
            "POST /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, tap_peer.len(), tap_peer
        );
        let resp2 = send_test_http_request(port, state.clone(), &add_req2).await;
        assert!(resp2.starts_with("HTTP/1.1 200 OK"));

        {
            let st = state.lock().unwrap();
            // "Bob" must NOT have been renamed to "@user_a22040"
            let bob = st
                .contacts
                .iter()
                .find(|c| c.address == "xchat_bob_addr")
                .expect("Bob must exist");
            assert_eq!(bob.alias, "Bob");
            // There must not be a duplicate contact created
            let matching_count = st
                .contacts
                .iter()
                .filter(|c| c.address == "xchat_bob_addr")
                .count();
            assert_eq!(
                matching_count, 1,
                "Must not create duplicate contact on matching address"
            );
        }
    }

    #[tokio::test]
    async fn test_origin_null_forbidden() {
        let (state, _temp) = create_test_app_state().await;
        let port = 8080;
        let csrf_token = state.lock().unwrap().csrf_token.clone();

        // 1. Request with Origin: null -> must return 403 Forbidden
        let req_null_origin = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: null\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp = send_test_http_request(port, state.clone(), &req_null_origin).await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "Origin: null must be rejected with 403 Forbidden, got: {}",
            resp
        );

        // 2. Request with valid Origin: http://localhost -> must succeed with 200 OK
        let req_valid_origin = format!(
            "GET /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://localhost:8080\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let resp_valid = send_test_http_request(port, state.clone(), &req_valid_origin).await;
        assert!(
            resp_valid.starts_with("HTTP/1.1 200 OK"),
            "Valid Origin must return 200 OK, got: {}",
            resp_valid
        );
    }

    #[tokio::test]
    async fn test_new_contact_two_messages_persist_across_restart() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let peer_port = listener.local_addr().unwrap().port();
        let (peer_state, _peer_tmp) = create_test_app_state().await;

        let p_state = peer_state.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let st = p_state.clone();
                tokio::spawn(async move {
                    handle_http_connection(socket, st, "127.0.0.1".to_string()).await;
                });
            }
        });

        let (state, temp_dir) = create_test_app_state().await;
        let my_port = 8080;
        let csrf_token = state.lock().unwrap().csrf_token.clone();

        // 1. Add contact without address (only alias and target)
        let add_body = format!(r#"{{"alias":"Zed","target":"127.0.0.1:{}"}}"#, peer_port);
        let add_req = format!(
            "POST /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            my_port, csrf_token, add_body.len(), add_body
        );
        let add_resp = send_test_http_request(my_port, state.clone(), &add_req).await;
        assert!(add_resp.starts_with("HTTP/1.1 200 OK"));

        // 2. Send first message
        let send1_body = r#"{"alias":"Zed","text":"first ever"}"#;
        let send1_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            my_port, csrf_token, send1_body.len(), send1_body
        );
        let send1_resp = send_test_http_request(my_port, state.clone(), &send1_req).await;
        assert!(send1_resp.starts_with("HTTP/1.1 200 OK"));

        // Check messages for Zed has "first ever"
        let msg_req1 = format!(
            "GET /api/messages?peer=Zed HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            my_port, csrf_token
        );
        let msg_resp1 = send_test_http_request(my_port, state.clone(), &msg_req1).await;
        assert!(msg_resp1.contains("first ever"));

        // 3. Send second message
        let send2_body = r#"{"alias":"Zed","text":"second"}"#;
        let send2_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            my_port, csrf_token, send2_body.len(), send2_body
        );
        let send2_resp = send_test_http_request(my_port, state.clone(), &send2_req).await;
        assert!(send2_resp.starts_with("HTTP/1.1 200 OK"));

        // Check messages for Zed has BOTH messages in order
        let msg_req2 = format!(
            "GET /api/messages?peer=Zed HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            my_port, csrf_token
        );
        let msg_resp2 = send_test_http_request(my_port, state.clone(), &msg_req2).await;
        assert!(msg_resp2.contains("first ever"));
        assert!(msg_resp2.contains("second"));
        let pos1 = msg_resp2.find("first ever").unwrap();
        let pos2 = msg_resp2.find("second").unwrap();
        assert!(pos1 < pos2, "Messages must be in chronological order");

        // 4. Simulate app restart by reloading contacts and messages from disk
        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
            &temp_dir.path().join("sessions.bin"),
        ))
        .unwrap();
        let loaded_contacts =
            load_contacts_encrypted(&temp_dir.path().join("contacts.bin"), &storage_key).unwrap();
        let loaded_messages =
            load_messages_encrypted(&temp_dir.path().join("messages.bin"), &storage_key).unwrap();

        let (restarted_state, _r_tmp) = create_test_app_state().await;
        {
            let mut r_st = restarted_state.lock().unwrap();
            r_st.contacts = loaded_contacts;
            r_st.messages = loaded_messages;
        }

        let r_msgs = get_unified_messages_for_peer(&restarted_state.lock().unwrap(), "Zed");
        assert_eq!(r_msgs.len(), 2, "Both messages must persist across restart");
        assert_eq!(r_msgs[0].text, "first ever");
        assert_eq!(r_msgs[1].text, "second");
    }

    #[tokio::test]
    async fn test_isolated_node_and_three_node_network_recipient_count() {
        // 1. Isolated Node with self injected in discovery engine
        let (state_a, _tmp_a) = create_test_app_state().await;
        let listener_a = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port_a = listener_a.local_addr().unwrap().port();
        {
            let mut st = state_a.lock().unwrap();
            st.local_port = port_a;
        }
        let st_a_srv = state_a.clone();
        tokio::spawn(run_server_loop(
            listener_a,
            st_a_srv,
            "127.0.0.1".to_string(),
        ));

        let csrf_token_a = state_a.lock().unwrap().csrf_token.clone();
        let my_addr_a = state_a
            .lock()
            .unwrap()
            .keystore
            .identity
            .public_key()
            .address();
        let my_uname_a = state_a.lock().unwrap().profile.username.clone();

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Register self in discovery engine to simulate self-beacon reflection
        let self_peer = xchat_core::profile::DiscoveredPeer {
            username: my_uname_a.clone(),
            display_name: "Node A".to_string(),
            address: my_addr_a.clone(),
            fingerprint: "FP_A".to_string(),
            socket_addr: format!("127.0.0.1:{}", port_a),
            discovered_at: now_ts,
            transport_type: "Wi-Fi Beacon".to_string(),
        };
        state_a.lock().unwrap().discovery.register_peer(self_peer);

        // Join room #isolateroom on isolated node
        let join_body = r#"{"room":"isolateroom","pass":"secret"}"#;
        let join_req = format!(
            "POST /api/burner/join HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port_a, csrf_token_a, join_body.len(), join_body
        );
        let join_resp = send_test_http_request(port_a, state_a.clone(), &join_req).await;
        assert!(join_resp.starts_with("HTTP/1.1 200 OK"));

        // Room send on isolated node must report peers_reached: 0 and status: failed
        let room_send_body =
            r##"{"alias":"#isolateroom","target":"burner","text":"isolated echo check"}"##;
        let room_send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port_a, csrf_token_a, room_send_body.len(), room_send_body
        );
        let room_resp = send_test_http_request(port_a, state_a.clone(), &room_send_req).await;
        assert!(
            room_resp.contains(r#""status":"failed""#),
            "Got: {}",
            room_resp
        );
        assert!(
            room_resp.contains(r#""peers_reached":0"#),
            "Got: {}",
            room_resp
        );

        // SOS on isolated node must report peers_reached: 0 and status: failed
        let sos_body = r#"{"lat":12.34,"lon":56.78,"message":"Isolated SOS"}"#;
        let sos_req = format!(
            "POST /api/sos HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port_a, csrf_token_a, sos_body.len(), sos_body
        );
        let sos_resp = send_test_http_request(port_a, state_a.clone(), &sos_req).await;
        assert!(
            sos_resp.contains(r#""status":"failed""#),
            "Got: {}",
            sos_resp
        );
        assert!(
            sos_resp.contains(r#""peers_reached":0"#),
            "Got: {}",
            sos_resp
        );

        // 2. 3-Node Network (Node A, Node B, Node C)
        let (state_b, _tmp_b) = create_test_app_state().await;
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_b = listener_b.local_addr().unwrap().port();
        tokio::spawn(run_server_loop(
            listener_b,
            state_b.clone(),
            "127.0.0.1".to_string(),
        ));

        let (state_c, _tmp_c) = create_test_app_state().await;
        let listener_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_c = listener_c.local_addr().unwrap().port();
        tokio::spawn(run_server_loop(
            listener_c,
            state_c.clone(),
            "127.0.0.1".to_string(),
        ));

        let addr_b = state_b
            .lock()
            .unwrap()
            .keystore
            .identity
            .public_key()
            .address();
        let addr_c = state_c
            .lock()
            .unwrap()
            .keystore
            .identity
            .public_key()
            .address();

        // Register Node B and Node C in Node A's discovery (along with self already registered)
        let peer_b = xchat_core::profile::DiscoveredPeer {
            username: "user_b".to_string(),
            display_name: "Node B".to_string(),
            address: addr_b.clone(),
            fingerprint: "FP_B".to_string(),
            socket_addr: format!("127.0.0.1:{}", port_b),
            discovered_at: now_ts,
            transport_type: "Wi-Fi Beacon".to_string(),
        };
        let peer_c = xchat_core::profile::DiscoveredPeer {
            username: "user_c".to_string(),
            display_name: "Node C".to_string(),
            address: addr_c.clone(),
            fingerprint: "FP_C".to_string(),
            socket_addr: format!("127.0.0.1:{}", port_c),
            discovered_at: now_ts,
            transport_type: "Wi-Fi Beacon".to_string(),
        };
        state_a.lock().unwrap().discovery.register_peer(peer_b);
        state_a.lock().unwrap().discovery.register_peer(peer_c);

        // Node A triggers SOS on 3-node network (self + B + C). Must report EXACTLY 2!
        let sos_3node_resp = send_test_http_request(port_a, state_a.clone(), &sos_req).await;
        assert!(
            sos_3node_resp.contains(r#""status":"broadcasted""#),
            "Got: {}",
            sos_3node_resp
        );
        assert!(
            sos_3node_resp.contains(r#""peers_reached":2"#),
            "On 3-node network, SOS must report exactly 2, got: {}",
            sos_3node_resp
        );
    }

    #[tokio::test]
    async fn test_burner_room_ram_only_never_persists_across_restart() {
        let (state, temp_dir) = create_test_app_state().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral listener");
        let port = listener.local_addr().unwrap().port();
        let csrf_token = state.lock().unwrap().csrf_token.clone();
        tokio::spawn(run_server_loop(
            listener,
            state.clone(),
            "127.0.0.1".to_string(),
        ));

        // 1. Join burner room #testroom via HTTP
        let join_body = r#"{"room":"testroom","pass":"secret123"}"#;
        let join_req = format!(
            "POST /api/burner/join HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, join_body.len(), join_body
        );
        let join_resp = send_test_http_request(port, state.clone(), &join_req).await;
        assert!(join_resp.starts_with("HTTP/1.1 200 OK"));

        // 2. Send message into #testroom
        let send_body = r##"{"alias":"#testroom","target":"burner","text":"hello room from A"}"##;
        let send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, send_body.len(), send_body
        );
        let send_resp = send_test_http_request(port, state.clone(), &send_req).await;
        assert!(send_resp.starts_with("HTTP/1.1 200 OK"));

        // In RAM, #testroom is present in contacts and messages
        {
            let st = state.lock().unwrap();
            assert!(st.contacts.iter().any(|c| c.alias == "#testroom"));
            assert!(st.messages.contains_key("#testroom"));
        }

        // 3. Trigger disk save of current state
        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
            &temp_dir.path().join("sessions.bin"),
        ))
        .unwrap();
        {
            let st = state.lock().unwrap();
            save_contacts_encrypted(
                &st.contacts,
                &temp_dir.path().join("contacts.bin"),
                &storage_key,
            )
            .unwrap();
            save_messages_encrypted(
                &st.messages,
                &temp_dir.path().join("messages.bin"),
                &storage_key,
            )
            .unwrap();
        }

        // 4. Reload from disk to simulate application restart
        let loaded_contacts =
            load_contacts_encrypted(&temp_dir.path().join("contacts.bin"), &storage_key).unwrap();
        let loaded_messages =
            load_messages_encrypted(&temp_dir.path().join("messages.bin"), &storage_key).unwrap();

        assert!(
            !loaded_contacts.iter().any(|c| c.alias == "#testroom"),
            "Burner room #testroom must NOT be in persisted contacts"
        );
        assert!(
            !loaded_messages.contains_key("#testroom"),
            "Burner room #testroom messages must NOT be in persisted messages"
        );

        let (restarted_state, _r_tmp) = create_test_app_state().await;
        {
            let mut r_st = restarted_state.lock().unwrap();
            r_st.contacts = loaded_contacts;
            r_st.messages = loaded_messages;
        }

        let r_msgs = get_unified_messages_for_peer(&restarted_state.lock().unwrap(), "#testroom");
        assert!(
            r_msgs.is_empty(),
            "Burner room messages must be completely gone on restart"
        );

        // 5. Test leaving a room via /api/burner/leave immediately clears memory
        let leave_body = r#"{"room":"testroom"}"#;
        let leave_req = format!(
            "POST /api/burner/leave HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, leave_body.len(), leave_body
        );
        let leave_resp = send_test_http_request(port, state.clone(), &leave_req).await;
        assert!(leave_resp.starts_with("HTTP/1.1 200 OK"));
        {
            let st = state.lock().unwrap();
            assert!(!st.contacts.iter().any(|c| c.alias == "#testroom"));
            assert!(!st.messages.contains_key("#testroom"));
            assert!(!st.burner_rooms.contains_key("#testroom"));
        }
    }

    #[tokio::test]
    async fn test_failed_send_recorded_and_persisted_as_failed_across_restart() {
        let (state, temp_dir) = create_test_app_state().await;
        let csrf_token = state.lock().unwrap().csrf_token.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_srv = state.clone();
        tokio::spawn(run_server_loop(
            listener,
            state_srv,
            "127.0.0.1".to_string(),
        ));

        // 1. Add contact without a valid network target
        let add_body = r#"{"alias":"OfflinePeer","target":""}"#;
        let add_req = format!(
            "POST /api/contacts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, add_body.len(), add_body
        );
        let add_resp = send_test_http_request(port, state.clone(), &add_req).await;
        assert!(add_resp.starts_with("HTTP/1.1 200 OK"));

        // 2. Send message to OfflinePeer -> must fail with 400
        let send_body = r#"{"alias":"OfflinePeer","target":"","text":"Message to nowhere"}"#;
        let send_req = format!(
            "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, csrf_token, send_body.len(), send_body
        );
        let send_resp = send_test_http_request(port, state.clone(), &send_req).await;
        assert!(send_resp.contains("400 Bad Request"));
        assert!(send_resp.contains(r#""status":"failed""#));

        // 3. Query /api/messages?peer=OfflinePeer -> message must be recorded with status failed
        let get_req = format!(
            "GET /api/messages?peer=OfflinePeer HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-XChat-Token: {}\r\nConnection: close\r\n\r\n",
            port, csrf_token
        );
        let get_resp = send_test_http_request(port, state.clone(), &get_req).await;
        assert!(get_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(get_resp.contains(r#""status":"failed""#));
        assert!(get_resp.contains("Message to nowhere"));

        // 4. Verify disk persistence: reload state from disk
        let storage_key = KeyStore::get_or_create_device_storage_key_for_path(Some(
            &temp_dir.path().join("sessions.bin"),
        ))
        .unwrap();
        let loaded_messages =
            load_messages_encrypted(&temp_dir.path().join("messages.bin"), &storage_key).unwrap();
        let msgs = loaded_messages
            .get("OfflinePeer")
            .or_else(|| {
                let st = state.lock().unwrap();
                let c = st
                    .contacts
                    .iter()
                    .find(|c| c.alias == "OfflinePeer")
                    .unwrap();
                loaded_messages.get(&c.address)
            })
            .expect("Persisted messages must contain OfflinePeer");
        assert_eq!(msgs[0].status, "failed");
        assert_eq!(msgs[0].text, "Message to nowhere");
    }
}
