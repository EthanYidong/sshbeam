use thrussh::server::*;
use thrussh::{ChannelId, CryptoVec};
use thrussh_keys::key::PublicKey;

use futures::future::{Ready, ready};

use std::sync::Arc;

use crate::{SBError, PORT};

#[derive(Clone)]
pub struct SSHBeamServer {
    authorized_keys: Arc<Vec<PublicKey>>
}

impl Handler for SSHBeamServer {
    type Error = SBError;
    type FutureAuth = Ready<Result<(Self, Auth), SBError>>;
    type FutureUnit = Ready<Result<(Self, Session), SBError>>;
    type FutureBool = Ready<Result<(Self, Session, bool), SBError>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        ready(Ok((self, s, b)))
    }
    fn finished(self, s: Session) -> Self::FutureUnit {
        ready(Ok((self, s)))
    }
    fn auth_publickey(self, user: &str, public_key: &PublicKey) -> Self::FutureAuth {
        println!("user connecting: {}", user);
        if self.authorized_keys.contains(public_key) {
            self.finished_auth(Auth::Accept)
        } else {
            println!("Key not authorized");
            self.finished_auth(Auth::Reject)
        }
    }
    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        tokio::spawn(clipboard_sender(channel, session.handle()));
        self.finished(session)
    }
    fn data(self, _channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let _ = cli_clipboard::set_contents(String::from_utf8(data.to_vec()).unwrap());
        self.finished(session)
    }
}

impl Server for SSHBeamServer {
    type Handler = Self;

    fn new(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl SSHBeamServer {
    pub fn new() -> Self {
        let authorized_keys = Arc::new(load_authorized_keys().unwrap_or(Vec::new()));
        SSHBeamServer {
            authorized_keys,
        }
    }

    pub async fn run(self) -> Result<(), SBError> {
        let mut config = Config::default();
        let key_pair = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
        println!("Fingerprint: {}", key_pair.clone_public_key().fingerprint());
        config.keys.push(key_pair);
        let config = Arc::new(config);
        run(config, &format!("0.0.0.0:{}", PORT), self).await?;
        Ok(())
    }
}

fn load_authorized_keys() -> Result<Vec<PublicKey>, SBError> {
    let authorized_keys_path = dirs_next::home_dir()
        .ok_or(SBError::Custom("No home dir"))?
        .join(".ssh")
        .join("authorized_keys");
    let authorized_keys_string = std::fs::read_to_string(authorized_keys_path)?;
    let mut authorized_keys = Vec::new();
    for line in authorized_keys_string.lines() {
        let key = line.split_whitespace().nth(1);
        if let Some(key) = key {
            if let Ok(key) = thrussh_keys::parse_public_key_base64(key) {
                authorized_keys.push(key);
            }
        }
    }
    Ok(authorized_keys)
}

async fn clipboard_sender(channel: ChannelId, mut handle: Handle) {
    let mut current_contents = None;
    loop {
        if let Ok(content) = cli_clipboard::get_contents() {
            if Some(&content) != current_contents.as_ref() {
                let _ = handle.data(channel, CryptoVec::from_slice(content.as_bytes())).await;
                current_contents = Some(content);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
