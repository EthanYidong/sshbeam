use thrussh::client::*;
use thrussh::ChannelId;
use thrussh_keys::agent::client::AgentClient;
use thrussh_keys::key::PublicKey;

use dialoguer::Confirm;

use futures::future::{Ready, ready};

use std::sync::Arc;
use std::path::PathBuf;

use crate::SBError;
use crate::PORT;

pub struct SSHBeamClient;

impl Handler for SSHBeamClient {
    type Error = SBError;
    type FutureUnit = Ready<Result<(Self, Session), SBError>>;
    type FutureBool = Ready<Result<(Self, bool), SBError>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        ready(Ok((self, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        ready(Ok((self, session)))
    }

    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
        println!("Server fingerprint: {}", server_public_key.fingerprint());
        let confirm = match Confirm::new().with_prompt("Is this accurate?").interact() {
            Ok(res) => res,
            Err(e) => return ready(Err(e.into())),
        };

        self.finished_bool(confirm)
    }

    fn data(self, _channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let _ = cli_clipboard::set_contents(String::from_utf8(data.to_vec()).unwrap());
        self.finished(session)
    }
}

impl SSHBeamClient {
    pub fn new() -> Self {
        SSHBeamClient
    }

    pub async fn connect(self, host: &str) -> Result<(), SBError> {
        let mut config = thrussh_config::parse_home(host)
            .unwrap_or(thrussh_config::Config::default(host));
        config.port = PORT;
        let stream = config.stream().await?;
    
        let client_config = Arc::new(Config::default());
        let mut ssh_handle = connect_stream(client_config, stream, self).await?;

        let mut agent = AgentClient::connect_env().await?;
    
        let identities = if let Some(ref file) = config.identity_file {
            let mut pubkey_path = PathBuf::from(&file);
            pubkey_path.set_extension("pub");
            vec![thrussh_keys::load_public_key(&pubkey_path)?]
        } else {
            agent.request_identities().await?
        };
    
        let mut agent = Some(agent);
        let mut authenticated = false;
        for key in identities {
            if let Some(a) = agent.take() {
                match ssh_handle.authenticate_future(&config.user, key, a).await {
                    (a, Ok(auth)) => {
                        if auth {
                            authenticated = true;
                            break;
                        }
                        agent = Some(a);
                    }
                    (a, Err(e)) => {
                        println!("{:?}", e);
                        agent = Some(a);
                    }
                }
            }
        }
    
        if !authenticated {
            return Err(SBError::Custom("Could not authenticate"));
        }
    
        let channel = ssh_handle.channel_open_session().await?;
        tokio::spawn(clipboard_sender(channel));
        ssh_handle.await?;
        Ok(())
    }
}

async fn clipboard_sender(mut channel: Channel) {
    let mut current_contents = None;
    loop {
        if let Ok(content) = cli_clipboard::get_contents() {
            if Some(&content) != current_contents.as_ref() {
                let _ = channel.data(content.as_bytes()).await;
                current_contents = Some(content);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
