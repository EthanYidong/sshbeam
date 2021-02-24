use sshbeam::*;

#[tokio::main]
async fn main() -> Result<(), SBError> {
    client::SSHBeamClient::new().connect(&std::env::args().nth(1).unwrap()).await
}
