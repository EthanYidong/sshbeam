use sshbeam::*;

#[tokio::main]
async fn main() -> Result<(), SBError> {
    server::SSHBeamServer::new().run().await
}
