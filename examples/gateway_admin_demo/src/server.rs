//! Live admin server binary.
//!
//! Starts the MoFA gateway admin API on port 9090 so you can drive it with
//! real HTTP tools (curl, httpie, Postman, …).
//!
//! Run:
//! ```sh
//! cargo run -p gateway_admin_demo --bin gateway_server
//! ```
//!
//! Then in another terminal run:
//! ```sh
//! bash scripts/gateway_demo.sh
//! ```

use mofa_gateway::admin::{AdminServer, AdminServerConfig};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    info!("MoFA Gateway Admin Server");
    info!("=========================");
    info!("Listening on http://127.0.0.1:9090");
    info!("Admin key : demo-secret-key");
    info!("Press Ctrl-C to stop.\n");

    let config = AdminServerConfig::new("demo-secret-key").with_port(9090);
    AdminServer::new(config)
        .start()
        .await
        .expect("server exited with error");
}
