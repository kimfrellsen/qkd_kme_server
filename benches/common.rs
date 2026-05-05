use std::sync::Arc;
use log::error;
use tokio::select;
use qkd_kme_server::event_subscription::ImportantEventSubscriber;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;
use qkd_kme_server::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::server::log_http_server::LoggingHttpServer;


pub const HOST_PORT: &'static str = "localhost:3000";

pub async fn launch_kme_from_config_file(config_file_path: &str) {
    let config = qkd_kme_server::config::Config::from_json_path(config_file_path).unwrap();

    let sae_https_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        &config.this_kme_config.saes_https_interface.listen_address,
        &config.this_kme_config.saes_https_interface.ca_client_cert_path,
        &config.this_kme_config.saes_https_interface.server_cert_path,
        &config.this_kme_config.saes_https_interface.server_key_path,
    );

    let inter_kme_https_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        &config.this_kme_config.kmes_https_interface.listen_address,
        &config.this_kme_config.kmes_https_interface.ca_client_cert_path,
        &config.this_kme_config.kmes_https_interface.server_cert_path,
        &config.this_kme_config.kmes_https_interface.server_key_path,
    );

    let qkd_manager = QkdManager::from_config(&config).await;
    let qkd_manager = qkd_manager.unwrap();

    match config.this_kme_config.debugging_http_interface {
        Some(listen_addr) => {
            let logging_http_server = Arc::new(LoggingHttpServer::new(&listen_addr));
            qkd_manager.add_important_event_subscriber(Arc::clone(&logging_http_server) as Arc<dyn ImportantEventSubscriber>).await.unwrap();
            select! {
                x = inter_kme_https_server.run(&qkd_manager) => {
                    error!("Error running inter-KMEs HTTPS server: {:?}", x);
                },
                x = sae_https_server.run(&qkd_manager) => {
                    error!("Error running SAEs HTTPS server: {:?}", x);
                },
                x = logging_http_server.run() => {
                    error!("Error running logging HTTP server: {:?}", x);
                }
            }
        },
        None => {
            select! {
                x = inter_kme_https_server.run(&qkd_manager) => {
                    error!("Error running inter-KMEs HTTPS server: {:?}", x);
                },
                x = sae_https_server.run(&qkd_manager) => {
                    error!("Error running SAEs HTTPS server: {:?}", x);
                }
            }
        }
    }
}

pub fn setup_cert_auth_reqwest_client() -> reqwest::Client {
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/kme-1-local-zone/client_1_cert.pem";
    let buf = std::fs::read(SAE_AUTH_CLIENT_CERT_PATH).unwrap();
    let client_cert_id = reqwest::Identity::from_pem(&buf).unwrap();
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}