//! QKD network routing manager, get route to SAE and KME info on classical network

use std::collections::HashMap;
use std::io;
use crate::{io_err, KmeId};

#[derive(Clone)]
pub(super) struct QkdRouter {
    kme_to_classical_network_info_associations: HashMap<KmeId, KmeInfoClassicalNetwork>,
}

impl QkdRouter {
    pub(super) fn new() -> Self {
        Self {
            kme_to_classical_network_info_associations: HashMap::new(),
        }
    }

    pub(super) fn add_kme_to_ip_domain_port_association(&mut self, kme_id: KmeId, ip_or_domain: &str, client_cert_path: &str, client_cert_password: &str, inter_kme_server_ca_cert_path: Option<&str>, should_ignore_system_proxy_settings: bool) -> Result<(), io::Error> {
        if !Self::check_ip_port_domain_url_validity(ip_or_domain) {
            return Err(io_err("Invalid IP, domain and port"));
        }

        let cert_ext = std::path::Path::new(client_cert_path).extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase());

        let buf = std::fs::read(client_cert_path)
            .map_err(|e| io_err(&format!("Cannot open client certificate file: {:?}", e)))?;

        let tls_client_cert_identity = match cert_ext.as_deref() {
            Some("pfx") => reqwest::tls::Identity::from_pkcs12_der(&buf, client_cert_password),
            Some("pem") | _ => reqwest::tls::Identity::from_pem(&buf),
        }.map_err(|e| io_err(&format!("Cannot create client certificate identity: {:?}", e)))?;

        let inter_kme_server_ca_cert = match inter_kme_server_ca_cert_path {
            Some(ca_path) => {
                let ca_pem = std::fs::read(ca_path)
                    .map_err(|e| io_err(&format!("Cannot read inter-KME server CA certificate: {:?}", e)))?;
                let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| io_err(&format!("Cannot parse inter-KME server CA certificate: {:?}", e)))?;
                Some(ca_cert)
            },
            None => None,
        };

        self.kme_to_classical_network_info_associations.insert(kme_id, KmeInfoClassicalNetwork {
            ip_domain_port: ip_or_domain.to_string(),
            tls_client_cert_identity,
            inter_kme_server_ca_cert,
            should_ignore_system_proxy_settings,
        });
        Ok(())
    }

    pub(super) fn get_classical_connection_info_from_kme_id(&self, kme_id: KmeId) -> Option<&KmeInfoClassicalNetwork> {
        self.kme_to_classical_network_info_associations.get(&kme_id)
    }

    fn check_ip_port_domain_url_validity(ip_domain_port: &str) -> bool {
        let url = url::Url::parse(&format!("https://{}", ip_domain_port));
        url.is_ok()
    }
}

#[derive(Clone)]
pub(super) struct KmeInfoClassicalNetwork {
    pub(super) ip_domain_port: String,
    pub(super) tls_client_cert_identity: reqwest::tls::Identity,
    pub(super) inter_kme_server_ca_cert: Option<reqwest::Certificate>,
    pub(super) should_ignore_system_proxy_settings: bool,
}

#[cfg(test)]
mod tests {
    use crate::qkd_manager::router::QkdRouter;

    #[test]
    fn test_add_kme_to_ip_or_domain_association_pem_cert() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "certs/inter_kmes/kme1-to-kme2.pem";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        assert!(qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, "", None, true).is_ok());
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_some());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_wrong_domain() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234;invalid_data";
        let client_cert_path = "certs/inter_kmes/kme1-to-kme2.pem";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, "", None, true);
        assert!(qkd_router_add_result.is_err());
        assert_eq!(qkd_router_add_result.err().unwrap().to_string(), "Invalid IP, domain and port");
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_cert_file_does_not_exist() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "not-exists.pem";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, "", None, true);
        assert!(qkd_router_add_result.is_err());
        if cfg!(target_os = "linux") {
            assert_eq!(qkd_router_add_result.err().unwrap().to_string(), "Cannot open client certificate file: Os { code: 2, kind: NotFound, message: \"No such file or directory\" }");
        }
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_cert_file_invalid_pem() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "tests/data/bad_certs/invalid_client_cert_data.pem";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, "", None, true);
        assert!(qkd_router_add_result.is_err());
        assert!(qkd_router_add_result.err().unwrap().to_string().starts_with("Cannot create client certificate identity: "));
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }
}
