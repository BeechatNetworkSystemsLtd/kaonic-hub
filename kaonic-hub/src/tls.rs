//! HTTPS with a certificate authority of this device's own.
//!
//! The CA key is made once, randomly, per device, and kept in the keystore.
//! The server certificate is signed for the device's current names and addresses and kept
//! in the keystore with its key, so it stays the same across restarts (a browser that
//! accepted it once is not warned again) until the names or addresses change.
//! `GET /device/rootca` hands out the CA certificate so a browser can trust it.

use std::net::IpAddr;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::app::App;
use crate::error::{ApiError, ApiResult};

const CA_KEY: &str = "tls/ca_key";
const CA_CERT: &str = "tls/ca_cert";
const SERVER_KEY: &str = "tls/server_key";
const SERVER_CERT: &str = "tls/server_cert";
/// The names and addresses the stored server certificate was made for.
const SERVER_NAMES: &str = "tls/server_names";

pub struct Tls {
    pub config: Arc<rustls::ServerConfig>,
    /// The CA certificate, PEM, for `/device/rootca`.
    pub ca_pem: String,
}

fn ca_params(serial: &str) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Kaonic");
    params
        .distinguished_name
        .push(DnType::CommonName, format!("Kaonic {serial} local CA"));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // The device may not know the date (no RTC): validity is wide, and trust ends by replacing the CA.
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2049, 12, 31);
    Ok(params)
}

pub async fn load_or_create(
    app: &App,
    names: Vec<String>,
    addresses: Vec<IpAddr>,
) -> ApiResult<Tls> {
    let serial = app.device.serial();
    let stored = app
        .secrets(|keys| {
            Ok((
                keys.get(CA_KEY)
                    .and_then(|s| s.expose_str().map(str::to_owned)),
                keys.get(CA_CERT)
                    .and_then(|s| s.expose_str().map(str::to_owned)),
            ))
        })
        .await?;
    let (ca_key_pem, ca_pem) = match stored {
        (Some(key), Some(cert)) => (key, cert),
        _ => {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(internal)?;
            let cert = ca_params(&serial)
                .map_err(internal)?
                .self_signed(&key)
                .map_err(internal)?;
            let (key_pem, cert_pem) = (key.serialize_pem(), cert.pem());
            let (k, c) = (key_pem.clone(), cert_pem.clone());
            app.secrets(move |keys| {
                keys.set(CA_KEY, k)?;
                keys.set(CA_CERT, c)
            })
            .await?;
            log::info!("made this device's HTTPS certificate authority");
            (key_pem, cert_pem)
        }
    };
    // The stored server certificate, if it was made by this CA for these names and addresses.
    let wanted = format!("{}|{}|{ca_pem}", names.join(","), addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
    let stored = app
        .secrets(|keys| {
            let get = |name| keys.get(name).and_then(|s| s.expose_str().map(str::to_owned));
            Ok((get(SERVER_NAMES), get(SERVER_KEY), get(SERVER_CERT)))
        })
        .await?;
    let (server_key_pem, server_cert_pem) = match stored {
        (Some(made_for), Some(key), Some(cert)) if made_for == wanted => (key, cert),
        _ => {
            let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(internal)?;
            let issuer = Issuer::new(ca_params(&serial).map_err(internal)?, ca_key);
            let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(internal)?;
            let mut params = CertificateParams::new(names).map_err(internal)?;
            params
                .subject_alt_names
                .extend(addresses.into_iter().map(SanType::IpAddress));
            params
                .distinguished_name
                .push(DnType::CommonName, format!("Kaonic {serial}"));
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2049, 12, 31);
            let server_cert = params.signed_by(&server_key, &issuer).map_err(internal)?;
            let (key_pem, cert_pem) = (server_key.serialize_pem(), server_cert.pem());
            let (k, c) = (key_pem.clone(), cert_pem.clone());
            app.secrets(move |keys| {
                keys.set(SERVER_KEY, k)?;
                keys.set(SERVER_CERT, c)?;
                keys.set(SERVER_NAMES, wanted)
            })
            .await?;
            log::info!("made a new HTTPS certificate for this device's names and addresses");
            (key_pem, cert_pem)
        }
    };

    let pem = |text: &str| -> ApiResult<CertificateDer<'static>> {
        rustls::pki_types::pem::PemObject::from_pem_slice(text.as_bytes()).map_err(|_| ApiError::internal())
    };
    let chain: Vec<CertificateDer<'static>> = vec![pem(&server_cert_pem)?, pem(&ca_pem)?];
    let key = PrivateKeyDer::Pkcs8(
        rustls::pki_types::pem::PemObject::from_pem_slice(server_key_pem.as_bytes()).map_err(|_| ApiError::internal())?,
    );
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(internal)?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(internal)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls {
        config: Arc::new(config),
        ca_pem,
    })
}

/// The names and addresses this device's certificates are made for.
pub fn device_names(app: &App) -> (Vec<String>, Vec<IpAddr>) {
    let hostname = app.device.hostname();
    let names = vec![hostname.clone(), format!("{hostname}.local"), "kaonic.local".to_owned()];
    let mut addresses = vec![IpAddr::from([192, 168, 10, 1])];
    for interface in ["br0", "usb0", "wlan0"] {
        addresses.extend(crate::system::interface_addresses(interface));
    }
    // The node's own client network (the VPN puts its address on br0 a moment after it starts).
    if let Some(vpn) = app.vpn.get() {
        addresses.extend(vpn.status().lans.iter().filter_map(|lan| lan.address).map(IpAddr::V4));
    }
    addresses.sort();
    addresses.dedup();
    (names, addresses)
}

/// A certificate for a plugin's own HTTPS page, signed by this device's CA (so a browser that
/// trusts the hub trusts the plugin): `(certificate chain PEM, private key PEM)`.
pub async fn service_cert(app: &App, plugin: &str) -> ApiResult<(String, String)> {
    let serial = app.device.serial();
    let stored = app
        .secrets(|keys| {
            Ok((
                keys.get(CA_KEY).and_then(|s| s.expose_str().map(str::to_owned)),
                keys.get(CA_CERT).and_then(|s| s.expose_str().map(str::to_owned)),
            ))
        })
        .await?;
    let (Some(ca_key_pem), Some(ca_pem)) = stored else {
        return Err(ApiError::unavailable("tls_unavailable", "This device has no certificate authority yet."));
    };
    let issuer = Issuer::new(ca_params(&serial).map_err(internal)?, KeyPair::from_pem(&ca_key_pem).map_err(internal)?);
    let (mut names, mut addresses) = device_names(app);
    names.push("localhost".to_owned());
    addresses.push(IpAddr::from([127, 0, 0, 1]));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(internal)?;
    let mut params = CertificateParams::new(names).map_err(internal)?;
    params.subject_alt_names.extend(addresses.into_iter().map(SanType::IpAddress));
    params.distinguished_name.push(DnType::CommonName, format!("Kaonic {serial} plugin {plugin}"));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2049, 12, 31);
    let cert = params.signed_by(&key, &issuer).map_err(internal)?;
    Ok((format!("{}{}", cert.pem(), ca_pem), key.serialize_pem()))
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    log::error!("tls: {error}");
    ApiError::internal()
}
