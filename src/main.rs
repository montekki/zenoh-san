use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use env_logger::Env;
use rcgen::{
    string::Ia5String, BasicConstraints, Certificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::time as tokio_time;

const KEY_EXPR: &str = "demo/mtls-cn-acl";
const MESSAGE: &str = "hello over zenoh mtls with CN ACL";
const HOST_A_CN: &str = "host-a";
const HOST_B_CN: &str = "host-b";
const HOST_A_URI_SAN: &str = "spiffe://app.test.io/host-a";
const HOST_B_URI_SAN: &str = "spiffe://app.test.io/host-b";
const RUNTIME_DIR: &str = "run/zenoh-san";
const CONFIG_DIR: &str = "src/configs";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let certs = generate_certs(&runtime_path("certs"))?;

    run_acl_case(
        &certs,
        AclCase {
            name: "allowed CN ACL",
            host_a_config: "allowed-cn-acl/host-a.json5",
            host_b_config: "allowed-cn-acl/host-b.json5",
            expect_delivery: true,
        },
    )
    .await?;

    run_acl_case(
        &certs,
        AclCase {
            name: "denied CN ACL",
            host_a_config: "denied-cn-acl/host-a.json5",
            host_b_config: "denied-cn-acl/host-b.json5",
            expect_delivery: false,
        },
    )
    .await?;

    log::info!(
        "Demo complete: TLS name verification stayed off, mTLS still validated the CA, and Zenoh ACL matched peer CNs."
    );
    log::info!("certificates written under {}", certs.dir.display());
    log::info!("configs loaded from {CONFIG_DIR}");

    Ok(())
}

#[derive(Clone)]
struct LeafFiles {
    cert: PathBuf,
    key: PathBuf,
}

struct CertFiles {
    dir: PathBuf,
    ca_cert: PathBuf,
    host_a: LeafFiles,
    host_b: LeafFiles,
}

struct AclCase<'a> {
    name: &'a str,
    host_a_config: &'a str,
    host_b_config: &'a str,
    expect_delivery: bool,
}

async fn run_acl_case(certs: &CertFiles, case: AclCase<'_>) -> Result<()> {
    ensure_cert_files_exist(certs)?;

    let host_a_config = config_path(case.host_a_config);
    let host_b_config = config_path(case.host_b_config);
    let session_a = zresult(zenoh::open(load_config(&host_a_config)?).await)
        .with_context(|| format!("open host-a session for {}", case.name))?;
    let session_b = zresult(zenoh::open(load_config(&host_b_config)?).await)
        .with_context(|| format!("open host-b session for {}", case.name))?;

    let subscriber = session_b
        .declare_subscriber(KEY_EXPR)
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))
        .with_context(|| format!("declare host-b subscriber for {}", case.name))?;

    tokio_time::sleep(Duration::from_secs(1)).await;

    session_a
        .put(KEY_EXPR, MESSAGE)
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))
        .with_context(|| format!("publish from host-a for {}", case.name))?;

    let received = tokio_time::timeout(Duration::from_secs(3), subscriber.recv_async()).await;
    match (case.expect_delivery, received) {
        (true, Ok(sample)) => {
            let sample = zresult(sample)
                .with_context(|| format!("receive host-b sample for {}", case.name))?;
            let payload = sample
                .payload()
                .try_to_string()
                .context("decode sample payload as UTF-8")?;
            log::info!(
                "{}: host-b received on {}: {}",
                case.name,
                sample.key_expr(),
                payload
            );
        }
        (true, Err(_)) => anyhow::bail!("{}: expected delivery, but timed out", case.name),
        (false, Ok(sample)) => {
            let sample = zresult(sample)
                .with_context(|| format!("receive unexpected sample for {}", case.name))?;
            anyhow::bail!(
                "{}: unexpected delivery from denied CN: {:?}",
                case.name,
                sample.payload().try_to_string()
            );
        }
        (false, Err(_)) => {
            log::error!(
                "{}: no sample delivered, as expected for non-matching cert_common_names",
                case.name
            );
        }
    }

    zresult(session_a.close().await).context("close host-a session")?;
    zresult(session_b.close().await).context("close host-b session")?;

    Ok(())
}

fn load_config(path: &Path) -> Result<zenoh::Config> {
    zresult(zenoh::Config::from_file(path))
        .with_context(|| format!("load zenoh config {}", path.display()))
}

fn config_path(relative_path: &str) -> PathBuf {
    PathBuf::from(CONFIG_DIR).join(relative_path)
}

fn runtime_path(child: &str) -> PathBuf {
    PathBuf::from(RUNTIME_DIR).join(child)
}

fn zresult<T>(result: std::result::Result<T, Box<dyn Error + Send + Sync>>) -> Result<T> {
    result.map_err(|err| anyhow::anyhow!("{err}"))
}

fn ensure_cert_files_exist(certs: &CertFiles) -> Result<()> {
    for path in [
        &certs.ca_cert,
        &certs.host_a.cert,
        &certs.host_a.key,
        &certs.host_b.cert,
        &certs.host_b.key,
    ] {
        if !path.exists() {
            anyhow::bail!("expected generated certificate file {}", path.display());
        }
    }
    Ok(())
}

fn generate_certs(dir: &Path) -> Result<CertFiles> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

    let (ca_cert, ca_issuer) = generate_ca()?;
    let ca_cert_path = dir.join("ca.pem");
    write_pem(&ca_cert_path, &ca_cert.pem())?;

    let host_a = generate_leaf(&ca_issuer, HOST_A_CN, HOST_A_URI_SAN, dir)?;
    let host_b = generate_leaf(&ca_issuer, HOST_B_CN, HOST_B_URI_SAN, dir)?;

    Ok(CertFiles {
        dir: dir.to_path_buf(),
        ca_cert: ca_cert_path,
        host_a,
        host_b,
    })
}

fn generate_ca() -> Result<(Certificate, Issuer<'static, KeyPair>)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let (not_before, not_after) = validity_window();

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "zenoh-san local test");
    params
        .distinguished_name
        .push(DnType::CommonName, "zenoh-san local root CA");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.not_before = not_before;
    params.not_after = not_after;

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, Issuer::new(params, key_pair)))
}

fn generate_leaf(
    issuer: &Issuer<'static, KeyPair>,
    common_name: &str,
    uri_san: &str,
    dir: &Path,
) -> Result<LeafFiles> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let (not_before, not_after) = validity_window();

    params
        .distinguished_name
        .push(DnType::OrganizationName, "zenoh-san local test");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .subject_alt_names
        .push(SanType::URI(Ia5String::try_from(uri_san)?));
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.not_before = not_before;
    params.not_after = not_after;

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    let cert_path = dir.join(format!("{common_name}.pem"));
    let key_path = dir.join(format!("{common_name}-key.pem"));
    write_pem(&cert_path, &cert.pem())?;
    write_pem(&key_path, &key_pair.serialize_pem())?;

    Ok(LeafFiles {
        cert: cert_path,
        key: key_path,
    })
}

fn validity_window() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - TimeDuration::days(1), now + TimeDuration::days(365))
}

fn write_pem(path: &Path, pem: &str) -> Result<()> {
    fs::write(path, pem).with_context(|| format!("write {}", path.display()))
}
