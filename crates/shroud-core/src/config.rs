use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default)]
    pub inbounds: ClientInboundsConfig,
    pub transport: TransportConfig,
    #[serde(default)]
    pub auth: ClientAuthConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub dns: ClientDnsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksInboundConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientInboundsConfig {
    #[serde(default)]
    pub socks: Option<SocksInboundConfig>,
    #[serde(default)]
    pub tun: TunInboundConfig,
}

impl ClientInboundsConfig {
    pub fn has_enabled_inbound(&self) -> bool {
        self.socks
            .as_ref()
            .map(|socks| socks.enabled)
            .unwrap_or(false)
            || self.tun.enabled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_address")]
    pub address: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub dns: Option<IpAddr>,
}

impl Default for TunInboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_tun_name(),
            address: default_tun_address(),
            mtu: default_tun_mtu(),
            auto_route: false,
            dns: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransportEndpointConfig {
    pub server: String,
    pub port: u16,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub tls_ca_cert_path: Option<String>,
    pub tls_server_cert_sha256: Option<String>,
    pub path: Option<String>,
}

impl From<&TransportConfig> for TransportEndpointConfig {
    fn from(transport: &TransportConfig) -> Self {
        Self {
            server: transport.server.clone(),
            port: transport.port,
            tls: transport.tls,
            tls_server_name: transport.tls_server_name.clone(),
            tls_ca_cert_path: transport.tls_ca_cert_path.clone(),
            tls_server_cert_sha256: transport.tls_server_cert_sha256.clone(),
            path: transport.path.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    RawTcp,
    Http2,
    Http3,
}

impl Default for TransportMode {
    fn default() -> Self {
        default_mode()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default = "default_mode")]
    pub mode: TransportMode,
    pub server: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub tls_ca_cert_path: Option<String>,
    #[serde(default)]
    pub tls_server_cert_sha256: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeoutsConfig {
    #[serde(default = "default_server_connect_ms")]
    pub server_connect_ms: u64,
    #[serde(default = "default_tls_handshake_ms")]
    pub tls_handshake_ms: u64,
    #[serde(default = "default_raw_tcp_handshake_ms")]
    pub raw_tcp_handshake_ms: u64,
    #[serde(default = "default_target_connect_ms")]
    pub target_connect_ms: u64,
    #[serde(default = "default_idle_timeout_sec")]
    pub idle_timeout_sec: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            server_connect_ms: default_server_connect_ms(),
            tls_handshake_ms: default_tls_handshake_ms(),
            raw_tcp_handshake_ms: default_raw_tcp_handshake_ms(),
            target_connect_ms: default_target_connect_ms(),
            idle_timeout_sec: default_idle_timeout_sec(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: default_max_concurrent_connections(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_relay_buffer_size")]
    pub upload_buffer_size: usize,
    #[serde(default = "default_relay_buffer_size")]
    pub download_buffer_size: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            upload_buffer_size: default_relay_buffer_size(),
            download_buffer_size: default_relay_buffer_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            server: String::new(),
            port: 0,
            tls: true,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_server_cert_sha256: None,
            path: None,
        }
    }
}

fn default_mode() -> TransportMode {
    TransportMode::RawTcp
}

fn default_server_connect_ms() -> u64 {
    10_000
}

fn default_tls_handshake_ms() -> u64 {
    10_000
}

fn default_raw_tcp_handshake_ms() -> u64 {
    5_000
}

fn default_target_connect_ms() -> u64 {
    10_000
}

fn default_idle_timeout_sec() -> u64 {
    300
}

fn default_max_concurrent_connections() -> usize {
    4096
}

fn default_relay_buffer_size() -> usize {
    64 * 1024
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDnsConfig {
    #[serde(default = "default_true")]
    pub remote_by_default: bool,
    #[serde(default = "default_true")]
    pub warn_on_ip_targets: bool,
    #[serde(default)]
    pub block_ip_targets: bool,
}

impl Default for ClientDnsConfig {
    fn default() -> Self {
        Self {
            remote_by_default: true,
            warn_on_ip_targets: true,
            block_ip_targets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_route_action")]
    pub default: RouteAction,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub action: RouteAction,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub domain_suffix: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Proxy,
    Block,
}

fn default_route_action() -> RouteAction {
    RouteAction::Proxy
}

fn default_true() -> bool {
    true
}

fn default_tun_name() -> String {
    "tun0".to_string()
}

fn default_tun_address() -> String {
    "10.10.0.2/24".to_string()
}

fn default_tun_mtu() -> u16 {
    1400
}

impl Default for RouteAction {
    fn default() -> Self {
        default_route_action()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default)]
    pub web_root: String,
    #[serde(default)]
    pub transport: ServerTransportConfig,
    #[serde(default)]
    pub tls: ServerTlsConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub security: ServerSecurityConfig,
    #[serde(default)]
    pub clients: Vec<AuthorizedClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTransportConfig {
    #[serde(default = "default_server_modes")]
    pub modes: Vec<TransportMode>,
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            modes: default_server_modes(),
        }
    }
}

fn default_server_modes() -> Vec<TransportMode> {
    vec![TransportMode::RawTcp]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSecurityConfig {
    #[serde(default = "default_true")]
    pub deny_private_ips: bool,
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self {
            deny_private_ips: true,
            allow_ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedClient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidationError {
    errors: Vec<ConfigFieldError>,
}

impl ConfigValidationError {
    fn new(errors: Vec<ConfigFieldError>) -> Self {
        Self { errors }
    }

    pub fn errors(&self) -> &[ConfigFieldError] {
        &self.errors
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.len() == 1 {
            let err = &self.errors[0];
            return write!(f, "invalid config: {}: {}", err.path, err.message);
        }

        writeln!(f, "invalid config:")?;
        for err in &self.errors {
            writeln!(f, "  - {}: {}", err.path, err.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFieldError {
    pub path: String,
    pub message: String,
}

impl ConfigFieldError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub fn generate_client_credentials() -> GeneratedCredentials {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(first.as_bytes());
    secret[16..].copy_from_slice(second.as_bytes());

    GeneratedCredentials {
        client_id: Uuid::new_v4().to_string(),
        client_secret: STANDARD_NO_PAD.encode(secret),
    }
}

pub fn load_client_config_yaml(raw: &str) -> Result<ClientConfig, ConfigValidationError> {
    let config: ClientConfig = serde_yaml::from_str(raw).map_err(|err| {
        ConfigValidationError::new(vec![ConfigFieldError::new("yaml", err.to_string())])
    })?;
    validate_client_config(&config)?;
    Ok(config)
}

pub fn load_server_config_yaml(raw: &str) -> Result<ServerConfig, ConfigValidationError> {
    let config: ServerConfig = serde_yaml::from_str(raw).map_err(|err| {
        ConfigValidationError::new(vec![ConfigFieldError::new("yaml", err.to_string())])
    })?;
    validate_server_config(&config)?;
    Ok(config)
}

pub fn validate_client_config(config: &ClientConfig) -> Result<(), ConfigValidationError> {
    let mut errors = Vec::new();

    if !config.inbounds.has_enabled_inbound() {
        errors.push(ConfigFieldError::new(
            "inbounds",
            "expected at least one enabled inbound: inbounds.socks or inbounds.tun",
        ));
    }

    if let Some(socks) = &config.inbounds.socks
        && socks.enabled
        && socks.listen.port() == 0
    {
        errors.push(ConfigFieldError::new(
            "inbounds.socks.listen",
            "port must be greater than 0",
        ));
    }

    if config.inbounds.tun.enabled {
        validate_non_empty(&mut errors, "inbounds.tun.name", &config.inbounds.tun.name);
        validate_cidr_value(
            &mut errors,
            "inbounds.tun.address",
            &config.inbounds.tun.address,
        );
        if config.inbounds.tun.mtu < 576 {
            errors.push(ConfigFieldError::new(
                "inbounds.tun.mtu",
                "must be at least 576",
            ));
        }
    }

    validate_transport_config(&mut errors, "transport", &config.transport);
    validate_client_auth_config(&mut errors, "auth", &config.auth);
    validate_timeouts_config(&mut errors, "timeouts", &config.timeouts);
    validate_relay_config(&mut errors, "relay", &config.relay);
    validate_limits_config(&mut errors, "limits", &config.limits);
    validate_routing_config_into(&mut errors, "routing.rules", &config.routing);
    validate_logging_config(&mut errors, "logging", &config.logging);

    finish_validation(errors)
}

pub fn validate_server_config(config: &ServerConfig) -> Result<(), ConfigValidationError> {
    let mut errors = Vec::new();

    if config.listen.port() == 0 {
        errors.push(ConfigFieldError::new(
            "listen",
            "port must be greater than 0",
        ));
    }
    validate_non_empty(&mut errors, "web_root", &config.web_root);
    if !config.web_root.trim().is_empty() {
        let web_root = Path::new(&config.web_root);
        if !web_root.exists() {
            errors.push(ConfigFieldError::new("web_root", "path does not exist"));
        } else if !web_root.is_dir() {
            errors.push(ConfigFieldError::new("web_root", "path is not a directory"));
        }
    }

    if config.tls.enabled {
        match config.tls.cert_path.as_deref() {
            Some(path) if !path.trim().is_empty() => {
                validate_file_path(&mut errors, "tls.cert_path", path)
            }
            _ => errors.push(ConfigFieldError::new(
                "tls.cert_path",
                "is required when tls.enabled=true",
            )),
        }
        match config.tls.key_path.as_deref() {
            Some(path) if !path.trim().is_empty() => {
                validate_file_path(&mut errors, "tls.key_path", path)
            }
            _ => errors.push(ConfigFieldError::new(
                "tls.key_path",
                "is required when tls.enabled=true",
            )),
        }
    }

    if config.clients.is_empty() {
        errors.push(ConfigFieldError::new(
            "clients",
            "at least one authorized client is required",
        ));
    }
    for (index, client) in config.clients.iter().enumerate() {
        validate_authorized_client_config(&mut errors, &format!("clients[{index}]"), client);
    }
    validate_unique_authorized_client_names(&mut errors, &config.clients);
    validate_server_transport_config(&mut errors, "transport", &config.transport);
    validate_timeouts_config(&mut errors, "timeouts", &config.timeouts);
    validate_relay_config(&mut errors, "relay", &config.relay);
    validate_limits_config(&mut errors, "limits", &config.limits);
    validate_server_security_config(&mut errors, "security", &config.security);

    finish_validation(errors)
}

fn validate_timeouts_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    timeouts: &TimeoutsConfig,
) {
    validate_positive_u64(
        errors,
        &format!("{base_path}.server_connect_ms"),
        timeouts.server_connect_ms,
    );
    validate_positive_u64(
        errors,
        &format!("{base_path}.tls_handshake_ms"),
        timeouts.tls_handshake_ms,
    );
    validate_positive_u64(
        errors,
        &format!("{base_path}.raw_tcp_handshake_ms"),
        timeouts.raw_tcp_handshake_ms,
    );
    validate_positive_u64(
        errors,
        &format!("{base_path}.target_connect_ms"),
        timeouts.target_connect_ms,
    );
    validate_positive_u64(
        errors,
        &format!("{base_path}.idle_timeout_sec"),
        timeouts.idle_timeout_sec,
    );
}

fn validate_limits_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    limits: &LimitsConfig,
) {
    validate_positive_usize(
        errors,
        &format!("{base_path}.max_concurrent_connections"),
        limits.max_concurrent_connections,
    );
}

fn validate_relay_config(errors: &mut Vec<ConfigFieldError>, base_path: &str, relay: &RelayConfig) {
    validate_positive_usize(
        errors,
        &format!("{base_path}.upload_buffer_size"),
        relay.upload_buffer_size,
    );
    validate_positive_usize(
        errors,
        &format!("{base_path}.download_buffer_size"),
        relay.download_buffer_size,
    );
}

fn validate_logging_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    logging: &LoggingConfig,
) {
    match logging.level.trim().to_ascii_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" | "off" => {}
        _ => errors.push(ConfigFieldError::new(
            format!("{base_path}.level"),
            "must be one of trace, debug, info, warn, error, or off",
        )),
    }
}

pub fn validate_routing_config(config: &RoutingConfig) -> Result<(), ConfigValidationError> {
    let mut errors = Vec::new();
    validate_routing_config_into(&mut errors, "routing.rules", config);
    finish_validation(errors)
}

fn validate_transport_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    transport: &TransportConfig,
) {
    validate_non_empty(errors, &format!("{base_path}.server"), &transport.server);
    if transport.port == 0 {
        errors.push(ConfigFieldError::new(
            format!("{base_path}.port"),
            "port must be greater than 0",
        ));
    }
    match transport.mode {
        TransportMode::RawTcp => {
            if transport.path.is_some() {
                errors.push(ConfigFieldError::new(
                    format!("{base_path}.path"),
                    "is only supported for http2 transport",
                ));
            }
        }
        TransportMode::Http2 => {
            if let Some(path) = &transport.path {
                validate_http_path(errors, &format!("{base_path}.path"), path);
            }
        }
        TransportMode::Http3 => {}
    }
    if transport.tls {
        if let Some(server_name) = &transport.tls_server_name {
            validate_non_empty(errors, &format!("{base_path}.tls_server_name"), server_name);
            if server_name.contains('/') || server_name.contains(':') {
                errors.push(ConfigFieldError::new(
                    format!("{base_path}.tls_server_name"),
                    "must be a DNS name or IP address, not a URL",
                ));
            }
        }
        if let Some(path) = &transport.tls_ca_cert_path {
            if path.trim().is_empty() {
                errors.push(ConfigFieldError::new(
                    format!("{base_path}.tls_ca_cert_path"),
                    "must not be empty",
                ));
            } else {
                validate_file_path(errors, &format!("{base_path}.tls_ca_cert_path"), path);
            }
        }
        if transport.tls_ca_cert_path.is_some() && transport.tls_server_cert_sha256.is_some() {
            errors.push(ConfigFieldError::new(
                format!("{base_path}.tls_server_cert_sha256"),
                "must not be used together with tls_ca_cert_path",
            ));
        }
        if let Some(pin) = &transport.tls_server_cert_sha256 {
            validate_sha256_hex(errors, &format!("{base_path}.tls_server_cert_sha256"), pin);
        }
    } else {
        if transport.tls_ca_cert_path.is_some() {
            errors.push(ConfigFieldError::new(
                format!("{base_path}.tls_ca_cert_path"),
                "requires tls=true",
            ));
        }
        if transport.tls_server_cert_sha256.is_some() {
            errors.push(ConfigFieldError::new(
                format!("{base_path}.tls_server_cert_sha256"),
                "requires tls=true",
            ));
        }
    }
}

fn validate_server_transport_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    transport: &ServerTransportConfig,
) {
    if transport.modes.is_empty() {
        errors.push(ConfigFieldError::new(
            format!("{base_path}.modes"),
            "must include at least one TCP transport mode",
        ));
    }
    for mode in &transport.modes {
        match mode {
            TransportMode::RawTcp | TransportMode::Http2 => {}
            TransportMode::Http3 => errors.push(ConfigFieldError::new(
                format!("{base_path}.modes"),
                "http3 transport is reserved but not implemented yet",
            )),
        }
    }
}

fn validate_server_security_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    security: &ServerSecurityConfig,
) {
    for (index, port) in security.allow_ports.iter().enumerate() {
        if *port == 0 {
            errors.push(ConfigFieldError::new(
                format!("{base_path}.allow_ports[{index}]"),
                "port must be greater than 0",
            ));
        }
    }
}

fn validate_client_auth_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    auth: &ClientAuthConfig,
) {
    validate_client_id(errors, &format!("{base_path}.client_id"), &auth.client_id);
    validate_non_empty(
        errors,
        &format!("{base_path}.client_secret"),
        &auth.client_secret,
    );
}

fn validate_authorized_client_config(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    client: &AuthorizedClient,
) {
    if let Some(name) = &client.name {
        validate_non_empty(errors, &format!("{base_path}.name"), name);
    }
    validate_client_id(errors, &format!("{base_path}.client_id"), &client.client_id);
    validate_non_empty(
        errors,
        &format!("{base_path}.client_secret"),
        &client.client_secret,
    );
}

fn validate_unique_authorized_client_names(
    errors: &mut Vec<ConfigFieldError>,
    clients: &[AuthorizedClient],
) {
    for (index, client) in clients.iter().enumerate() {
        let Some(name) = client.name.as_deref().map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if clients
            .iter()
            .take(index)
            .any(|existing| existing.name.as_deref().map(str::trim) == Some(name))
        {
            errors.push(ConfigFieldError::new(
                format!("clients[{index}].name"),
                format!("duplicate client name: {name}"),
            ));
        }
    }
}

fn validate_routing_config_into(
    errors: &mut Vec<ConfigFieldError>,
    base_path: &str,
    config: &RoutingConfig,
) {
    for (index, rule) in config.rules.iter().enumerate() {
        let rule_path = format!("{base_path}[{index}]");
        if let Some(cidr) = &rule.cidr {
            validate_cidr_value(errors, &format!("{rule_path}.cidr"), cidr);
        }
        if let Some(domain) = &rule.domain {
            validate_non_empty(errors, &format!("{rule_path}.domain"), domain);
        }
        if let Some(domain_suffix) = &rule.domain_suffix {
            validate_non_empty(errors, &format!("{rule_path}.domain_suffix"), domain_suffix);
        }
    }
}

fn validate_client_id(errors: &mut Vec<ConfigFieldError>, path: &str, value: &str) {
    validate_non_empty(errors, path, value);
    if !value.trim().is_empty() && Uuid::parse_str(value).is_err() {
        errors.push(ConfigFieldError::new(path, "must be a UUID"));
    }
}

fn validate_http_path(errors: &mut Vec<ConfigFieldError>, path: &str, value: &str) {
    validate_non_empty(errors, path, value);
    if value.trim().is_empty() {
        return;
    }
    if !value.starts_with('/') {
        errors.push(ConfigFieldError::new(path, "must start with '/'"));
    }
    if value.contains('?') || value.contains('#') || value.contains(char::is_whitespace) {
        errors.push(ConfigFieldError::new(
            path,
            "must be a plain absolute path without query, fragment, or whitespace",
        ));
    }
}

fn validate_cidr_value(errors: &mut Vec<ConfigFieldError>, path: &str, value: &str) {
    validate_non_empty(errors, path, value);
    if value.trim().is_empty() {
        return;
    }

    let Some((network, prefix_len)) = parse_cidr(value) else {
        errors.push(ConfigFieldError::new(path, "is not valid CIDR"));
        return;
    };
    match network {
        IpAddr::V4(_) if prefix_len > 32 => {
            errors.push(ConfigFieldError::new(path, "has invalid IPv4 prefix"))
        }
        IpAddr::V6(_) if prefix_len > 128 => {
            errors.push(ConfigFieldError::new(path, "has invalid IPv6 prefix"))
        }
        _ => {}
    }
}

fn validate_file_path(errors: &mut Vec<ConfigFieldError>, path: &str, value: &str) {
    let file_path = Path::new(value);
    if !file_path.exists() {
        errors.push(ConfigFieldError::new(path, "file does not exist"));
    } else if !file_path.is_file() {
        errors.push(ConfigFieldError::new(path, "path is not a file"));
    }
}

fn validate_sha256_hex(errors: &mut Vec<ConfigFieldError>, field: &str, value: &str) {
    let trimmed = value.trim();

    if trimmed.len() != 64 {
        errors.push(ConfigFieldError::new(
            field,
            "must be a 64-character lowercase or uppercase hex SHA-256 value",
        ));
        return;
    }

    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        errors.push(ConfigFieldError::new(
            field,
            "must contain only hexadecimal characters",
        ));
    }
}

fn validate_non_empty(errors: &mut Vec<ConfigFieldError>, path: &str, value: &str) {
    if value.trim().is_empty() {
        errors.push(ConfigFieldError::new(path, "must not be empty"));
    }
}

fn validate_positive_u64(errors: &mut Vec<ConfigFieldError>, path: &str, value: u64) {
    if value == 0 {
        errors.push(ConfigFieldError::new(path, "must be greater than 0"));
    }
}

fn validate_positive_usize(errors: &mut Vec<ConfigFieldError>, path: &str, value: usize) {
    if value == 0 {
        errors.push(ConfigFieldError::new(path, "must be greater than 0"));
    }
}

fn finish_validation(errors: Vec<ConfigFieldError>) -> Result<(), ConfigValidationError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(errors))
    }
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (network, prefix_len) = cidr.split_once('/')?;
    let network = network.parse::<IpAddr>().ok()?;
    let prefix_len = prefix_len.parse::<u8>().ok()?;
    Some((network, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PIN: &str = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";

    const BASE_CLIENT_CONFIG: &str = r#"
inbounds:
  socks:
    listen: "127.0.0.1:1080"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

    const BASE_CLIENT_TRANSPORT_CONFIG: &str = BASE_CLIENT_CONFIG;

    fn client_transport_config_with_tls(tls: bool, extra_transport: &str) -> String {
        format!(
            r#"
inbounds:
  socks:
    listen: "127.0.0.1:1080"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: {tls}
{extra_transport}auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#
        )
    }

    fn client_transport_config_with(extra_transport: &str) -> String {
        client_transport_config_with_tls(true, extra_transport)
    }

    #[test]
    fn client_config_accepts_raw_tcp_transport_shape() {
        let cfg = load_client_config_yaml(BASE_CLIENT_TRANSPORT_CONFIG).expect("valid config");

        assert_eq!(cfg.transport.mode, TransportMode::RawTcp);
        assert_eq!(cfg.transport.server, "127.0.0.1");
        assert_eq!(cfg.transport.port, 8443);
        assert!(cfg.transport.tls);
        assert!(cfg.transport.path.is_none());
        assert_eq!(cfg.timeouts.server_connect_ms, 10_000);
        assert_eq!(cfg.timeouts.tls_handshake_ms, 10_000);
        assert_eq!(cfg.timeouts.raw_tcp_handshake_ms, 5_000);
        assert_eq!(cfg.timeouts.target_connect_ms, 10_000);
        assert_eq!(cfg.timeouts.idle_timeout_sec, 300);
        assert_eq!(cfg.relay.upload_buffer_size, 65_536);
        assert_eq!(cfg.relay.download_buffer_size, 65_536);
        assert_eq!(cfg.limits.max_concurrent_connections, 4096);
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn client_config_accepts_logging_level_override() {
        let raw = format!("{BASE_CLIENT_TRANSPORT_CONFIG}\nlogging:\n  level: debug\n");

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn client_config_rejects_invalid_logging_level() {
        let raw = format!("{BASE_CLIENT_TRANSPORT_CONFIG}\nlogging:\n  level: verbose\n");

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("logging.level"));
    }

    #[test]
    fn client_config_accepts_transport_cert_sha256_pin() {
        let raw =
            client_transport_config_with(&format!("  tls_server_cert_sha256: \"{VALID_PIN}\"\n"));

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(
            cfg.transport.tls_server_cert_sha256.as_deref(),
            Some(VALID_PIN)
        );
    }

    #[test]
    fn client_config_rejects_short_transport_cert_sha256_pin() {
        let raw = client_transport_config_with("  tls_server_cert_sha256: \"abc\"\n");

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.tls_server_cert_sha256"));
        assert!(err.to_string().contains("64-character"));
    }

    #[test]
    fn client_config_rejects_long_transport_cert_sha256_pin() {
        let raw =
            client_transport_config_with(&format!("  tls_server_cert_sha256: \"{VALID_PIN}00\"\n"));

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.tls_server_cert_sha256"));
        assert!(err.to_string().contains("64-character"));
    }

    #[test]
    fn client_config_rejects_non_hex_transport_cert_sha256_pin() {
        let raw = client_transport_config_with(
            "  tls_server_cert_sha256: \"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"\n",
        );

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.tls_server_cert_sha256"));
        assert!(err.to_string().contains("hexadecimal"));
    }

    #[test]
    fn client_config_rejects_transport_ca_and_cert_pin_together() {
        let raw = client_transport_config_with(&format!(
            "  tls_ca_cert_path: \"Cargo.toml\"\n  tls_server_cert_sha256: \"{VALID_PIN}\"\n"
        ));

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.tls_server_cert_sha256"));
        assert!(err.to_string().contains("must not be used together"));
    }

    #[test]
    fn client_config_rejects_transport_cert_pin_when_tls_disabled() {
        let raw = client_transport_config_with_tls(
            false,
            &format!("  tls_server_cert_sha256: \"{VALID_PIN}\"\n"),
        );

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.tls_server_cert_sha256"));
        assert!(err.to_string().contains("requires tls=true"));
    }

    #[test]
    fn client_config_accepts_transport_cert_pin() {
        let raw = BASE_CLIENT_CONFIG.replace(
            "  tls: true",
            &format!("  tls: true\n  tls_server_cert_sha256: \"{VALID_PIN}\""),
        );

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(
            cfg.transport.tls_server_cert_sha256.as_deref(),
            Some(VALID_PIN)
        );
    }

    #[test]
    fn client_config_accepts_timeout_overrides() {
        let raw = format!(
            "{BASE_CLIENT_TRANSPORT_CONFIG}\ntimeouts:\n  server_connect_ms: 1\n  tls_handshake_ms: 2\n  raw_tcp_handshake_ms: 3\n  target_connect_ms: 4\n  idle_timeout_sec: 5\n"
        );

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.timeouts.server_connect_ms, 1);
        assert_eq!(cfg.timeouts.tls_handshake_ms, 2);
        assert_eq!(cfg.timeouts.raw_tcp_handshake_ms, 3);
        assert_eq!(cfg.timeouts.target_connect_ms, 4);
        assert_eq!(cfg.timeouts.idle_timeout_sec, 5);
    }

    #[test]
    fn client_config_rejects_zero_timeout() {
        let raw = format!("{BASE_CLIENT_TRANSPORT_CONFIG}\ntimeouts:\n  raw_tcp_handshake_ms: 0\n");

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("timeouts.raw_tcp_handshake_ms"));
    }

    #[test]
    fn client_config_accepts_relay_buffer_overrides() {
        let raw = format!(
            "{BASE_CLIENT_TRANSPORT_CONFIG}\nrelay:\n  upload_buffer_size: 32768\n  download_buffer_size: 131072\n"
        );

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.relay.upload_buffer_size, 32_768);
        assert_eq!(cfg.relay.download_buffer_size, 131_072);
    }

    #[test]
    fn client_config_rejects_zero_relay_buffer() {
        let raw = format!("{BASE_CLIENT_TRANSPORT_CONFIG}\nrelay:\n  upload_buffer_size: 0\n");

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("relay.upload_buffer_size"));
    }

    #[test]
    fn client_config_accepts_limit_overrides() {
        let raw =
            format!("{BASE_CLIENT_TRANSPORT_CONFIG}\nlimits:\n  max_concurrent_connections: 64\n");

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.limits.max_concurrent_connections, 64);
    }

    #[test]
    fn client_config_rejects_zero_connection_limit() {
        let raw =
            format!("{BASE_CLIENT_TRANSPORT_CONFIG}\nlimits:\n  max_concurrent_connections: 0\n");

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(
            err.to_string()
                .contains("limits.max_concurrent_connections")
        );
    }

    #[test]
    fn client_config_accepts_http2_transport_shape() {
        let raw = BASE_CLIENT_TRANSPORT_CONFIG.replace(
            "mode: raw_tcp\n  server",
            "mode: http2\n  path: \"/api/v1/events\"\n  server",
        );

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.transport.mode, TransportMode::Http2);
        assert_eq!(cfg.transport.path.as_deref(), Some("/api/v1/events"));
    }

    #[test]
    fn client_config_rejects_raw_tcp_transport_path() {
        let raw = BASE_CLIENT_TRANSPORT_CONFIG.replace(
            "mode: raw_tcp\n  server",
            "mode: raw_tcp\n  path: \"/api/tunnel/h2\"\n  server",
        );

        let err = load_client_config_yaml(&raw).expect_err("invalid config");

        assert!(err.to_string().contains("transport.path"));
        assert!(err.to_string().contains("only supported for http2"));
    }

    #[test]
    fn client_config_accepts_http3_as_reserved_transport_shape() {
        let raw = BASE_CLIENT_TRANSPORT_CONFIG.replace("mode: raw_tcp", "mode: http3");

        let cfg = load_client_config_yaml(&raw).expect("valid config");

        assert_eq!(cfg.transport.mode, TransportMode::Http3);
    }

    #[test]
    fn server_config_accepts_transport_modes() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
transport:
  modes:
    - raw_tcp
    - http2
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let cfg = load_server_config_yaml(raw).expect("valid config");

        assert_eq!(
            cfg.transport.modes,
            vec![TransportMode::RawTcp, TransportMode::Http2]
        );
        assert_eq!(cfg.timeouts.raw_tcp_handshake_ms, 5_000);
        assert_eq!(cfg.relay.upload_buffer_size, 65_536);
        assert_eq!(cfg.relay.download_buffer_size, 65_536);
        assert_eq!(cfg.limits.max_concurrent_connections, 4096);
        assert!(cfg.security.deny_private_ips);
        assert!(cfg.security.allow_ports.is_empty());
    }

    #[test]
    fn sample_server_config_enables_http2_mode() {
        let cfg: ServerConfig = serde_yaml::from_str(include_str!("../../../configs/server.yaml"))
            .expect("parse sample server config");

        assert!(cfg.transport.modes.contains(&TransportMode::RawTcp));
        assert!(cfg.transport.modes.contains(&TransportMode::Http2));
    }

    #[test]
    fn server_config_rejects_legacy_tunnel_path_field() {
        let raw = r#"
listen: "127.0.0.1:8443"
tunnel_path: "/api/tunnel"
web_root: "."
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("legacy tunnel_path must be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn server_config_accepts_limit_overrides() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
limits:
  max_concurrent_connections: 128
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let cfg = load_server_config_yaml(raw).expect("valid config");

        assert_eq!(cfg.limits.max_concurrent_connections, 128);
    }

    #[test]
    fn server_config_rejects_zero_connection_limit() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
limits:
  max_concurrent_connections: 0
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");

        assert!(
            err.to_string()
                .contains("limits.max_concurrent_connections")
        );
    }

    #[test]
    fn server_config_accepts_relay_buffer_overrides() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
relay:
  upload_buffer_size: 16384
  download_buffer_size: 262144
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let cfg = load_server_config_yaml(raw).expect("valid config");

        assert_eq!(cfg.relay.upload_buffer_size, 16_384);
        assert_eq!(cfg.relay.download_buffer_size, 262_144);
    }

    #[test]
    fn server_config_rejects_zero_relay_buffer() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
relay:
  download_buffer_size: 0
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");

        assert!(err.to_string().contains("relay.download_buffer_size"));
    }

    #[test]
    fn server_config_accepts_security_acl_overrides() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
security:
  deny_private_ips: false
  allow_ports:
    - 80
    - 443
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let cfg = load_server_config_yaml(raw).expect("valid config");

        assert!(!cfg.security.deny_private_ips);
        assert_eq!(cfg.security.allow_ports, vec![80, 443]);
    }

    #[test]
    fn server_config_rejects_zero_acl_port() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
security:
  allow_ports:
    - 0
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");

        assert!(err.to_string().contains("security.allow_ports[0]"));
    }

    #[test]
    fn server_config_rejects_reserved_transport_modes() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
transport:
  modes:
    - raw_tcp
    - http3
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");

        assert!(err.to_string().contains("http3 transport is reserved"));
    }

    #[test]
    fn client_dns_config_defaults_to_remote_dns_warning_without_blocking() {
        let cfg: ClientConfig = serde_yaml::from_str(BASE_CLIENT_CONFIG).expect("parse config");

        assert!(cfg.dns.remote_by_default);
        assert!(cfg.dns.warn_on_ip_targets);
        assert!(!cfg.dns.block_ip_targets);
    }

    #[test]
    fn client_dns_config_can_be_overridden() {
        let raw = format!(
            "{BASE_CLIENT_CONFIG}\ndns:\n  remote_by_default: false\n  warn_on_ip_targets: false\n  block_ip_targets: true\n"
        );
        let cfg: ClientConfig = serde_yaml::from_str(&raw).expect("parse config");

        assert!(!cfg.dns.remote_by_default);
        assert!(!cfg.dns.warn_on_ip_targets);
        assert!(cfg.dns.block_ip_targets);
    }

    #[test]
    fn client_config_rejects_legacy_inbound_field() {
        let raw = BASE_CLIENT_CONFIG.replace(
            "inbounds:\n  socks:\n    listen: \"127.0.0.1:1080\"",
            "inbound:\n  listen: \"127.0.0.1:1080\"",
        );

        let err = load_client_config_yaml(&raw).expect_err("legacy inbound must be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn client_config_rejects_legacy_outbound_field() {
        let raw = BASE_CLIENT_CONFIG.replace(
            "transport:\n  mode: raw_tcp\n  server: \"127.0.0.1\"\n  port: 8443\n  tls: true",
            "outbound:\n  server: \"127.0.0.1\"\n  port: 8443\n  path: \"/api/tunnel\"\n  tls: true",
        );

        let err = load_client_config_yaml(&raw).expect_err("legacy outbound must be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn client_config_rejects_legacy_outbounds_field() {
        let raw = BASE_CLIENT_CONFIG.replace(
            "transport:\n  mode: raw_tcp\n  server: \"127.0.0.1\"\n  port: 8443\n  tls: true",
            "outbounds:\n  proxy:\n    server: \"127.0.0.1\"\n    port: 8443\n    path: \"/api/tunnel\"\n    tls: true",
        );

        let err = load_client_config_yaml(&raw).expect_err("legacy outbounds must be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn client_config_rejects_legacy_routing_outbound_alias() {
        let raw = format!(
            "{BASE_CLIENT_CONFIG}\nrouting:\n  rules:\n    - outbound: direct\n      domain_suffix: \".local\"\n"
        );

        let err =
            load_client_config_yaml(&raw).expect_err("legacy routing outbound must be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn client_config_accepts_inbounds_socks_shape() {
        let raw = r#"
inbounds:
  socks:
    listen: "127.0.0.1:1081"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");
        let socks = cfg.inbounds.socks.expect("socks inbound");

        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1081");
    }

    #[test]
    fn client_config_accepts_tun_inbound_shape() {
        let raw = r#"
inbounds:
  tun:
    enabled: true
    name: "tun-test0"
    address: "10.20.0.2/24"
    mtu: 1300
    auto_route: true
    dns: "10.20.0.53"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");

        assert!(cfg.inbounds.socks.is_none());
        assert!(cfg.inbounds.tun.enabled);
        assert_eq!(cfg.inbounds.tun.name, "tun-test0");
        assert_eq!(cfg.inbounds.tun.address, "10.20.0.2/24");
        assert_eq!(cfg.inbounds.tun.mtu, 1300);
        assert!(cfg.inbounds.tun.auto_route);
        assert_eq!(
            cfg.inbounds.tun.dns.expect("tun dns").to_string(),
            "10.20.0.53"
        );
    }

    #[test]
    fn client_config_rejects_missing_enabled_inbounds() {
        let raw = r#"
inbounds:
  socks:
    enabled: false
    listen: "127.0.0.1:1080"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let err = load_client_config_yaml(raw).expect_err("invalid config");
        assert!(err.to_string().contains("inbounds"));
    }

    #[test]
    fn client_config_validation_reports_field_paths() {
        let raw = r#"
inbounds:
  socks:
    listen: "127.0.0.1:1080"
transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 0
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
routing:
  rules:
    - action: "direct"
      cidr: "127.0.0.0/99"
"#;

        let err = load_client_config_yaml(raw).expect_err("invalid config");
        let message = err.to_string();

        assert!(message.contains("transport.port"));
        assert!(message.contains("auth.client_secret"));
        assert!(message.contains("routing.rules[0].cidr"));
    }

    #[test]
    fn server_config_validation_reports_field_paths() {
        let raw = r#"
listen: "127.0.0.1:8443"
web_root: "."
tls:
  enabled: true
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");
        let message = err.to_string();

        assert!(message.contains("tls.cert_path"));
        assert!(message.contains("tls.key_path"));
        assert!(message.contains("clients[0].client_secret"));
    }

    #[test]
    fn generated_credentials_are_valid_config_values() {
        let credentials = generate_client_credentials();

        assert!(Uuid::parse_str(&credentials.client_id).is_ok());
        assert!(credentials.client_secret.len() >= 32);
    }
}
