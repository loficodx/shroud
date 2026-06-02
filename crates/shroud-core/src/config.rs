use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub inbound: Option<SocksInboundConfig>,
    pub inbounds: ClientInboundsConfig,
    pub transport: TransportConfig,
    pub outbound: OutboundConfig,
    pub auth: ClientAuthConfig,
    pub timeouts: TimeoutsConfig,
    pub limits: LimitsConfig,
    pub routing: RoutingConfig,
    pub dns: ClientDnsConfig,
    #[serde(skip_serializing)]
    transport_source: TransportConfigSource,
    #[serde(skip_serializing)]
    transport_compat_warnings: Vec<String>,
}

impl<'de> Deserialize<'de> for ClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ClientConfigRaw::deserialize(deserializer)?;

        let mut inbounds: ClientInboundsConfig = raw.inbounds.unwrap_or_default().into();
        if let Some(legacy_socks) = raw.inbound {
            inbounds.socks = Some(legacy_socks);
        }

        let inbound = inbounds.socks.clone();

        let legacy_outbound = raw
            .outbound
            .or_else(|| raw.outbounds.and_then(|outbounds| outbounds.proxy));

        let (transport, outbound, transport_source, transport_compat_warnings) =
            match (raw.transport, legacy_outbound) {
                (Some(transport), Some(_)) => (
                    transport.clone(),
                    OutboundConfig::from_transport(&transport),
                    TransportConfigSource::Transport,
                    vec![
                        "outbound config is deprecated and ignored when transport is set"
                            .to_string(),
                    ],
                ),
                (Some(transport), None) => (
                    transport.clone(),
                    OutboundConfig::from_transport(&transport),
                    TransportConfigSource::Transport,
                    Vec::new(),
                ),
                (None, Some(outbound)) => (
                    TransportConfig::from_legacy_outbound(&outbound),
                    outbound.clone(),
                    TransportConfigSource::LegacyOutbound,
                    legacy_outbound_warnings(&outbound),
                ),
                (None, None) => (
                    TransportConfig::default(),
                    OutboundConfig::default(),
                    TransportConfigSource::Default,
                    Vec::new(),
                ),
            };

        let auth = raw.auth.unwrap_or_default();

        let timeouts = raw.timeouts.unwrap_or_default();
        let limits = raw.limits.unwrap_or_default();
        let routing = raw.routing.unwrap_or_default();
        let dns = raw.dns.unwrap_or_default();

        Ok(Self {
            inbound,
            inbounds,
            transport,
            outbound,
            auth,
            timeouts,
            limits,
            routing,
            dns,
            transport_source,
            transport_compat_warnings,
        })
    }
}

impl ClientConfig {
    pub fn transport_compat_warnings(&self) -> &[String] {
        &self.transport_compat_warnings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub tls_ca_cert_path: Option<String>,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            path: String::new(),
            tls: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
        }
    }
}

impl OutboundConfig {
    fn from_transport(transport: &TransportConfig) -> Self {
        Self {
            server: transport.server.clone(),
            port: transport.port,
            path: transport
                .path
                .clone()
                .unwrap_or_else(default_legacy_tunnel_path),
            tls: transport.tls,
            tls_server_name: transport.tls_server_name.clone(),
            tls_ca_cert_path: transport.tls_ca_cert_path.clone(),
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

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            server: String::new(),
            port: 0,
            tls: true,
            tls_server_name: None,
            tls_ca_cert_path: None,
            path: None,
        }
    }
}

impl TransportConfig {
    fn from_legacy_outbound(outbound: &OutboundConfig) -> Self {
        Self {
            mode: default_mode(),
            server: outbound.server.clone(),
            port: outbound.port,
            tls: outbound.tls,
            tls_server_name: outbound.tls_server_name.clone(),
            tls_ca_cert_path: outbound.tls_ca_cert_path.clone(),
            path: (!outbound.path.is_empty()).then(|| outbound.path.clone()),
        }
    }
}

fn default_mode() -> TransportMode {
    TransportMode::RawTcp
}

fn default_legacy_tunnel_path() -> String {
    "/api/tunnel".to_string()
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

fn legacy_outbound_warnings(outbound: &OutboundConfig) -> Vec<String> {
    let mut warnings = vec![
        "outbound config is deprecated; use transport.mode, transport.server, and transport.port"
            .to_string(),
    ];
    if !outbound.path.is_empty() {
        warnings.push(
            "outbound.path with custom HTTP Upgrade is deprecated and will be removed".to_string(),
        );
    }
    warnings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportConfigSource {
    Transport,
    LegacyOutbound,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct RoutingConfig {
    #[serde(default = "default_route_action")]
    pub default: RouteAction,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(alias = "outbound")]
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
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "default_legacy_tunnel_path")]
    pub tunnel_path: String,
    #[serde(default)]
    pub web_root: String,
    #[serde(default)]
    pub transport: ServerTransportConfig,
    #[serde(default)]
    pub tls: ServerTlsConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub security: ServerSecurityConfig,
    #[serde(default)]
    pub clients: Vec<AuthorizedClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ServerTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedClient {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
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
            "expected at least one enabled inbound: inbound, inbounds.socks, or inbounds.tun",
        ));
    }

    if let Some(socks) = &config.inbounds.socks {
        if socks.enabled && socks.listen.port() == 0 {
            errors.push(ConfigFieldError::new(
                "inbounds.socks.listen",
                "port must be greater than 0",
            ));
        }
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

    match config.transport_source {
        TransportConfigSource::Transport => {
            validate_transport_config(&mut errors, "transport", &config.transport);
        }
        TransportConfigSource::LegacyOutbound | TransportConfigSource::Default => {
            validate_outbound_config(&mut errors, &config.outbound);
        }
    }
    validate_client_auth_config(&mut errors, "auth", &config.auth);
    validate_timeouts_config(&mut errors, "timeouts", &config.timeouts);
    validate_limits_config(&mut errors, "limits", &config.limits);
    validate_routing_config_into(&mut errors, "routing.rules", &config.routing);

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
    validate_http_path(&mut errors, "tunnel_path", &config.tunnel_path);
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
    validate_server_transport_config(&mut errors, "transport", &config.transport);
    validate_timeouts_config(&mut errors, "timeouts", &config.timeouts);
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
    if let Some(path) = &transport.path {
        validate_http_path(errors, &format!("{base_path}.path"), path);
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
            TransportMode::RawTcp => {}
            TransportMode::Http2 => errors.push(ConfigFieldError::new(
                format!("{base_path}.modes"),
                "http2 transport is reserved but not implemented yet",
            )),
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

fn validate_outbound_config(errors: &mut Vec<ConfigFieldError>, outbound: &OutboundConfig) {
    validate_non_empty(errors, "outbound.server", &outbound.server);
    if outbound.port == 0 {
        errors.push(ConfigFieldError::new(
            "outbound.port",
            "port must be greater than 0",
        ));
    }
    validate_http_path(errors, "outbound.path", &outbound.path);
    if outbound.tls {
        if let Some(server_name) = &outbound.tls_server_name {
            validate_non_empty(errors, "outbound.tls_server_name", server_name);
            if server_name.contains('/') || server_name.contains(':') {
                errors.push(ConfigFieldError::new(
                    "outbound.tls_server_name",
                    "must be a DNS name or IP address, not a URL",
                ));
            }
        }
        if let Some(path) = &outbound.tls_ca_cert_path {
            if path.trim().is_empty() {
                errors.push(ConfigFieldError::new(
                    "outbound.tls_ca_cert_path",
                    "must not be empty",
                ));
            } else {
                validate_file_path(errors, "outbound.tls_ca_cert_path", path);
            }
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
    validate_client_id(errors, &format!("{base_path}.client_id"), &client.client_id);
    validate_non_empty(
        errors,
        &format!("{base_path}.client_secret"),
        &client.client_secret,
    );
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

#[derive(Debug, Deserialize)]
struct ClientConfigRaw {
    #[serde(default)]
    inbound: Option<SocksInboundConfig>,
    #[serde(default)]
    inbounds: Option<ClientInboundsRaw>,
    #[serde(default)]
    transport: Option<TransportConfig>,
    #[serde(default)]
    outbound: Option<OutboundConfig>,
    #[serde(default)]
    outbounds: Option<ClientOutboundsRaw>,
    #[serde(default)]
    auth: Option<ClientAuthConfig>,
    #[serde(default)]
    timeouts: Option<TimeoutsConfig>,
    #[serde(default)]
    limits: Option<LimitsConfig>,
    #[serde(default)]
    routing: Option<RoutingConfig>,
    #[serde(default)]
    dns: Option<ClientDnsConfig>,
}

#[derive(Debug, Deserialize)]
struct ClientInboundsRaw {
    #[serde(default)]
    socks: Option<SocksInboundConfig>,
    #[serde(default)]
    tun: TunInboundConfig,
}

impl Default for ClientInboundsRaw {
    fn default() -> Self {
        Self {
            socks: None,
            tun: TunInboundConfig::default(),
        }
    }
}

impl From<ClientInboundsRaw> for ClientInboundsConfig {
    fn from(raw: ClientInboundsRaw) -> Self {
        Self {
            socks: raw.socks,
            tun: raw.tun,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientOutboundsRaw {
    #[serde(default)]
    proxy: Option<OutboundConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CLIENT_CONFIG: &str = r#"
inbound:
  listen: "127.0.0.1:1080"
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

    const BASE_CLIENT_TRANSPORT_CONFIG: &str = r#"
inbound:
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

    #[test]
    fn client_config_accepts_raw_tcp_transport_shape() {
        let cfg = load_client_config_yaml(BASE_CLIENT_TRANSPORT_CONFIG).expect("valid config");

        assert_eq!(cfg.transport.mode, TransportMode::RawTcp);
        assert_eq!(cfg.transport.server, "127.0.0.1");
        assert_eq!(cfg.transport.port, 8443);
        assert!(cfg.transport.tls);
        assert!(cfg.transport.path.is_none());
        assert!(cfg.transport_compat_warnings().is_empty());

        assert_eq!(cfg.outbound.server, "127.0.0.1");
        assert_eq!(cfg.outbound.port, 8443);
        assert_eq!(cfg.outbound.path, "/api/tunnel");
        assert_eq!(cfg.timeouts.server_connect_ms, 10_000);
        assert_eq!(cfg.timeouts.tls_handshake_ms, 10_000);
        assert_eq!(cfg.timeouts.raw_tcp_handshake_ms, 5_000);
        assert_eq!(cfg.timeouts.target_connect_ms, 10_000);
        assert_eq!(cfg.timeouts.idle_timeout_sec, 300);
        assert_eq!(cfg.limits.max_concurrent_connections, 4096);
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
        assert_eq!(cfg.outbound.path, "/api/v1/events");
    }

    #[test]
    fn client_config_maps_legacy_outbound_to_transport_with_warnings() {
        let cfg = load_client_config_yaml(BASE_CLIENT_CONFIG).expect("valid config");

        assert_eq!(cfg.transport.mode, TransportMode::RawTcp);
        assert_eq!(cfg.transport.server, "127.0.0.1");
        assert_eq!(cfg.transport.port, 8443);
        assert_eq!(cfg.transport.path.as_deref(), Some("/api/tunnel"));

        let warnings = cfg.transport_compat_warnings();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("outbound config is deprecated"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("outbound.path"))
        );
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
tunnel_path: "/api/tunnel"
web_root: "."
transport:
  modes:
    - raw_tcp
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let cfg = load_server_config_yaml(raw).expect("valid config");

        assert_eq!(cfg.transport.modes, vec![TransportMode::RawTcp]);
        assert_eq!(cfg.timeouts.raw_tcp_handshake_ms, 5_000);
        assert_eq!(cfg.limits.max_concurrent_connections, 4096);
        assert!(cfg.security.deny_private_ips);
        assert!(cfg.security.allow_ports.is_empty());
    }

    #[test]
    fn server_config_accepts_limit_overrides() {
        let raw = r#"
listen: "127.0.0.1:8443"
tunnel_path: "/api/tunnel"
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
tunnel_path: "/api/tunnel"
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
    fn server_config_accepts_security_acl_overrides() {
        let raw = r#"
listen: "127.0.0.1:8443"
tunnel_path: "/api/tunnel"
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
tunnel_path: "/api/tunnel"
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
tunnel_path: "/api/tunnel"
web_root: "."
transport:
  modes:
    - raw_tcp
    - http2
    - http3
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "secret"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");

        assert!(err.to_string().contains("http2 transport is reserved"));
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
    fn client_config_normalizes_legacy_inbound_into_inbounds_socks() {
        let cfg: ClientConfig = serde_yaml::from_str(BASE_CLIENT_CONFIG).expect("parse config");

        let legacy = cfg.inbound.expect("legacy inbound alias");
        let socks = cfg.inbounds.socks.expect("normalized socks inbound");

        assert!(legacy.enabled);
        assert_eq!(legacy.listen.to_string(), "127.0.0.1:1080");
        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1080");
        assert!(!cfg.inbounds.tun.enabled);
        assert_eq!(cfg.inbounds.tun.name, "tun0");
        assert_eq!(cfg.inbounds.tun.address, "10.10.0.2/24");
        assert_eq!(cfg.inbounds.tun.mtu, 1400);
        assert!(!cfg.inbounds.tun.auto_route);
        assert!(cfg.inbounds.tun.dns.is_none());
    }

    #[test]
    fn client_config_accepts_inbounds_socks_shape() {
        let raw = r#"
inbounds:
  socks:
    listen: "127.0.0.1:1081"
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");
        let socks = cfg.inbounds.socks.expect("socks inbound");

        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1081");
        assert!(cfg.inbound.is_some());
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
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");

        assert!(cfg.inbound.is_none());
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
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
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
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "api/tunnel"
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

        assert!(message.contains("outbound.path"));
        assert!(message.contains("auth.client_secret"));
        assert!(message.contains("routing.rules[0].cidr"));
    }

    #[test]
    fn server_config_validation_reports_field_paths() {
        let raw = r#"
listen: "127.0.0.1:8443"
tunnel_path: "api/tunnel"
web_root: "."
tls:
  enabled: true
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
"#;

        let err = load_server_config_yaml(raw).expect_err("invalid config");
        let message = err.to_string();

        assert!(message.contains("tunnel_path"));
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
