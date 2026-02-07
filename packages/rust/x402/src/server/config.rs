use std::str::FromStr;

use envconfig::Envconfig;
use url::Url;

#[derive(Envconfig)]
struct TabEnvConfig {
    #[envconfig(from = "4MICA_TAB_ENDPOINT", default = "/4mica/tab")]
    tab_endpoint: String,
    #[envconfig(from = "4MICA_TAB_TTL_SECONDS")]
    tab_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabConfig {
    pub advertised_endpoint: String,
    pub ttl_seconds: Option<u64>,
}

impl TabConfig {
    pub fn new(advertised_endpoint: String, ttl_seconds: Option<u64>) -> Self {
        Self {
            advertised_endpoint,
            ttl_seconds,
        }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let env_config = TabEnvConfig::init_from_env()?;
        Ok(Self {
            advertised_endpoint: env_config.tab_endpoint,
            ttl_seconds: env_config.tab_ttl_seconds,
        })
    }

    pub fn from_env_with_resource(resource_url: &str) -> anyhow::Result<Self> {
        let env_config = TabEnvConfig::init_from_env()?;
        let advertised_endpoint =
            EndpointResolver::new(&env_config.tab_endpoint, resource_url).resolve_to_string()?;

        Ok(Self {
            advertised_endpoint,
            ttl_seconds: env_config.tab_ttl_seconds,
        })
    }
}

impl FromStr for TabConfig {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.to_owned(), None))
    }
}

pub fn tab_endpoint_from_env_with_resource(resource_url: &str) -> anyhow::Result<String> {
    TabConfig::from_env_with_resource(resource_url).map(|config| config.advertised_endpoint)
}

struct EndpointResolver<'a> {
    raw_endpoint: &'a str,
    resource_url: &'a str,
}

impl<'a> EndpointResolver<'a> {
    fn new(raw_endpoint: &'a str, resource_url: &'a str) -> Self {
        Self {
            raw_endpoint,
            resource_url,
        }
    }

    fn resolve_to_string(&self) -> anyhow::Result<String> {
        if Url::parse(self.raw_endpoint).is_ok() {
            return Ok(self.raw_endpoint.to_owned());
        }

        Ok(self
            .join_with_resource_base(self.raw_endpoint)
            .map(|url| url.to_string())?)
    }

    fn join_with_resource_base(&self, path: &str) -> Result<Url, url::ParseError> {
        let mut base = Url::parse(self.resource_url)?;
        base.set_path("/");
        base.set_query(None);
        base.set_fragment(None);

        let normalized_path = normalize_path(path);
        base.join(&normalized_path)
    }
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

pub fn extract_path(endpoint: &str) -> String {
    let path = Url::parse(endpoint)
        .ok()
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|| endpoint.to_owned());

    normalize_path(&path)
}
