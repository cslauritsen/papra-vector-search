use std::sync::Arc;

use opentelemetry::{
    global,
    metrics::{Counter, Meter},
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};

#[derive(Clone)]
/// Counters used to monitor searches and HTTP requests.
pub struct Metrics {
    /// Number of searches grouped by status.
    pub search_count: Arc<Counter<u64>>,
    /// Number of HTTP requests grouped by route and status.
    pub request_count: Arc<Counter<u64>>,
    prometheus_registry: Arc<Registry>,
    prometheus_search_count: IntCounterVec,
    prometheus_request_count: IntCounterVec,
}

impl Metrics {
    /// Creates application metrics and registers the process meter provider.
    pub fn new(endpoint: Option<&str>) -> Result<Self, prometheus::Error> {
        if let Some(endpoint) = endpoint {
            tracing::info!(endpoint = %endpoint, "OTLP endpoint configured; using process meter provider");
        }
        let provider = SdkMeterProvider::builder().build();
        global::set_meter_provider(provider);
        let meter: Meter = global::meter("papra-vector-search");
        let prometheus_registry = Arc::new(Registry::new());
        let prometheus_search_count = IntCounterVec::new(
            Opts::new("papra_search", "Number of searches grouped by outcome"),
            &["status"],
        )?;
        let prometheus_request_count = IntCounterVec::new(
            Opts::new(
                "papra_http_requests",
                "Number of HTTP requests grouped by method, route, and status",
            ),
            &["method", "route", "status"],
        )?;
        prometheus_registry.register(Box::new(prometheus_search_count.clone()))?;
        prometheus_registry.register(Box::new(prometheus_request_count.clone()))?;
        Ok(Self {
            search_count: Arc::new(meter.u64_counter("papra.search.count").build()),
            request_count: Arc::new(meter.u64_counter("papra.http.request.count").build()),
            prometheus_registry,
            prometheus_search_count,
            prometheus_request_count,
        })
    }

    /// Records a search attempt grouped by outcome.
    pub fn search(&self, status: &'static str) {
        self.search_count
            .add(1, &[opentelemetry::KeyValue::new("status", status)]);
        self.prometheus_search_count
            .with_label_values(&[status])
            .inc();
    }

    /// Records an HTTP request grouped by method, route, and status.
    pub fn request(&self, method: &str, route: &str, status: u16) {
        self.request_count.add(
            1,
            &[
                opentelemetry::KeyValue::new("http.method", method.to_string()),
                opentelemetry::KeyValue::new("http.route", route.to_string()),
                opentelemetry::KeyValue::new("http.response.status_code", status as i64),
            ],
        );
        self.prometheus_request_count
            .with_label_values(&[method, route, &status.to_string()])
            .inc();
    }

    /// Encodes accumulated counters in Prometheus text format.
    pub fn prometheus_text(&self) -> Result<String, prometheus::Error> {
        let metric_families = self.prometheus_registry.gather();
        let mut output = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut output)?;
        String::from_utf8(output).map_err(|error| prometheus::Error::Msg(error.to_string()))
    }
}

/// Initializes tracing output using the configured log format.
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match std::env::var("LOG_FORMAT")
        .unwrap_or_else(|_| "pretty".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .try_init();
        }
        "pretty" | "human" => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .pretty()
                .try_init();
        }
        value => {
            eprintln!("invalid LOG_FORMAT={value:?}; using human-readable logs");
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .pretty()
                .try_init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_text_contains_recorded_counters() {
        let metrics = Metrics::new(None).unwrap();
        metrics.search("success");
        metrics.request("GET", "/metrics", 200);
        let output = metrics.prometheus_text().unwrap();

        assert!(output.contains("papra_search{status=\"success\"} 1"));
        assert!(output.contains(
            "papra_http_requests{method=\"GET\",route=\"/metrics\",status=\"200\"} 1"
        ));
    }
}
