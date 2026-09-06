use std::sync::Arc;

use opentelemetry::{
    global,
    metrics::{Counter, Meter},
};
use opentelemetry_sdk::metrics::SdkMeterProvider;

#[derive(Clone)]
pub struct Metrics {
    pub search_count: Arc<Counter<u64>>,
    pub request_count: Arc<Counter<u64>>,
}

impl Metrics {
    pub fn new(endpoint: Option<&str>) -> Self {
        if let Some(endpoint) = endpoint {
            tracing::info!(endpoint = %endpoint, "OTLP endpoint configured; using process meter provider");
        }
        let provider = SdkMeterProvider::builder().build();
        global::set_meter_provider(provider);
        let meter: Meter = global::meter("papra-vector-search");
        Self {
            search_count: Arc::new(meter.u64_counter("papra.search.count").build()),
            request_count: Arc::new(meter.u64_counter("papra.http.request.count").build()),
        }
    }

    pub fn search(&self, status: &'static str) {
        self.search_count
            .add(1, &[opentelemetry::KeyValue::new("status", status)]);
    }

    pub fn request(&self, method: &str, route: &str, status: u16) {
        self.request_count.add(
            1,
            &[
                opentelemetry::KeyValue::new("http.method", method.to_string()),
                opentelemetry::KeyValue::new("http.route", route.to_string()),
                opentelemetry::KeyValue::new("http.response.status_code", status as i64),
            ],
        );
    }
}

pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}
