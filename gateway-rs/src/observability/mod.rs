pub mod analytics_aggregator;
pub mod audit;
pub mod email;
pub mod logging;
pub mod metrics;

pub fn init() {
    logging::init();
}
