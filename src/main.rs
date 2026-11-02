use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fitproxy::cache::DiskCache;
use fitproxy::config::{AppConfig, CliArgs};
use fitproxy::dns::DnsServer;
use fitproxy::fakeip::FakeIpManager;
use fitproxy::network::NetworkManager;
use fitproxy::tproxy::TproxyServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging with RUST_LOG support (default to info)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting fitproxy...");

    let cli = CliArgs::parse();
    let config = match AppConfig::load_and_merge(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    info!("Loaded {} proxy rules", config.rules.rules().len());
    info!("Fake IP CIDR range: {}", config.fakeip_range);
    info!(
        "Static fake IP assignments: {}",
        config.static_fakeips.len()
    );
    info!("TPROXY listen address: {}", config.listen_addr);
    info!("DNS server listen address: {}", config.listen_dns_addr);
    info!("Disk cache path: {:?}", config.cache_path);

    // Initialize disk cache
    let disk_cache = Arc::new(DiskCache::new(config.cache_path.clone()));

    // Load persisted allocations, validate, deduplicate, and compact immediately
    let (initial_domain_to_ip, initial_ip_to_domain) = match disk_cache.load_and_clean(
        &config.fakeip_range,
        &config.rules,
        &config.static_fakeips,
        &config.static_ip_to_domain,
    ) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Failed to read cache file {:?}: {}. Starting with empty cache.",
                config.cache_path, e
            );
            (
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
            )
        }
    };

    let fakeip_manager = FakeIpManager::new(
        config.fakeip_range,
        config.static_fakeips.clone(),
        config.static_ip_to_domain.clone(),
        initial_domain_to_ip,
        initial_ip_to_domain,
        disk_cache.clone(),
    );

    // Setup system routing and nftables rules if requested
    let mut network_manager = if config.setup_network {
        let mut nm = NetworkManager::new(
            config.fakeip_range,
            config.listen_addr.port(),
            config.table_id,
            config.fwmark.clone(),
        );
        if let Err(e) = nm.setup() {
            warn!(
                "Network routing / nftables setup failed: {}. \
                 If running in a container or without CAP_NET_ADMIN, use --no-network-setup.",
                e
            );
        }
        Some(nm)
    } else {
        info!("Automatic network setup disabled (--no-network-setup)");
        None
    };

    // DNS server
    let dns_server = Arc::new(DnsServer::new(
        config.listen_dns_addr,
        fakeip_manager.clone(),
        config.rules.clone(),
    ));

    // TPROXY server
    let tproxy_server = Arc::new(TproxyServer::new(
        config.listen_addr,
        fakeip_manager.clone(),
        config.rules.clone(),
    ));

    // Periodic cache compaction task (every 30 minutes)
    let compactor_manager = fakeip_manager.clone();
    let compactor_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1800));
        loop {
            interval.tick().await;
            compactor_manager.compact_cache();
        }
    });

    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            error!("DNS server fatal error: {}", e);
        }
    });

    let tproxy_task = tokio::spawn(async move {
        if let Err(e) = tproxy_server.run().await {
            error!("TPROXY server fatal error: {}", e);
        }
    });

    // Graceful shutdown signals: SIGINT (Ctrl+C) and SIGTERM
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT (Ctrl+C), shutting down gracefully...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down gracefully...");
        }
        _ = dns_task => {
            warn!("DNS server stopped unexpectedly");
        }
        _ = tproxy_task => {
            warn!("TPROXY server stopped unexpectedly");
        }
    }

    compactor_task.abort();

    // Final compaction before exit
    info!("Performing final cache compaction...");
    fakeip_manager.compact_cache();

    // Cleanup network routing and nftables rules
    if let Some(mut nm) = network_manager.take() {
        nm.teardown();
    }

    info!("fitproxy shutdown complete");
    Ok(())
}
