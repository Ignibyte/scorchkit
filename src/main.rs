use clap::Parser;

use scorchkit::cli::args::Cli;
use scorchkit::cli::runner;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    if let Err(e) = runner::execute(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
