use clap::Parser;

use scorchkit::cli::args::Cli;
use scorchkit::cli::runner;

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref()
        == Some(std::ffi::OsStr::new(scorchkit::extension::EXTENSION_WORKER_ARGUMENT))
        && arguments.next().is_none()
    {
        if scorchkit::extension::run_worker_stdio().await.is_err() {
            eprintln!("extension worker failed");
            std::process::exit(1);
        }
        return;
    }
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

    if let Err(e) = Box::pin(runner::execute(cli)).await {
        eprintln!("error: {}", scorchkit::report::terminal::escape_terminal_text(&e.to_string()));
        std::process::exit(1);
    }
}
