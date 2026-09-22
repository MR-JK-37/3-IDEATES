use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod file_monitor;
use file_monitor::{monitor_paths, scan_file};

#[derive(Parser)]
#[command(author = "CyberShield PoC", version, about = "Linux security engine CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start monitoring given directories (blocking)
    Start {
        #[arg(short, long, value_name = "DIRS")] 
        dirs: Vec<PathBuf>,
    },
    /// Scan a single file and print entropy/indicators
    Scan {
        #[arg(value_name = "FILE")] 
        file: PathBuf,
    }
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Start { dirs } => {
            if dirs.is_empty() {
                eprintln!("Provide at least one directory to monitor")
            } else {
                // If environment variable CYBERSHIELD_SOCKET is set, pass to monitor
                let sock = std::env::var("CYBERSHIELD_SOCKET").ok().map(PathBuf::from);
                monitor_paths(dirs.clone(), sock);
            }
        }
        Commands::Scan { file } => {
            match scan_file(file) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Scan failed: {}", e),
            }
        }
    }
}
