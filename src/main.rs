pub mod cli;
pub mod config;
pub mod crypto;
pub mod diff;
pub mod error;
pub mod export;
pub mod git;
pub mod parser;
pub mod store;
pub mod types;

#[cfg(test)]
mod test_helpers;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
