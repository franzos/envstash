use clap::CommandFactory;

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
    clap_complete::CompleteEnv::with_factory(cli::Cli::command).complete();

    if let Err(e) = cli::run() {
        if let error::Error::ExitCode(code) = e {
            std::process::exit(code);
        }
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
