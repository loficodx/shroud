use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub fn parse() -> Result<ClientCommand> {
    Cli::parse().into_command()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCommand {
    Run {
        config_path: PathBuf,
        log_format: LogFormat,
    },
    Import(ImportOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOptions {
    pub raw: String,
    pub output: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug, Parser)]
#[command(name = "shroud-client")]
struct Cli {
    #[arg(value_name = "config-path")]
    config_path: Option<PathBuf>,

    #[arg(
        short = 'c',
        long = "config",
        value_name = "path",
        conflicts_with = "config_path"
    )]
    config: Option<PathBuf>,

    #[arg(long = "log-format", value_enum, default_value = "plain")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Option<ClientSubcommand>,
}

#[derive(Debug, Subcommand)]
enum ClientSubcommand {
    Import(ImportArgs),
}

#[derive(Debug, clap::Args)]
struct ImportArgs {
    #[arg(value_name = "shrd:1:...")]
    raw: String,

    #[arg(short = 'o', long = "output", value_name = "path")]
    output: Option<PathBuf>,

    #[arg(long = "force")]
    force: bool,
}

impl Cli {
    fn into_command(self) -> Result<ClientCommand> {
        match self.command {
            Some(ClientSubcommand::Import(args)) => Ok(ClientCommand::Import(ImportOptions {
                raw: args.raw,
                output: args.output,
                force: args.force,
            })),
            None => Ok(ClientCommand::Run {
                config_path: self
                    .config
                    .or(self.config_path)
                    .unwrap_or_else(|| PathBuf::from("configs/client.yaml")),
                log_format: self.log_format,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, ClientCommand, ImportOptions, LogFormat};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parse_cli_defaults_to_sample_client_config() {
        let config_path = Cli::try_parse_from(["shroud-client"])
            .expect("parse default config")
            .into_command()
            .expect("build command");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_config_path() {
        let config_path = Cli::try_parse_from(["shroud-client", "custom-client.yaml"])
            .expect("parse custom config")
            .into_command()
            .expect("build command");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: PathBuf::from("custom-client.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_explicit_config_path() {
        let command =
            Cli::try_parse_from(["shroud-client", "--config", "configs/client-laptop.yaml"])
                .expect("parse --config")
                .into_command()
                .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client-laptop.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_rejects_config_flag_with_positional_config_path() {
        let err = Cli::try_parse_from([
            "shroud-client",
            "custom-client.yaml",
            "--config",
            "configs/client-laptop.yaml",
        ])
        .expect_err("reject conflicting config paths");

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parse_cli_accepts_log_format() {
        let command = Cli::try_parse_from([
            "shroud-client",
            "--config",
            "configs/client-laptop.yaml",
            "--log-format",
            "json",
        ])
        .expect("parse --log-format")
        .into_command()
        .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client-laptop.yaml"),
                log_format: LogFormat::Json,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_import_command() {
        let command = Cli::try_parse_from([
            "shroud-client",
            "import",
            "shrd:1:test",
            "--output",
            "configs/client-laptop.yaml",
            "--force",
        ])
        .expect("parse import command")
        .into_command()
        .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Import(ImportOptions {
                raw: "shrd:1:test".to_string(),
                output: Some(PathBuf::from("configs/client-laptop.yaml")),
                force: true,
            })
        );
    }
}
