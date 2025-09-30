use clap::{ArgAction, Parser, Subcommand, builder::styling};
use clap_handler::Handler;

use crate::ll;

pub mod download;
pub mod inspect;
pub mod merge;
pub mod update;
pub mod upload;

pub const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold().underline())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

#[derive(Parser, Handler, Clone)]
#[clap(name = "shiori", version = env!("SHIORI_VERSION"), author, styles = STYLES)]
#[clap(about = ll!("shiori-about"))]
pub struct ShioriArgs {
    /// Whether to skip update check
    #[clap(long = "skip-update", action = ArgAction::SetFalse)]
    update_check: bool,

    #[clap(subcommand)]
    command: ShioriCommand,
}

#[derive(Subcommand, Handler, Clone)]
pub enum ShioriCommand {
    #[clap(after_help = inspect::get_default_external_inspector().help())]
    Download(download::DownloadCommand<inspect::InspectorOptions>),
    #[clap(after_help = inspect::get_default_external_inspector().help())]
    Inspect(inspect::InspectCommand),
    Merge(merge::MergeCommand),
    Update(update::UpdateCommand),
    Upload(upload::UploadCommand),
}
