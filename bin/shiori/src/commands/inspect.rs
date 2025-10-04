use crate::inspect::{
    PluginManager,
    inspectors::{DashPlugin, HlsPlugin, ShortLinkPlugin},
};
use clap::Parser;
use clap_handler::handler;
use iori_gigafile::GigafilePlugin;
use iori_nicolive::inspect::NicoPlugin;
use iori_showroom::inspect::ShowroomPlugin;
use shiori_plugin::{InspectorArguments, InspectorCommand};

#[derive(Parser, Clone, Default)]
#[clap(name = "inspect", short_flag = 'S')]
pub struct InspectCommand {
    #[clap(short, long)]
    wait: bool,

    #[clap(flatten)]
    inspector_options: InspectorOptions,

    url: String,
}

pub(crate) fn get_default_external_inspector() -> PluginManager {
    let mut inspector = PluginManager::new();
    inspector
        .add(ShortLinkPlugin)
        .add(ShowroomPlugin)
        .add(NicoPlugin)
        .add(GigafilePlugin)
        .add(HlsPlugin)
        .add(DashPlugin);

    inspector
}

#[handler(InspectCommand)]
async fn handle_inspect(this: InspectCommand) -> anyhow::Result<()> {
    let (matched_inspector, data) = get_default_external_inspector()
        .wait(this.wait)
        .inspect(&this.url, &this.inspector_options, |c| {
            c.into_iter().next().unwrap()
        })
        .await?;

    eprintln!("{matched_inspector}: {data:?}");

    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct InspectorOptions {
    arg_matches: clap::ArgMatches,
}

impl InspectorOptions {
    pub fn new(arg_matches: clap::ArgMatches) -> Self {
        Self { arg_matches }
    }
}

impl InspectorArguments for InspectorOptions {
    fn get_string(&self, argument: &'static str) -> Option<String> {
        self.arg_matches.get_one::<String>(argument).cloned()
    }

    fn get_boolean(&self, argument: &'static str) -> bool {
        self.arg_matches
            .get_one::<bool>(argument)
            .copied()
            .unwrap_or(false)
    }
}

impl clap::FromArgMatches for InspectorOptions {
    fn from_arg_matches(arg_matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        Ok(Self::new(arg_matches.clone()))
    }

    fn from_arg_matches_mut(arg_matches: &mut clap::ArgMatches) -> Result<Self, clap::Error> {
        Ok(Self::new(arg_matches.clone()))
    }

    fn update_from_arg_matches(
        &mut self,
        arg_matches: &clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut arg_matches.clone())
    }

    fn update_from_arg_matches_mut(
        &mut self,
        arg_matches: &mut clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        self.arg_matches = arg_matches.clone();
        Result::Ok(())
    }
}

impl clap::Args for InspectorOptions {
    fn group_id() -> Option<clap::Id> {
        Some(clap::Id::from("InspectorOptions"))
    }

    fn augment_args<'b>(command: clap::Command) -> clap::Command {
        InspectorOptions::augment_args_for_update(command)
    }

    fn augment_args_for_update<'b>(command: clap::Command) -> clap::Command {
        let inspectors = get_default_external_inspector();
        let mut wrapper = InspectorCommandWrapper::new(command);
        inspectors.add_arguments(&mut wrapper);

        wrapper.into_inner()
    }
}

struct InspectorCommandWrapper(Option<clap::Command>);

impl InspectorCommandWrapper {
    fn new(command: clap::Command) -> Self {
        Self(Some(command))
    }

    fn into_inner(self) -> clap::Command {
        self.0.unwrap()
    }
}

impl InspectorCommand for InspectorCommandWrapper {
    fn add_argument(
        &mut self,
        long: &'static str,
        value_name: Option<&'static str>,
        help: &'static str,
    ) {
        let command = self.0.take().unwrap();
        self.0 = Some(
            command.arg(
                clap::Arg::new(long)
                    .value_name(value_name.unwrap_or(long))
                    .value_parser(clap::value_parser!(String))
                    .action(clap::ArgAction::Set)
                    .long(long)
                    .help(help),
            ),
        );
    }

    fn add_boolean_argument(&mut self, long: &'static str, help: &'static str) {
        let command = self.0.take().unwrap();
        self.0 = Some(
            command.arg(
                clap::Arg::new(long)
                    .value_parser(clap::value_parser!(bool))
                    .action(clap::ArgAction::SetTrue)
                    .long(long)
                    .help(help),
            ),
        );
    }
}
