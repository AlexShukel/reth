//! Main node command for launching a node

use clap::{value_parser, Arg, Args, CommandFactory, FromArgMatches, Parser};
use grandine_runtime::{run, GrandineArgs};
use reth_chainspec::{ChainKind, EthChainSpec, EthereumHardforks, NamedChain};
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_runner::CliContext;
use reth_cli_util::parse_socket_address;
use reth_db::{init_db, DatabaseEnv};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_node_core::{
    args::{
        DatabaseArgs, DatadirArgs, DebugArgs, DevArgs, NetworkArgs, PayloadBuilderArgs,
        PruningArgs, RpcServerArgs, TxPoolArgs,
    },
    node_config::NodeConfig,
    version,
};
use std::{ffi::OsStr, path::PathBuf, sync::Arc};
use std::{ffi::OsString, fmt, future::Future, net::SocketAddr};
use tokio::task::spawn_blocking;

#[derive(Debug, Clone)]
pub struct RethGrandineArgs(GrandineArgs);

impl FromArgMatches for RethGrandineArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> std::result::Result<Self, clap::Error> {
        let mut args = vec!["".to_string()];

        let command = GrandineArgs::command();
        // let cmd_args = command
        //     .get_arguments()
        //     .map(|v| (v.get_id().clone(), v.clone()))
        //     .collect::<HashMap<_, _>>();

        for id in matches.ids() {
            if id.as_str().starts_with("grandine.") {
                // let old_id: String = id.as_str().chars().skip(9).collect();
                // let old_flag = format!("--{old_id}");

                // let Some(arg) = cmd_args.get(old_id.as_str()) else {
                //     continue;
                // };

                // match arg.get_action() {
                //     clap::ArgAction::SetTrue => {
                //         if matches.get_flag(id) {
                //             args.push(old_flag);
                //         }
                //     },
                //     clap::ArgAction::SetFalse => {
                //         if !matches.get_flag(id) {
                //             args.push(old_flag);
                //         }
                //     },
                //     _ => {}
                // }

                if let Some(occurences) = matches.get_raw_occurrences(id.as_str()) {
                    let vec_occurences = occurences.collect::<Vec<_>>();

                    // Skip the option if the only occurence value is "false"
                    if vec_occurences.len() == 1 {
                        if let Some(first_occurence) = vec_occurences.get(0) {
                            let vec_first_occurence = first_occurence.clone().collect::<Vec<_>>();
                            if let Some(value) = vec_first_occurence.get(0) {
                                if value.to_string_lossy().to_string() == "false" {
                                    continue;
                                }
                            }
                        }
                    }

                    let new_id = format!("--{}", id.as_str().chars().skip(9).collect::<String>());
                    args.push(new_id.replace('_', "-"));

                    for occurence in vec_occurences {
                        for value in occurence {
                            let arg_value = value.to_string_lossy().to_string();
                            if arg_value != "true" {
                                args.push(arg_value);
                            }
                        }
                    }
                }
            }
        }

        println!("me: {:?}", args);

        GrandineArgs::from_arg_matches(&command.get_matches_from(args)).map(RethGrandineArgs)
    }

    fn update_from_arg_matches(
        &mut self,
        matches: &clap::ArgMatches,
    ) -> std::result::Result<(), clap::Error> {
        self.0.update_from_arg_matches(matches)
    }
}

impl Args for RethGrandineArgs {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        Self::augment_args_for_update(cmd)
    }

    fn augment_args_for_update(mut cmd: clap::Command) -> clap::Command {
        let command = GrandineArgs::command();

        for arg in command.get_arguments() {
            if arg.get_id() == "network" {
                continue;
            }

            let id: &'static str = Box::leak(format!("grandine.{}", arg.get_id()).into_boxed_str());

            let mut new_arg = Arg::new(id).action(arg.get_action().clone());

            if let Some(help) = arg.get_help() {
                new_arg = new_arg.help(help.clone());
            }

            if let Some(value_names) = arg.get_value_names() {
                new_arg = new_arg.value_names(value_names);
            }

            if let Some(value_delimiter) = arg.get_value_delimiter() {
                new_arg = new_arg.value_delimiter(value_delimiter);
            }

            if let Some(env) = arg.get_env() {
                let alias_name: &'static OsStr = Box::leak(env.to_owned().into_boxed_os_str());

                new_arg = new_arg.env(alias_name);
            }

            if let Some(aliases) = arg.get_long_and_visible_aliases() {
                for alias in aliases {
                    let alias_name: &'static str =
                        Box::leak(format!("grandine.{alias}").into_boxed_str());
                    new_arg = new_arg.long(alias_name);
                }
            }

            cmd = cmd.arg(new_arg);
        }

        cmd
    }
}

/// Start the node
#[derive(Debug, Parser)]
pub struct NodeCommand<
    C: ChainSpecParser = EthereumChainSpecParser,
    Ext: clap::Args + fmt::Debug = NoArgs,
> {
    /// The path to the configuration file to use.
    #[arg(long, value_name = "FILE", verbatim_doc_comment)]
    pub config: Option<PathBuf>,

    /// The chain this node is running.
    ///
    /// Possible values are either a built-in chain or the path to a chain specification file.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        long_help = C::help_message(),
        default_value = C::SUPPORTED_CHAINS[0],
        default_value_if("dev", "true", "dev"),
        value_parser = C::parser(),
        required = false,
    )]
    pub chain: Arc<C::ChainSpec>,

    /// Enable Prometheus metrics.
    ///
    /// The metrics will be served at the given interface and port.
    #[arg(long, value_name = "SOCKET", value_parser = parse_socket_address, help_heading = "Metrics")]
    pub metrics: Option<SocketAddr>,

    /// Add a new instance of a node.
    ///
    /// Configures the ports of the node to avoid conflicts with the defaults.
    /// This is useful for running multiple nodes on the same machine.
    ///
    /// Max number of instances is 200. It is chosen in a way so that it's not possible to have
    /// port numbers that conflict with each other.
    ///
    /// Changes to the following port numbers:
    /// - `DISCOVERY_PORT`: default + `instance` - 1
    /// - `AUTH_PORT`: default + `instance` * 100 - 100
    /// - `HTTP_RPC_PORT`: default - `instance` + 1
    /// - `WS_RPC_PORT`: default + `instance` * 2 - 2
    #[arg(long, value_name = "INSTANCE", global = true, default_value_t = 1, value_parser = value_parser!(u16).range(..=200))]
    pub instance: u16,

    /// Sets all ports to unused, allowing the OS to choose random unused ports when sockets are
    /// bound.
    ///
    /// Mutually exclusive with `--instance`.
    #[arg(long, conflicts_with = "instance", global = true)]
    pub with_unused_ports: bool,

    /// Runs grandine CL together with reth
    #[arg(long)]
    pub grandine: bool,

    /// All datadir related arguments
    #[command(flatten)]
    pub datadir: DatadirArgs,

    /// All networking related arguments
    #[command(flatten)]
    pub network: NetworkArgs,

    /// All rpc related arguments
    #[command(flatten)]
    pub rpc: RpcServerArgs,

    /// All txpool related arguments with --txpool prefix
    #[command(flatten)]
    pub txpool: TxPoolArgs,

    /// All payload builder related arguments
    #[command(flatten)]
    pub builder: PayloadBuilderArgs,

    /// All debug related arguments with --debug prefix
    #[command(flatten)]
    pub debug: DebugArgs,

    /// All database related arguments
    #[command(flatten)]
    pub db: DatabaseArgs,

    /// All dev related arguments with --dev prefix
    #[command(flatten)]
    pub dev: DevArgs,

    /// All pruning related arguments
    #[command(flatten)]
    pub pruning: PruningArgs,

    /// Additional cli arguments
    #[command(flatten, next_help_heading = "Extension")]
    pub ext: Ext,

    /// Grandine cli arguments
    #[command(flatten, next_help_heading = "Grandine")]
    pub grandine_args: RethGrandineArgs,
}

impl<C: ChainSpecParser> NodeCommand<C> {
    /// Parsers only the default CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parsers only the default [`NodeCommand`] arguments from the given iterator
    pub fn try_parse_args_from<I, T>(itr: I) -> Result<Self, clap::error::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        Self::try_parse_from(itr)
    }
}

impl<
        C: ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>,
        Ext: clap::Args + fmt::Debug,
    > NodeCommand<C, Ext>
{
    /// Launches the node
    ///
    /// This transforms the node command into a node config and launches the node using the given
    /// closure.
    pub async fn execute<L, Fut>(self, ctx: CliContext, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        tracing::info!(target: "reth::cli", version = ?version::SHORT_VERSION, "Starting reth");

        let Self {
            datadir,
            config,
            chain,
            metrics,
            instance,
            with_unused_ports,
            network,
            rpc,
            txpool,
            builder,
            debug,
            db,
            dev,
            pruning,
            ext,
            grandine,
            mut grandine_args,
        } = self;

        // set up node config
        let mut node_config = NodeConfig {
            datadir,
            config,
            chain,
            metrics,
            instance,
            network,
            rpc,
            txpool,
            builder,
            debug,
            db,
            dev,
            pruning,
        };

        let data_dir = node_config.datadir();
        let db_path = data_dir.db();

        tracing::info!(target: "reth::cli", path = ?db_path, "Opening database");
        let database = Arc::new(init_db(db_path.clone(), self.db.database_args())?.with_metrics());

        if with_unused_ports {
            node_config = node_config.with_unused_ports();
        }

        if grandine {
            let converted_network = match node_config.chain.chain().kind() {
                ChainKind::Named(v) => match v {
                    NamedChain::Mainnet => grandine_runtime::Network::Mainnet,
                    NamedChain::Goerli => grandine_runtime::Network::Goerli,
                    NamedChain::Sepolia => grandine_runtime::Network::Sepolia,
                    NamedChain::Holesky => grandine_runtime::Network::Holesky,
                    _ => eyre::bail!(format!("Chain {} is not supported in grandine", v)),
                },
                ChainKind::Id(id) => {
                    eyre::bail!(format!("Chain id {} is not supported in grandine", id))
                }
            };

            grandine_args.0.chain_options.network = converted_network;
            let grandine_config =
                grandine_args.0.try_into_config().or_else(|e| eyre::bail!("{}", e))?;

            spawn_blocking(move || {
                run(grandine_config).unwrap();
            });
        }

        let builder = NodeBuilder::new(node_config)
            .with_database(database)
            .with_launch_context(ctx.task_executor);

        launcher(builder, ext).await
    }
}

/// No Additional arguments
#[derive(Debug, Clone, Copy, Default, Args)]
#[non_exhaustive]
pub struct NoArgs;

#[cfg(test)]
mod tests {
    use super::*;
    use reth_discv4::DEFAULT_DISCOVERY_PORT;
    use reth_ethereum_cli::chainspec::SUPPORTED_CHAINS;
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::Path,
    };

    #[test]
    fn parse_help_node_command() {
        let err = NodeCommand::<EthereumChainSpecParser>::try_parse_args_from(["reth", "--help"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parse_common_node_command_chain_args() {
        for chain in SUPPORTED_CHAINS {
            let args: NodeCommand = NodeCommand::parse_from(["reth", "--chain", chain]);
            assert_eq!(args.chain.chain, chain.parse::<reth_chainspec::Chain>().unwrap());
        }
    }

    #[test]
    fn parse_discovery_addr() {
        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--discovery.addr", "127.0.0.1"]).unwrap();
        assert_eq!(cmd.network.discovery.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn parse_addr() {
        let cmd: NodeCommand = NodeCommand::try_parse_args_from([
            "reth",
            "--discovery.addr",
            "127.0.0.1",
            "--addr",
            "127.0.0.1",
        ])
        .unwrap();
        assert_eq!(cmd.network.discovery.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(cmd.network.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn parse_discovery_port() {
        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--discovery.port", "300"]).unwrap();
        assert_eq!(cmd.network.discovery.port, 300);
    }

    #[test]
    fn parse_port() {
        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--discovery.port", "300", "--port", "99"])
                .unwrap();
        assert_eq!(cmd.network.discovery.port, 300);
        assert_eq!(cmd.network.port, 99);
    }

    #[test]
    fn parse_metrics_port() {
        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--metrics", "9001"]).unwrap();
        assert_eq!(cmd.metrics, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001)));

        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--metrics", ":9001"]).unwrap();
        assert_eq!(cmd.metrics, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001)));

        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--metrics", "localhost:9001"]).unwrap();
        assert_eq!(cmd.metrics, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001)));
    }

    #[test]
    fn parse_config_path() {
        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--config", "my/path/to/reth.toml"]).unwrap();
        // always store reth.toml in the data dir, not the chain specific data dir
        let data_dir = cmd.datadir.resolve_datadir(cmd.chain.chain);
        let config_path = cmd.config.unwrap_or_else(|| data_dir.config());
        assert_eq!(config_path, Path::new("my/path/to/reth.toml"));

        let cmd: NodeCommand = NodeCommand::try_parse_args_from(["reth"]).unwrap();

        // always store reth.toml in the data dir, not the chain specific data dir
        let data_dir = cmd.datadir.resolve_datadir(cmd.chain.chain);
        let config_path = cmd.config.clone().unwrap_or_else(|| data_dir.config());
        let end = format!("{}/reth.toml", SUPPORTED_CHAINS[0]);
        assert!(config_path.ends_with(end), "{:?}", cmd.config);
    }

    #[test]
    fn parse_db_path() {
        let cmd: NodeCommand = NodeCommand::try_parse_args_from(["reth"]).unwrap();
        let data_dir = cmd.datadir.resolve_datadir(cmd.chain.chain);

        let db_path = data_dir.db();
        let end = format!("reth/{}/db", SUPPORTED_CHAINS[0]);
        assert!(db_path.ends_with(end), "{:?}", cmd.config);

        let cmd: NodeCommand =
            NodeCommand::try_parse_args_from(["reth", "--datadir", "my/custom/path"]).unwrap();
        let data_dir = cmd.datadir.resolve_datadir(cmd.chain.chain);

        let db_path = data_dir.db();
        assert_eq!(db_path, Path::new("my/custom/path/db"));
    }

    #[test]
    fn parse_instance() {
        let mut cmd: NodeCommand = NodeCommand::parse_from(["reth"]);
        cmd.rpc.adjust_instance_ports(cmd.instance);
        cmd.network.port = DEFAULT_DISCOVERY_PORT + cmd.instance - 1;
        // check rpc port numbers
        assert_eq!(cmd.rpc.auth_port, 8551);
        assert_eq!(cmd.rpc.http_port, 8545);
        assert_eq!(cmd.rpc.ws_port, 8546);
        // check network listening port number
        assert_eq!(cmd.network.port, 30303);

        let mut cmd: NodeCommand = NodeCommand::parse_from(["reth", "--instance", "2"]);
        cmd.rpc.adjust_instance_ports(cmd.instance);
        cmd.network.port = DEFAULT_DISCOVERY_PORT + cmd.instance - 1;
        // check rpc port numbers
        assert_eq!(cmd.rpc.auth_port, 8651);
        assert_eq!(cmd.rpc.http_port, 8544);
        assert_eq!(cmd.rpc.ws_port, 8548);
        // check network listening port number
        assert_eq!(cmd.network.port, 30304);

        let mut cmd: NodeCommand = NodeCommand::parse_from(["reth", "--instance", "3"]);
        cmd.rpc.adjust_instance_ports(cmd.instance);
        cmd.network.port = DEFAULT_DISCOVERY_PORT + cmd.instance - 1;
        // check rpc port numbers
        assert_eq!(cmd.rpc.auth_port, 8751);
        assert_eq!(cmd.rpc.http_port, 8543);
        assert_eq!(cmd.rpc.ws_port, 8550);
        // check network listening port number
        assert_eq!(cmd.network.port, 30305);
    }

    #[test]
    fn parse_with_unused_ports() {
        let cmd: NodeCommand = NodeCommand::parse_from(["reth", "--with-unused-ports"]);
        assert!(cmd.with_unused_ports);
    }

    #[test]
    fn with_unused_ports_conflicts_with_instance() {
        let err = NodeCommand::<EthereumChainSpecParser>::try_parse_args_from([
            "reth",
            "--with-unused-ports",
            "--instance",
            "2",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn with_unused_ports_check_zero() {
        let mut cmd: NodeCommand = NodeCommand::parse_from(["reth"]);
        cmd.rpc = cmd.rpc.with_unused_ports();
        cmd.network = cmd.network.with_unused_ports();

        // make sure the rpc ports are zero
        assert_eq!(cmd.rpc.auth_port, 0);
        assert_eq!(cmd.rpc.http_port, 0);
        assert_eq!(cmd.rpc.ws_port, 0);

        // make sure the network ports are zero
        assert_eq!(cmd.network.port, 0);
        assert_eq!(cmd.network.discovery.port, 0);

        // make sure the ipc path is not the default
        assert_ne!(cmd.rpc.ipcpath, String::from("/tmp/reth.ipc"));
    }
}
