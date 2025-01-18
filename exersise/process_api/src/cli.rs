use anyhow::Result;
use clap::{Arg, ArgMatches, Command as ClapCommand};
use process_api_service::{
    process_api_service_client::ProcessApiServiceClient, ProcessId, StartCommand,
};
use std::{env, str::FromStr};
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
    Request,
};

pub mod process_api_service {
    tonic::include_proto!("process_api_service");
}

fn get_arg_matches() -> clap::ArgMatches {
    let matches: clap::ArgMatches = ClapCommand::new("excersise_cli")
        .version("1.0")
        .author("Author Name <derekdshaw@protonmail.com>")
        .about("Connects to a gRPC to execute a set of commands")
        .subcommand(
            ClapCommand::new("start").about("Starts a process").arg(
                Arg::new("command")
                    .short('c')
                    .help("The command to start the process")
                    .required(true),
            ),
        )
        .subcommand(
            ClapCommand::new("output")
                .about("Gets the output of a process")
                .arg(
                    Arg::new("process_id")
                        .short('p')
                        .help("The ID of the process")
                        .required(true),
                ),
        )
        .subcommand(
            ClapCommand::new("stop")
                .about("Stops the specified process.")
                .arg(
                    Arg::new("process_id")
                        .short('p')
                        .help("The ID of the process")
                        .required(true),
                ),
        )
        .subcommand(
            ClapCommand::new("status")
                .about("Get the status of the  specified process.")
                .arg(
                    Arg::new("process_id")
                        .short('p')
                        .help("The ID of the process")
                        .required(true),
                ),
        )
        .subcommand(
            ClapCommand::new("list") // could be logs?
                .about("Get the list of active processes"),
        )
        .get_matches();

    matches
}

fn get_tls_config() -> Result<ClientTlsConfig, Box<dyn std::error::Error>> {
    let root_exe_path = std::env::current_exe()?;

    // for now these paths are relative to the build exe.
    let server_root_ca_pem =
        std::fs::read_to_string(root_exe_path.join("../../../data/tls/ca.crt"))?;
    let server_root_ca_cert = Certificate::from_pem(server_root_ca_pem);

    // The client cert can be changed to allow for different authorization Roles to be applied.
    // For now this is hard coded. It could be exposed through a config or as a path on the command line.
    let client_cert =
        std::fs::read_to_string(root_exe_path.join("../../../data/tls/executor_client_cert.pem"))?;
    let client_key =
        std::fs::read_to_string(root_exe_path.join("../../../data/tls/client_key.pem"))?;
    let client_identity = Identity::from_pem(client_cert, client_key);

    let tls = ClientTlsConfig::new()
        .ca_certificate(server_root_ca_cert)
        .domain_name("localhost")
        .identity(client_identity);

    Ok(tls)
}

type LimitsResult = Result<(Option<u32>, Option<u64>, Option<u64>), tonic::Status>;

// Optional values for resource limits. If not set, the system defaults are used.
// Option value types are basesd off of protobuf base types.
fn get_limits_from_env() -> LimitsResult {
    let mut cpu_limit = None;
    let mut memory_limit = None;
    let mut io_limit = None;

    match env::var("PM_PROCESS_CPU_LIMIT") {
        Ok(value) => match value.parse::<u32>() {
            Ok(cpu_limit_value) => {
                cpu_limit = Some(cpu_limit_value);
            }
            Err(_) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "Invalid value for PM_PROCESS_CPU_LIMIT: {}",
                    value
                )));
            }
        },
        Err(_) => {
            // no value set, this is fine.
        }
    }

    match env::var("PM_PROCESS_MEMORY_LIMIT") {
        Ok(value) => match value.parse::<u64>() {
            Ok(memory_limit_value) => {
                memory_limit = Some(memory_limit_value);
            }
            Err(_) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "Invalid value for PM_PROCESS_MEMORY_LIMIT: {}",
                    value
                )));
            }
        },
        Err(_) => {
            // no value set, this is fine.
        }
    }

    match env::var("PM_PROCESS_IO_LIMIT") {
        Ok(value) => match value.parse::<u64>() {
            Ok(io_limit_value) => {
                io_limit = Some(io_limit_value);
            }
            Err(_) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "Invalid value for PM_PROCESS_IO_LIMIT: {}",
                    value
                )));
            }
        },
        Err(_) => {
            // no value set, this is fine.
        }
    }

    Ok((cpu_limit, memory_limit, io_limit))
}

/// This will start a process with the given command_line. The CPU, Memory
/// and I/O limits are retrieved from the environment variables
/// PM_PROCESS_CPU_LIMIT: a number from 1-100 as a percentage of CPU
/// PM_PROCESS_MEMORY_LIMIT: a value representing the max memory usage in bytes.
/// PM_PROCESS_IO_LIMIT: a value in bytes representing bytes/second throughput
/// If not specified detaults to max system values.
async fn run_start_command(
    client: &mut ProcessApiServiceClient<Channel>,
    command: &str,
) -> Result<(), tonic::Status> {
    // For now pull these from environment variables. However we could plumb these through the command line as optional arguments.
    let (cpu_limit, memory_limit, io_limit) = get_limits_from_env()?;

    let resp = client
        .start(StartCommand {
            command: command.to_string(),
            cpu_limit,
            memory_limit,
            io_limit,
        })
        .await?;

    match &resp.get_ref().process_id {
        Some(process_id) => {
            println!("Started process Id: {}", process_id.id);
        }
        None => {
            println!("No process id returned from start command");
        }
    }

    Ok(())
}

async fn run_stop_command(
    client: &mut ProcessApiServiceClient<Channel>,
    process_id: u64,
) -> Result<(), tonic::Status> {
    let resp = client.stop(ProcessId { id: process_id }).await?;

    let is_stopped = resp.get_ref().process_stopped;
    if is_stopped {
        println!("Process stopped.");
    } else {
        println!("Unable to stop process.");
    }

    Ok(())
}

async fn run_status_command(
    client: &mut ProcessApiServiceClient<Channel>,
    process_id: u64,
) -> Result<(), tonic::Status> {
    let resp = client.status(ProcessId { id: process_id }).await?;

    let status = &resp.get_ref().status;

    println!("Process status: {}", status);

    Ok(())
}

async fn run_list_command(
    client: &mut ProcessApiServiceClient<Channel>,
) -> Result<(), tonic::Status> {
    let resp = client.list(()).await?;

    let processs_ids = &resp.get_ref().processes;
    if processs_ids.is_empty() {
        println!("No processes running.");
    } else {
        for process_id in processs_ids {
            println!("Process Id: {}", process_id);
        }
    }

    Ok(())
}

async fn run_output_command(
    client: &mut ProcessApiServiceClient<Channel>,
    process_id: u64,
) -> Result<(), tonic::Status> {
    let request = Request::new(ProcessId { id: process_id });
    let mut stream = client.output(request).await?.into_inner();

    // loop continuously reads from the stream for now
    loop {
        let output_message = stream.message().await;
        match output_message {
            Ok(msg) => {
                if let Some(msg) = msg {
                    if !msg.stdout.is_empty() {
                        println!("Received: {}", msg.stdout);
                    } else {
                        print!(".");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
    // stream is dropped here and the disconnect info is sent to server
    Ok(())
}

fn get_process_id(args: &ArgMatches) -> u64 {
    let process_id_string = args.get_one::<String>("process_id").expect("required");
    let process_id =
        u64::from_str(process_id_string.as_str()).expect("process_id must be a number");
    process_id
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = get_arg_matches();

    let tls = get_tls_config()?;

    let channel = Channel::from_static("https://[::1]:50051")
        .tls_config(tls)?
        .connect()
        .await?;

    let mut client = ProcessApiServiceClient::new(channel);

    match matches.subcommand() {
        Some(("start", sub_m)) => {
            let command = sub_m.get_one::<String>("command").expect("required");
            run_start_command(&mut client, command).await?;
        }
        Some(("stop", sub_m)) => {
            let process_id = get_process_id(sub_m);
            run_stop_command(&mut client, process_id).await?;
        }
        Some(("output", sub_m)) => {
            let process_id = get_process_id(sub_m);
            run_output_command(&mut client, process_id).await?;
        }
        Some(("status", sub_m)) => {
            let process_id = get_process_id(sub_m);
            run_status_command(&mut client, process_id).await?;
        }
        Some(("list", _)) => {
            run_list_command(&mut client).await?;
        }
        _ => eprintln!("Unknown subcommand"),
    }

    Ok(())
}

#[cfg(test)]

mod tests {
    use super::*;
    use process_api_service::process_api_service_server::{
        ProcessApiService, ProcessApiServiceServer,
    };
    use process_api_service::{Command, ProcessId, StartedProcess};
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::Sender;
    use tonic::transport::{Endpoint, Server};
    use tonic::{Request, Response, Status};

    struct MockProcessApiService {
        sender: Sender<StartedProcess>,
    }

    #[tonic::async_trait]
    impl ProcessApiService for MockProcessApiService {
        async fn start(
            &self,
            request: Request<Command>,
        ) -> Result<Response<StartedProcess>, Status> {
            let process_id = StartedProcess {
                process_id: Some(ProcessId { id: 1 }),
            };
            self.sender.send(process_id.clone()).await.unwrap();
            Ok(Response::new(process_id))
        }

        async fn output(
            &self,
            _request: Request<ProcessId>,
        ) -> Result<Response<process_api_service::OutputStream>, Status> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_start_command() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, _rx) = mpsc::channel(1);

        let mock_service = MockProcessApiService { sender: tx };
        let addr = "[::1]:50051".parse().unwrap();
        let server = Server::builder()
            .add_service(ProcessApiServiceServer::new(mock_service))
            .serve(addr);

        tokio::spawn(server);

        let channel = Endpoint::from_static("http://[::1]:50051")
            .connect()
            .await?;

        let mut client = ProcessApiServiceClient::new(channel);

        let request = Request::new(Command {
            command: "do stuff".into(),
        });

        let response = client.start(request).await?;

        assert_eq!(response.get_ref().process_id.as_ref().unwrap().id, 1);

        Ok(())
    }
}
