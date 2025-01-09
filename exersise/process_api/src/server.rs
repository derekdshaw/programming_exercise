use anyhow::Result;
use openssl::ssl::{SslAcceptor, SslFiletype, SslRef};
use openssl::x509::{X509ReqRef, X509};
use process_api_service::process_api_service_server::{ProcessApiService, ProcessApiServiceServer};
use process_api_service::{
    OutputStreamResponse, ProcessId, ProcessList, ProcessStatus, StartCommand, StartedProcess,
    StoppedProcess,
};
use process_pool::process_pool_manager::ProcessPoolManager;
use std::borrow::BorrowMut;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, Mutex}; // Must use tokio::sync::Mutex, not std::sync::Mutex because it supports Send and can be moved into a thread.
use tokio_openssl::SslStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::Interceptor;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use x509_parser::extensions::ParsedExtension;
use x509_parser::extensions::{PolicyInformation, PolicyQualifierInfo};
use x509_parser::prelude::*;

pub mod process_api_service {
    tonic::include_proto!("process_api_service"); // The string specified here must match the proto package name
}

/// Used to set a Role in the request after parsing the client cert.
#[derive(Debug, Clone, PartialEq)]
pub struct Role(String);

impl PartialEq<str> for Role {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Role {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[derive(Debug, PartialEq)]
pub enum Roles {
    Executor,
    Reader,
}

impl PartialEq<str> for Roles {
    fn eq(&self, other: &str) -> bool {
        match self {
            Roles::Executor => other == "Executor",
            Roles::Reader => other == "Reader",
        }
    }
}

#[derive(Default)]
pub struct ProcessApiServiceImpl {
    process_pool: Arc<Mutex<ProcessPoolManager>>,
}

impl ProcessApiServiceImpl {
    /// # Safety
    /// This function is unsafe because it creates a new instance of ProcessPoolManager
    pub unsafe fn new() -> Self {
        ProcessApiServiceImpl {
            process_pool: Arc::new(Mutex::new(ProcessPoolManager::new())),
        }
    }
}

#[tonic::async_trait]
impl ProcessApiService for ProcessApiServiceImpl {
    async fn start(
        &self,
        request: Request<StartCommand>,
    ) -> Result<Response<StartedProcess>, Status> {
        if can_run_command(&request, Roles::Executor) {
            let command = request.into_inner();
            let cmd_str = command.command.clone();
            let cpu_limit = command.cpu_limit;
            let memory_limit = command.memory_limit;
            let io_limit = command.io_limit;

            if cmd_str.is_empty() {
                return Err(Status::invalid_argument("Command cannot be empty"));
            }

            let mut pp_locked = self.process_pool.lock().await;
            match pp_locked.start_process(&cmd_str, cpu_limit, memory_limit, io_limit) {
                Ok(process_id) => {
                    let started_process = StartedProcess {
                        process_id: Some(ProcessId { id: process_id }),
                    };
                    Ok(Response::new(started_process))
                }
                Err(e) => Err(Status::internal(e.to_string())),
            }
        } else {
            Err(Status::unauthenticated(
                "Unauthorized: Incorrect role for command",
            ))
        }
    }

    async fn stop(&self, request: Request<ProcessId>) -> Result<Response<StoppedProcess>, Status> {
        if can_run_command(&request, Roles::Executor) {
            let process_id = request.into_inner().id;

            println!("Stopping process ID: {}", process_id);

            let mut pp_locked = self.process_pool.lock().await;
            match pp_locked.stop_process(process_id) {
                Ok(is_process_stopped) => {
                    let stopped_process = StoppedProcess {
                        process_stopped: is_process_stopped,
                    };

                    println!("Process stopped: {}", is_process_stopped);
                    Ok(Response::new(stopped_process))
                }
                Err(e) => {
                    return Err(Status::internal(e.to_string()));
                }
            }
        } else {
            Err(Status::unauthenticated(
                "Unauthorized: Incorrect role for command",
            ))
        }
    }

    async fn list(&self, request: Request<()>) -> Result<Response<ProcessList>, Status> {
        if can_run_command(&request, Roles::Reader) {
            let pp_locked = self.process_pool.lock().await;
            let process_list = pp_locked.list_process_ids();
            Ok(Response::new(ProcessList {
                processes: process_list,
            }))
        } else {
            Err(Status::unauthenticated(
                "Unauthorized: Incorrect role for command",
            ))
        }
    }

    async fn status(&self, request: Request<ProcessId>) -> Result<Response<ProcessStatus>, Status> {
        if can_run_command(&request, Roles::Reader) {
            let process_id = request.into_inner().id;

            let pp_locked = self.process_pool.lock().await;
            match pp_locked.query_process_status(process_id) {
                Ok(status) => {
                    let process_status = ProcessStatus {
                        status: status.to_string(),
                    };

                    Ok(Response::new(process_status))
                }
                Err(e) => Err(Status::internal(e.to_string())),
            }
        } else {
            Err(Status::unauthenticated(
                "Unauthorized: Incorrect role for command",
            ))
        }
    }

    type OutputStream = ReceiverStream<Result<OutputStreamResponse, Status>>;

    async fn output(
        &self,
        request: Request<ProcessId>,
    ) -> Result<Response<Self::OutputStream>, Status> {
        if can_run_command(&request, Roles::Reader) {
            let pp = Arc::clone(&self.process_pool);
            let process_id = request.into_inner().id;
            let (tx, rx) = mpsc::channel(4);
            let mut interval = tokio::time::interval(Duration::from_millis(1000));
            let mut output_start = 0;

            // Spawn the task to generate the response to the client. We get the entire output
            // from the library and send only the new output to the client.
            tokio::spawn(async move {
                loop {
                    let mut pp_locked = pp.lock().await;
                    match pp_locked.get_process_output(process_id) {
                        Ok(output_string) => {
                            interval.tick().await;

                            if tx
                                .send(Ok(OutputStreamResponse {
                                    stdout: output_string[output_start..].to_string(),
                                }))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            output_start = output_string.len();
                        }
                        Err(e) => {
                            eprintln!("Failed to read from stdout pipe: {}", e);
                            break;
                        }
                    }
                }
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        } else {
            Err(Status::unauthenticated(
                "Unauthorized: Incorrect role for command",
            ))
        }
    }
}

fn can_run_command<T>(request: &Request<T>, requested_access: Roles) -> bool {
    if let Some(role) = request.extensions().get::<Role>() {
        if requested_access == Roles::Reader {
            if role == "Executor" || role == "Reader" {
                return true;
            }
        } else if requested_access == Roles::Executor {
            if role == "Executor" {
                return true;
            }
        }
    }

    false
}

fn get_tls_config() -> Result<ServerTlsConfig, Box<dyn std::error::Error>> {
    let root_exe_path = std::env::current_exe()?;

    let cert = std::fs::read_to_string(root_exe_path.join("../../../data/tls/server_cert.pem"))?;
    let key = std::fs::read_to_string(root_exe_path.join("../../../data/tls/server_key.pem"))?;
    let server_identity = Identity::from_pem(cert, key);

    let ca = std::fs::read_to_string(root_exe_path.join("../../../data/tls/ca.crt"))?;
    let client_ca_cert = Certificate::from_pem(ca);

    let tls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    Ok(tls)
}

pub fn auth_interceptor(request: Request<()>) -> Result<Request<()>, Status> {
    static ROLE_LOOKUP: &str = "Role: ";
    let certs = request
        .peer_certs()
        .expect("Client did not send its certs!");

    for (i, cert) in certs.iter().enumerate() {
        let der_u8 = cert.to_vec();
        let x509_cert = X509Certificate::from_der(der_u8.as_slice());
        match x509_cert {
            Ok((_rem, cert)) => {
                for ext in cert.extensions() {
                    if let ParsedExtension::CertificatePolicies(policy_info) =
                        ext.parsed_extension()
                    {
                        for policy in policy_info {
                            for policy_quals in &policy.policy_qualifiers {
                                for policy_qualifier in policy_quals {
                                    // look for a defined Role. If found add a Role to the request for later retrieval.
                                    let qualifier = policy_qualifier.qualifier;
                                    let qual_str = String::from_utf8(qualifier.to_vec())
                                        .expect("Unable to parse qualifier");
                                    match qual_str.find(ROLE_LOOKUP) {
                                        Some(role_index) => {
                                            let role_str =
                                                &qual_str[role_index + ROLE_LOOKUP.len()..];
                                            let role = Role(role_str.to_string());
                                            let mut req_mut = request;
                                            req_mut.extensions_mut().insert(role);
                                            return Ok(req_mut);
                                        }
                                        None => {} // role not found nothing to do
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_e) => {
                return Err(Status::unauthenticated("Unable to parse cert."));
            }
        }
    }

    Ok(request)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls = get_tls_config()?;

    let addr = "[::1]:50051".parse()?;
    let service = ProcessApiServiceImpl::default();

    println!("Server listening on {}", addr);

    Server::builder()
        .tls_config(tls)?
        .add_service(ProcessApiServiceServer::with_interceptor(
            service,
            auth_interceptor,
        ))
        .serve(addr)
        .await?;

    Ok(())
}
