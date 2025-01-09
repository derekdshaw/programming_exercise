use crate::worker::WorkerStatus::{self, *};
use crate::worker::{self, Worker};
use anyhow::{bail, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, io::BufRead};

#[derive(Default)]
pub struct ProcessPoolManager {
    pool: HashMap<u64, Box<Worker>>,
}

// Required for the pool to be shared between threads
unsafe impl Sync for ProcessPoolManager {}
unsafe impl Send for ProcessPoolManager {}

impl ProcessPoolManager {
    pub fn new() -> Self {
        ProcessPoolManager {
            pool: HashMap::new(), // Does this need a mutex for insertions?
        }
    }

    pub fn start_process(&mut self, command_line: &str, cpu_limit: Option<u32>, memory_limit: Option<u64>, io_limit: Option<u64>) -> Result<(u64)> {
        let worker = Worker::new();
        let process_id = worker.get_id();
        self.pool.insert(process_id, Box::new(worker));
        let mut worker_mut = self.pool.get_mut(&process_id).unwrap();

        worker_mut.start(command_line, cpu_limit, memory_limit, io_limit)
    }

    // Should this remove the worker from the pool.
    pub fn stop_process(&mut self, process_id: u64) -> Result<bool> {
        // TODO test if the worker is in the pool and return an error if not
        if self.pool.contains_key(&process_id) {
            let mut worker = self.pool.get_mut(&process_id).unwrap();
            match worker.stop() {
                Ok(_) => {
                    let did_stop = worker.get_status() == WorkerStatus::Stopped;

                    // Remove the worker from the pool
                    if did_stop {
                        self.pool.remove(&process_id);
                    }

                    Ok(did_stop)
                }
                Err(e) => Err(e),
            }
        } else {
            Err(anyhow::anyhow!("Process not found in pool"))
        }
    }

    // This needs to return a result if the process is not in the pool
    pub fn query_process_status(&self, process_id: u64) -> Result<WorkerStatus> {
        if self.pool.contains_key(&process_id) {
            let worker = &self.pool[&process_id];
            Ok(worker.get_status())
        } else {
            Err(anyhow::anyhow!("Process not found in pool"))
        }
    }

    pub fn get_process_output(&mut self, process_id: u64) -> Result<String> {
        if self.pool.contains_key(&process_id) {
            let mut worker = self.pool.get_mut(&process_id).unwrap();
            worker.get_output_buf()
        } else {
            Err(anyhow::anyhow!("Process not found in pool"))
        }
    }

    pub fn list_process_ids(&self) -> Vec<u64> {
        self.pool.keys().copied().collect()
    }
}
