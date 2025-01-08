use anyhow::{bail, Error, Result};
use std::{
    env,
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, BufReader, Read},
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    ptr::null_mut,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use windows::{
    core::*,
    Win32::{
        Foundation::STILL_ACTIVE,
        Foundation::*,
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH,
            FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_ALWAYS, OPEN_EXISTING,
        },
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectCpuRateControlInformation,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
                SetIoRateControlInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
                JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOBOBJECT_IO_RATE_CONTROL_INFORMATION,
                JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V1,
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                JOB_OBJECT_IO_RATE_CONTROL_ENABLE, JOB_OBJECT_LIMIT_JOB_MEMORY,
                JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            },
            Pipes::CreatePipe,
            Threading::{
                CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess,
                WaitForSingleObject, CREATE_SUSPENDED, INFINITE, NORMAL_PRIORITY_CLASS,
                PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
            },
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkerStatus {
    NotStarted,
    FailedToStart,
    Running,
    Stopped,
}

impl fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            WorkerStatus::NotStarted => "NotStarted",
            WorkerStatus::FailedToStart => "FailedToStart",
            WorkerStatus::Running => "Running",
            WorkerStatus::Stopped => "Stoped",
        };
        write!(f, "{}", name)
    }
}

// This global is a simple way to create a unique id. One could
// use other methods like GUID or a hash of the current date/time.
// Make the counter thread safe to access/create
static COUNTER: AtomicU64 = AtomicU64::new(1);
fn get_id() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub struct Worker {
    id: u64, // use a simple id as this struct wraps the PROCESS_INFORMATION that has the real process id.
    pi: PROCESS_INFORMATION,
    output_buffer: Arc<Mutex<Vec<u8>>>, // Note that this buffer could overflow in time, this is a temp solution
    status: Arc<Mutex<WorkerStatus>>,
    command: Option<String>, // store the command for now, though not currently used. Could be sent to output for debugging.
}

impl Worker {
    pub fn new() -> Self {
        unsafe {
            Worker {
                id: get_id(),
                pi: PROCESS_INFORMATION::default(),
                output_buffer: Arc::new(Mutex::new(Vec::new())),
                status: Arc::new(Mutex::new(WorkerStatus::NotStarted)),
                command: None,
            }
        }
    }

    fn is_process_running(&self) -> Result<bool> {
        unsafe {
            let mut exit_code: u32 = 0;
            let result = GetExitCodeProcess(self.pi.hProcess, &mut exit_code);
            match result {
                Ok(_) => {
                    if exit_code == STILL_ACTIVE.0 as u32 {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
    }

    /// Start a process with the given command and return the process id
    pub fn start(&mut self, command: &str, cpu_limit: Option<u32>, memory_limit: Option<u64>, io_limit: Option<u64>) -> Result<u64> {
        unsafe {
            let sa_attr = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                bInheritHandle: TRUE,
                ..Default::default()
            };

            // Create pipes for stdout and stderr
            let mut stdout_read = HANDLE::default();
            let mut stdout_write = HANDLE::default();

            if let Err(e) = CreatePipe(&mut stdout_read, &mut stdout_write, Some(&sa_attr), 0)
            {
                eprintln!("Failed to create stdout pipe: {:?}", e);
                self.set_status(WorkerStatus::FailedToStart);
                return Err(e.into());
            }

            // Ensure the write handle is not inherited
            if let Err(e) = SetHandleInformation(stdout_write, 0, HANDLE_FLAG_INHERIT) {
                eprintln!("Failed to set handle information for stdout: {:?}", e);
                self.set_status(WorkerStatus::FailedToStart);
                return Err(e.into());
            }

            // Create a job object in order to set process limits
            let mut job = HANDLE::default();
            match CreateJobObjectW(None, None) {
                Ok(job_local) => {
                    job = job_local;
                }
                Err(e) => {
                    eprintln!("Failed to create job object: {:?}", e);
                    self.set_status(WorkerStatus::FailedToStart);
                    return Err(e.into());
                }
            }

            if cpu_limit.is_some() {
                self.set_cpu_limit(&job, cpu_limit.unwrap())?;
            }
            
            if memory_limit.is_some() {
                self.set_memory_limit(&job, memory_limit.unwrap())?;
            }

            if io_limit.is_some() {
                self.set_io_limit(&job, io_limit.unwrap())?;
            }

            // output pipes are assigned here. Note we use the same pipe for both stdout and stderr.
            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                hStdOutput: stdout_write,
                hStdError: stdout_write,
                dwFlags: STARTF_USESTDHANDLES,
                ..Default::default()
            };

            // Start the process suspended so there is time to attach the Job object to the process before it starts.
            let mut command_str: Vec<u16> = command.encode_utf16().collect();
            command_str.push(0); // null terminate the string
            if let Err(e) = CreateProcessW(
                None,
                PWSTR(command_str.as_ptr() as *mut _),
                None,
                None,
                true, // this must be set to true otherwise there is no output collected
                CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut self.pi as *mut _ as *mut _,
            ) {
                eprintln!("Failed to create process: {:?}", e);
                CloseHandle(job).expect("Unable to close job handle.");
                self.set_status(WorkerStatus::FailedToStart);
                return Err(e.into());
            }

            if let Err(e) = AssignProcessToJobObject(job, self.pi.hProcess) {
                eprintln!("Failed to assign process to job object: {:?}", e);
                CloseHandle(self.pi.hProcess).expect("Unable to close process handle");
                CloseHandle(self.pi.hThread).expect("Unable to close thread handle");
                CloseHandle(job).expect("Unable to close job handle");
                self.set_status(WorkerStatus::FailedToStart);
                return Err(e.into());
            }

            // Close the write end of the pipe
            CloseHandle(stdout_write).expect("Unable to close stdout write handle.");

            // Start the process up
            ResumeThread(self.pi.hThread);
            CloseHandle(self.pi.hThread);

            //Spawn a thread to watch for output from the process and collect that into the
            // output buffer.
            let buffer_clone = Arc::clone(&self.output_buffer);
            let status_clone = Arc::clone(&self.status);
            let mut reader = BufReader::new(File::from_raw_handle(stdout_read.0));

            // Ideally we would also check for the self.pi.hProcess is_invalid or not. However
            // there seems to be no way to pass the HANDLE down to the thread closure.
            thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => continue, // just keep reading
                        Ok(n) => {
                            let mut output = buffer_clone.lock().unwrap();
                            output.extend_from_slice(&buffer[..n]);
                        }
                        Err(err) => {
                            eprintln!("Failed to read from stdout pipe: {}", err);
                            break;
                        }
                    }
                    let status = status_clone.lock().unwrap();
                    if (*status != WorkerStatus::Running && *status != WorkerStatus::NotStarted) {
                        break;
                    }
                }
            });
        }

        // all went well so set internal properties
        self.set_status(WorkerStatus::Running);
        self.command = Some(command.to_string());

        // return the id of the newly started process.
        // an id of zero means something failed to start.
        Ok(self.id)
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.get_status() == WorkerStatus::Running
            && !self.pi.hProcess.is_invalid()
            && self.is_process_running()?
        {
            unsafe {
                // Terminate the process
                if let Err(e) = TerminateProcess(self.pi.hProcess, 0) {
                    return Err(e.into());
                }

                CloseHandle(self.pi.hProcess).expect("Unable to close process handle");
            }
        } 

        // Either we stopped the process or its not running.
        self.set_status(WorkerStatus::Stopped);

        Ok(())
    }

    // pub fn get_status_string(&self) -> String {
    //     // this would be a good place to check the validity of the process handle.
    //     // And set the status to Stopped if the process has terminated.
    //     let status = self.status.lock().unwrap();

    //     format!("{}", *status)
    // }

    pub fn get_status(&self) -> WorkerStatus {
        // this would be a good place to check the validity of the process handle.
        // And set the status to Stopped if the process has terminated.
        let status = self.status.lock().unwrap();

        *status
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }

    // Return a copy of the current output to date
    // so as to keep the buffer lock to a minimum.
    pub fn get_output_buf(&mut self) -> Result<String> {
        unsafe {
            // create a new bufreader each time to avoid lifetime issues.
            //let mut reader = BufReader::new(File::from_raw_handle(self.stdout_read.0));
            let buffer = self.output_buffer.lock().unwrap();
            match std::str::from_utf8(&buffer) {
                Err(e) => Err(e.into()),
                Ok(output_string) => {
                    Ok(output_string.to_string()) // this is a converted copy of the current buffer.
                }
            }
        }
    }

    pub fn wait(&mut self) {
        if self.get_status() == WorkerStatus::Running && self.is_process_running().unwrap() && !self.pi.hProcess.is_invalid() {
            unsafe {
                // Should use a reasonable timeout here. Perhaps from an environment variable.
                WaitForSingleObject(self.pi.hProcess, INFINITE);
                CloseHandle(self.pi.hProcess).expect("Unable to close process handle");
            }
        }
        
        self.set_status(WorkerStatus::Stopped);
    }

    fn set_status(&mut self, status: WorkerStatus) {
        let mut locked_status = self.status.lock().unwrap();
        *locked_status = status;
    }

    // internal methods
    fn set_cpu_limit(&mut self, job: &HANDLE, cpu_limit: u32) -> Result<()> {
        unsafe {
            if cpu_limit < 1 && cpu_limit > 100 {
                return Err(Error::msg("CPU limit must be between 1 and 100"));
            }

            let mut cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                    CpuRate: cpu_limit * 100,
                },
            };

            if let Err(e) = SetInformationJobObject(
                *job,
                JobObjectCpuRateControlInformation,
                &mut cpu_info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            ) {
                eprintln!("Failed to set cpu job object information: {:?}", e);
                CloseHandle(*job).expect("Unable to close cpu job handle");
                self.set_status(WorkerStatus::FailedToStart);
            }
        }

        Ok(())
    }

    fn set_memory_limit(&mut self, job: &HANDLE, memory_limit: u64) -> Result<()> {
        unsafe {
            let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_JOB_MEMORY
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                    ..Default::default()
                },
                JobMemoryLimit: memory_limit as usize,
                ProcessMemoryLimit: memory_limit as usize,
                ..Default::default()
            };

            if let Err(e) = SetInformationJobObject(
                *job,
                JobObjectExtendedLimitInformation,
                &mut job_info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) {
                eprintln!("Failed to set job memory job object information: {:?}", e);
                CloseHandle(*job).expect("Unable to close memory job handle.");
                self.set_status(WorkerStatus::FailedToStart);
                return Err(e.into());
            }
        }

        Ok(())
    }

    fn set_io_limit(&mut self, job: &HANDLE, io_limit: u64) -> Result<()> {

        unsafe {
            let mut io_info = JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V1 {
                ControlFlags: JOB_OBJECT_IO_RATE_CONTROL_ENABLE, // We cant use this type to assign here JOB_OBJECT_IO_RATE_CONTROL_ENABLE;
                MaxIops: io_limit as i64,
                MaxBandwidth: io_limit as i64,
                ..Default::default()
            };
            // Need to use this different api in order to set io limits.
            if SetIoRateControlInformationJobObject(
                *job,
                &mut io_info as *mut _ as *mut _,
            ) == 0
            {
                eprintln!(
                    "Failed to set io job object io information: {:?}",
                    GetLastError()
                );
                CloseHandle(*job).expect("Unable to close job handle");
                self.set_status(WorkerStatus::FailedToStart);
                return Err(Error::msg("Unable to set io rate"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let w = Worker::new();
        assert_eq!(w.get_status(), WorkerStatus::NotStarted);
    }

    #[test]
    fn test_start_and_terminate() {
        let mut w = Worker::new();
        match w.start("cmd.exe /C ping -n 5 apple.com", None, None, None) {
            Ok(id) => {
                assert_ne!(id, 0);
                assert_eq!(w.get_status(), WorkerStatus::Running);
            }
            Err(e) => {
                assert!(false, "Unable to start process: {:?}", e);
            }
        }

        match w.stop() {
            Ok(_) => {
                assert_eq!(w.get_status(), WorkerStatus::Stopped);
            }
            Err(e) => {
                assert!(false, "Unable to stop process: {:?}", e);
            }
        }
    }

    #[test]
    fn test_terminate_after_process_exit() {
        let mut w = Worker::new();
        match w.start("cmd.exe /C ping apple.com", None, None, None) {
            Ok(id) => {
                assert_ne!(id, 0);
                assert_eq!(w.get_status(), WorkerStatus::Running);
            }
            Err(e) => {
                assert!(false, "Unable to start process: {:?}", e);
            }
        }

        w.wait();

        match w.stop() {
            Ok(_) => {
                assert_eq!(w.get_status(), WorkerStatus::Stopped);
            }
            Err(e) => {
                assert!(false, "Unable to stop process: {:?}", e);
            }
        }
    }

    #[test]
    fn test_getoutput_after_termination() {
        let mut w = Worker::new();

        // this command takes a few seconds to run so we can wait on its completion.
        match w.start("cmd.exe /C ping -n 5 apple.com", None, None, None) {
            Ok(id) => {
                assert_ne!(id, 0);
                assert_eq!(w.get_status(), WorkerStatus::Running);
            }
            Err(e) => {
                assert!(false, "Unable to start process: {:?}", e);
            }
        }

        w.wait();

        assert_eq!(w.get_status(), WorkerStatus::Stopped);

        match w.get_output_buf() {
            Ok(string) => {
                assert_ne!(string.len(), 0);
            }
            Err(e) => {
                eprintln!("Failed get output string: {}", e);
                assert!(false);
            }
        };
    }

    #[test]
    fn test_getoutput_while_running() {
        let mut w = Worker::new();

        // this command takes a while to run so we can wait on its completion.
        match w.start("cmd.exe /C ping -n 100 apple.com", None, None, None) {
            Ok(id) => {
                assert_ne!(id, 0);
                assert_eq!(w.get_status(), WorkerStatus::Running);
            }
            Err(e) => {
                assert!(false, "Unable to start process: {:?}", e);
            }
        }

        thread::sleep(Duration::from_millis(200)); // Give time for new output

        // Run this in a short loop to keep the time for the test to finish down. 
        let mut max_len = 0;
        for _ in 0..2 {
            if w.is_process_running().unwrap() && !w.pi.hProcess.is_invalid() {
                match w.get_output_buf() {
                    Ok(string) => {
                        println!("OutputLen: {}", string.len());
                        println!("Output: {}", string);
                        assert!(string.len() > max_len);
                        max_len = string.len();
                        thread::sleep(Duration::from_millis(1000)); // Give time for new output
                    }
                    Err(e) => {
                        eprintln!("Failed get output string: {}", e);
                        assert!(false);
                    }
                };
            } else {
                break;
            }
        }

        match w.stop() {
            Ok(_) => {
                assert_eq!(w.get_status(), WorkerStatus::Stopped);
            }
            Err(e) => {
                assert!(false, "Unable to stop process: {:?}", e);
            }
        }
    }

}
