# Programming Excercise

This project was done to complete a programming excercise. It implements a process pool with a gRPC client and server along with TLSm Authorization and Authentication. The client is a CLI that connects to the server and allows for the creation of proccess with a given command line. Then allows for the monitoring, and management of those procecesses.
Some shortcuts were take in order to speed up development or make the implementation a bit simpler.  

I may add on to this over time, but thought I would post this code for public consumption. For design details please take a look at the document [design doc](./design/exercise_design_doc.md).

Some dificulties that were encountered during development.
- There seems to be no equivelent api in the windows crate to monitor a Job and signal if the process owned by the Job has ended. It may be possible using a combination of the api `SetInformationJobObject`, `JobObjectAssociateCompletionPortInformation`, `CreateIoCompletionPort` and `GetQueuedCompletionStatus`. Though at the time of implementation I could not get these api's to be recognized as part of the windows crate. 
- Getting the client TLSm authorization information turned out to be quite layered.

Some ToDos:
- implement a config system to contiain items like the connection port. Location of TLSm certs etc.
- Add more tests to the server and client code.
- Make the error handling even more robust. 

While this is not my first Rust project, I am still new to Rust. Any comments or suggestions are welcome.
