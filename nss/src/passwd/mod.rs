use crate::error;
use libc::uid_t;
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use sysinfo::{Pid, System};
use tokio::runtime::Builder;
use tonic::Request;

use crate::client::{self, authd};
use authd::PasswdEntry;

#[derive(Default)]
struct MyClass {
    dropped: bool,
}

impl MyClass {
    async fn get_entries(&mut self) -> Response<Vec<Passwd>> {
        let mut client = match client::new_client().await {
            Ok(c) => c,
            Err(e) => {
                error!("could not connect to gRPC server: {}", e);
                return Response::Unavail;
            }
        };

        let req = Request::new(authd::Empty {});
        match client.get_passwd_entries(req).await {
            Ok(r) => Response::Success(passwd_entries_to_passwds(r.into_inner().entries)),
            Err(e) => {
                error!("error when listing passwd: {}", e.message());
                super::grpc_status_to_nss_response(e)
            }
        }
    }
}

impl Drop for MyClass {
    fn drop(&mut self) {
        if !self.dropped {
            let mut this = MyClass::default();
            std::mem::swap(&mut this, self);
            this.dropped = true;
            tokio::spawn(async move { this.get_entries().await });
        }
    }
}

// use std::{
//     result::Result,
//     time::Duration,
// };

// use async_dropper::{AsyncDrop, AsyncDropper};
// use async_trait::async_trait;

// // NOTE: this example is rooted in crates/async-dropper

// /// This object will be async-dropped (which must be wrapped in AsyncDropper)
// #[derive(Default)]
// struct AsyncThing(String);

// #[async_trait]
// impl AsyncDrop for AsyncThing {
//     async fn async_drop(&mut self) {
//         eprintln!("async dropping [{}]!", self.0);
//         tokio::time::sleep(Duration::from_secs(2)).await;
//         eprintln!("dropped [{}]!", self.0);
//     }
// }

pub struct AuthdPasswd;
impl PasswdHooks for AuthdPasswd {
    /// get_all_entries returns all passwd entries.
    fn get_all_entries() -> Response<Vec<Passwd>> {
        get_all_entries()
    }

    /// get_entry_by_uid returns the passwd entry for the given uid.
    fn get_entry_by_uid(uid: uid_t) -> Response<Passwd> {
        get_entry_by_uid(uid)
    }

    /// get_entry_by_name returns the passwd entry for the given name.
    fn get_entry_by_name(name: String) -> Response<Passwd> {
        get_entry_by_name(name)
    }
}

/// get_all_entries connects to the grpc server and asks for all passwd entries.
fn get_all_entries() -> Response<Vec<Passwd>> {
    eprintln!("Before the async drop");
    eprintln!("here comes the (async) drop");
    return Response::Unavail;
    // super::RT.block_on(async {
        // let mut client = match client::new_client().await {
        //     Ok(c) => c,
        //     Err(e) => {
        //         error!("could not connect to gRPC server: {}", e);
        //         return Response::Unavail;
        //     }
        // };

        // let req = Request::new(authd::Empty {});
        // match client.get_passwd_entries(req).await {
        //     Ok(r) => Response::Success(passwd_entries_to_passwds(r.into_inner().entries)),
        //     Err(e) => {
        //         error!("error when listing passwd: {}", e.message());
        //         super::grpc_status_to_nss_response(e)
        //     }
        // }
    // })
}

/// get_entry_by_uid connects to the grpc server and asks for the passwd entry with the given uid.
fn get_entry_by_uid(uid: uid_t) -> Response<Passwd> {
    eprintln!("Before the async drop");
    // let _example_obj = AsyncDropper::new(AsyncThing(String::from("test")));
    eprintln!("here comes the (async) drop");
    return Response::Unavail;
    // super::RT.block_on(async {
        // let mut client = match client::new_client().await {
        //     Ok(c) => c,
        //     Err(e) => {
        //         error!("could not connect to gRPC server: {}", e);
        //         return Response::Unavail;
        //     }
        // };

        // let req = Request::new(authd::GetByIdRequest { id: uid });
        // match client.get_passwd_by_uid(req).await {
        //     Ok(r) => Response::Success(passwd_entry_to_passwd(r.into_inner())),
        //     Err(e) => {
        //         error!("error when getting passwd by uid: {}", e.message());
        //         super::grpc_status_to_nss_response(e)
        //     }
        // }
    // })
}

/// get_entry_by_name connects to the grpc server and asks for the passwd entry with the given name.
fn get_entry_by_name(name: String) -> Response<Passwd> {
    eprintln!("Before the async drop");
    // let _example_obj = AsyncDropper::new(AsyncThing(String::from("test")));
    eprintln!("here comes the (async) drop");
    return Response::Unavail;
    // super::RT.block_on(async {
        // let mut client = match client::new_client().await {
        //     Ok(c) => c,
        //     Err(e) => {
        //         error!("could not connect to gRPC server: {}", e);
        //         return Response::Unavail;
        //     }
        // };

        // let req = Request::new(authd::GetPasswdByNameRequest {
        //     name,
        //     should_pre_check: should_pre_check(),
        // });
        // match client.get_passwd_by_name(req).await {
        //     Ok(r) => Response::Success(passwd_entry_to_passwd(r.into_inner())),
        //     Err(e) => {
        //         error!("error when getting passwd by name: {}", e.message());
        //         super::grpc_status_to_nss_response(e)
        //     }
        // }
    // })
}

/// passwd_entry_to_passwd converts a PasswdEntry to a libnss::Passwd.
fn passwd_entry_to_passwd(entry: PasswdEntry) -> Passwd {
    Passwd {
        name: entry.name,
        passwd: entry.passwd,
        uid: entry.uid,
        gid: entry.gid,
        gecos: entry.gecos,
        dir: entry.homedir,
        shell: entry.shell,
    }
}

/// passwd_entries_to_passwds converts a Vec<PasswdEntry> to a Vec<libnss::Passwd>.
fn passwd_entries_to_passwds(entries: Vec<PasswdEntry>) -> Vec<Passwd> {
    entries.into_iter().map(passwd_entry_to_passwd).collect()
}

/// should_pre_check returns true if the current process is a child of sshd.
#[allow(unreachable_code)] // This function body is overridden in integration tests, so we need to ignore the warning.
fn should_pre_check() -> bool {
    #[cfg(feature = "integration_tests")]
    return std::env::var("AUTHD_NSS_SHOULD_PRE_CHECK").is_ok();

    let sys = System::new_all();
    let ppid: Option<Pid>;
    if let Some(p) = sys.process(Pid::from_u32(std::process::id())) {
        ppid = p.parent();
    } else {
        return false;
    }

    if let Some(id) = ppid {
        if let Some(p) = sys.process(id) {
            if p.name() == "sshd" {
                return true;
            }
        }
    }

    false
}
