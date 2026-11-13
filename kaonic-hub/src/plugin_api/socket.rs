//! The plugin API's sockets: `<api_dir>/<id>.sock` for each installed plugin, owned by the
//! plugin's user, mode 0600, in a directory only root writes (0711).
//!
//! A connection is served only if its peer is the plugin's user. Each socket serves at most
//! [`MAX_CONNECTIONS`] at once, with the hub's header timeout and request deadline
//! (`crate::server`). Sockets come and go with the installer's list ([`Sockets::reconcile`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

use crate::app::App;

/// Connections one plugin's socket holds at once; more are closed at once.
pub const MAX_CONNECTIONS: usize = 16;
/// After a failed accept (out of descriptors), wait instead of spinning on the one core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A socket being served; closed and removed when dropped.
struct Served {
    uid: u32,
    path: PathBuf,
    task: JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Default)]
pub struct Sockets {
    served: Mutex<HashMap<String, Served>>,
}

impl Sockets {
    /// One socket per plugin in `list` (its id and user); the others' sockets go.
    pub fn reconcile(&self, app: &App, dir: &Path, list: &[(&str, u32)]) {
        if let Err(error) = make_dir(dir) {
            log::error!("plugins: cannot make {}: {error}", dir.display());
            return;
        }
        let mut served = self.served.lock().expect("sockets lock");
        served.retain(|id, socket| list.iter().any(|&(plugin, uid)| plugin == id && uid == socket.uid));
        for &(id, uid) in list {
            if served.contains_key(id) {
                continue;
            }
            let path = dir.join(format!("{id}.sock"));
            match open(app, id, uid, &path) {
                Ok(task) => {
                    served.insert(id.to_owned(), Served { uid, path, task });
                }
                Err(error) => log::error!("plugins: cannot open {}: {error}", path.display()),
            }
        }
    }

    /// The plugins with a socket now.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.served.lock().expect("sockets lock").keys().cloned().collect();
        ids.sort();
        ids
    }
}

/// The sockets' directory: root's, others may only pass through.
fn make_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o711).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))
}

/// Binds `path` for the plugin `id` running as `uid` and serves it until the task ends.
pub fn open(app: &App, id: &str, uid: u32, path: &Path) -> std::io::Result<JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt;
    // A socket left by an earlier hub; only root writes in the directory.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    let owned = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).and_then(|()| std::os::unix::fs::chown(path, Some(uid), None));
    if let Err(error) = owned {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(tokio::spawn(serve(listener, app.clone(), id.to_owned(), uid)))
}

/// Serves plugin `id`'s API on `listener` to `uid` only, until the task ends.
pub async fn serve(listener: UnixListener, app: App, id: String, uid: u32) {
    let router = crate::server::with_deadline(super::router(app, &id));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Dropped with the task: every connection still open ends with it.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) => {
                        log::debug!("plugins: accept on {id}'s socket: {error}");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                let peer = crate::server::peer_uid(&stream);
                if peer != Some(uid) {
                    log::warn!("plugins: {id}'s socket refused user {peer:?}");
                    continue;
                }
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    log::debug!("plugins: {id} holds {MAX_CONNECTIONS} connections already");
                    continue;
                };
                connections.spawn(crate::server::serve_connection(crate::server::Admitted::new(stream, slot), router.clone()));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}
