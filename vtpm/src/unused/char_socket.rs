use virtio_devices::vhost_user::vu_common_ctrl::{
    add_memory_region, connect_vhost_user, negotiate_features_vhost_user, reset_vhost_user,
    setup_vhost_user, update_mem_table,
};
use {Error, Result};

/// Unix domain socket endpoint for vhost-user connection.
pub struct Endpoint<R: Req> {
    sock: UnixStream,
    _r: PhantomData<R>,
}

pub struct Master {
    node: Arc<Mutex<MasterInternal>>,
}

impl Master {
    pub fn connect<P: AsRef<Path>>(path: P, max_queue_num: u64) -> Result<Self> {
        let mut retry_count = 5;
        let endpoint = loop {
            match Endpoint::<MasterReq>::connect(&path) {
                Ok(endpoint) => break Ok(endpoint),
                Err(e) => match &e {
                    VhostUserError::SocketConnect(why) => {
                        if why.kind() == std::io::ErrorKind::ConnectionRefused && retry_count > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            retry_count -= 1;
                            continue;
                        } else {
                            break Err(e);
                        }
                    }
                    _ => break Err(e),
                },
            }
        }?;

        Ok(Self::new(endpoint, max_queue_num))
    }

    pub fn connect_socket(
        socket_path: &str,
        num_queues: u64,
    ) -> Result<Master> {
        let now = Instant::now();
        // Retry connecting for a full minute
        let err = loop {
            let err = match Master::connect(socket_path, num_queues) {
                Ok(m) => return Ok(m),
                Err(e) => e,
            };
            sleep(Duration::from_millis(100));

            if now.elapsed().as_secs() >= 60 {
                break err;
            }
        };
    }
}

pub struct CharSocket {
    id: String,
    socket_path: String,
    req_num_queues: usize,
}

impl CharSocket {
    pub fn new(
        id: String,
        path: &str,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<CharSocket> {
        let mut slave_req_support = false;

        // Connect to the vhost-user socket.
        let mut vhost_user_fs = connect_vhost_user(false, path, num_queues as u64, false)?;

    }
}