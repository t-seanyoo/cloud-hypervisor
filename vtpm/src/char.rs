use std::sync::{Arc, Mutex};
use std::cmp;
use std::io;
use std::io::{BufRead, BufReader};
use std::os::unix::net::{UnixStream,UnixListener};
use std::thread;
use std::time::{Duration, Instant};
use std::thread::sleep;
use std::str;
use std::io::prelude::*;
use std::io::Write;

const TPM_TIS_BUFFER_MAX: usize = 4096;

type Result<T> = std::result::Result<T, Error>;

/// Copy data in `from` into `to`, until the shortest
/// of the two slices.
///
/// Return the number of bytes written.
fn byte_copy(from: &[u8], mut to: &mut [u8]) -> usize {
    to.write(from).unwrap()
}

#[derive(PartialEq)]
enum ChardevState {
    ChardevStateDisconnected,
    ChardevStateConnecting,
    ChardevStateConnected,
}

pub struct SocketCharDev {
    state: ChardevState,
    stream: Option<UnixStream>,
    chr_write_lock: Arc<Mutex<usize>>,
}

impl SocketCharDev {
    pub fn new() -> Self {
        Self {
            state: ChardevState::ChardevStateDisconnected,
            stream: None,
            chr_write_lock: Arc::new(Mutex::new(0))
        }
    }

    pub fn connect(&self, socket_path: &str) -> isize {
        let now = Instant::now();

        // Retry connecting for a full minute
        let err = loop {
            let err = match UnixStream::connect(socket_path) {
                Ok(s) => {
                    self.stream = Some(s);
                    self.state = ChardevState::ChardevStateConnected;
                    return 0
                }
                Err(e) => e,
            };
            sleep(Duration::from_millis(100));

            if now.elapsed().as_secs() >= 60 {
                break err;
            }
        };
        
        // error!(
        //     "Failed connecting the backend after trying for 1 minute: {:?}",
        //     err
        // );
        -1
    }

    pub fn chr_write(&self, buf: &mut [u8], len:usize) -> isize {
        
        if let Some(sock) = self.stream {
            /* Lock object for scope */
            let mut guard = self.chr_write_lock.lock().unwrap();
            sock.write_all(&buf);
            std::mem::drop(guard);
            0
        } else {
            -1
        }
    }

    pub fn chr_read(&self, buf: &mut [u8], len: usize) -> isize {
        //Grab all response bytes so none is left behind
        let mut newbuf: &[u8] = &[0; TPM_TIS_BUFFER_MAX];
        
        if let Some(sock) = self.stream {
            sock.read(&mut newbuf);
            byte_copy(&newbuf, buf);
            0
        } else {
            -1
        }
    }
}

pub struct CharBackend {
    chr: Option<SocketCharDev>,
    fe_open: bool,
}

impl CharBackend {
    pub fn new() -> Self {
        Self {
            chr: None,
            fe_open: false,
        }
    }

    pub fn chr_fe_init(&self) -> isize {
        let sockdev = SocketCharDev::new();

        let res = sockdev.connect("/tmp/mytpm1/swtpm-sock");
        self.chr = Some(sockdev);
        if res < 0 {
            return -1
        }
        
        self.fe_open = true;
        0
    }

    /**
     * qemu_chr_fe_write_all:
     * @buf: the data
     * @len: the number of bytes to send
     *
     * Write data to a character backend from the front end.  This function will
     * send data from the front end to the back end.  Unlike @chr_fe_write,
     * this function will block if the back end cannot consume all of the data
     * attempted to be written.  This function is thread-safe.
     *
     * Returns: the number of bytes consumed (0 if no associated Chardev)
     */
    pub fn chr_fe_write_all(&self, buf: &mut [u8], len: usize) -> isize {
        if let Some(dev) = self.chr {
            dev.chr_write(&mut buf, len)
        } else {
            -1
        }
    }


    /**
     * chr_fe_read_all:
     * @buf: the data buffer
     * @len: the number of bytes to read
     *
     * Read data to a buffer from the back end.
     *
     * Returns: the number of bytes read (0 if no associated Chardev)
     */
    pub fn chr_fe_read_all(&self, buf: &mut [u8], len: usize) -> isize {
        if let Some(dev) = self.chr {
            dev.chr_read(&mut buf, len)
        } else {
            -1
        }
    }


}

pub enum Error {
    BindSocket()
}