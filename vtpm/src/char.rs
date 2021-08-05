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
use std::os::unix::io::{RawFd, AsRawFd};
use nix::unistd::{read, write};
use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag, sendmsg, recvfrom, ControlMessage, MsgFlags };
use nix::sys::uio::IoVec;
use libc;

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
    write_msgfd: RawFd,
    /* Control Channel */
    ctrl_fd: RawFd,
    /* Command Channel */
    data_ioc: RawFd,
    chr_write_lock: Arc<Mutex<usize>>,
}

impl SocketCharDev {
    pub fn new() -> Self {
        Self {
            state: ChardevState::ChardevStateDisconnected,
            stream: None,
            write_msgfd: -1,
            ctrl_fd: -1,
            data_ioc: -1,
            chr_write_lock: Arc::new(Mutex::new(0))
        }
    }

    pub fn connect(&self, socket_path: &str) -> isize {
        self.state = ChardevState::ChardevStateConnecting;

        let now = Instant::now();

        // Retry connecting for a full minute
        let err = loop {
            let err = match UnixStream::connect(socket_path) {
                Ok(s) => {
                    self.stream = Some(s);
                    self.state = ChardevState::ChardevStateConnected;
                    self.ctrl_fd = s.as_raw_fd();
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

    pub fn set_dataioc(&mut self, fd: RawFd) {
        self.data_ioc = fd;
    }

    pub fn set_msgfd(&mut self, fd: RawFd){
        self.write_msgfd = fd;
    }

    pub fn chr_sync_read(&self, buf: &mut [u8], len: usize) -> isize {
        if self.state != ChardevState::ChardevStateConnected {
            return 0
        }
        //SET BLOCKING
        let (size, _) = recvfrom(self.ctrl_fd, buf).expect("char.rs: sync_read recvmsg error");
        size as isize
    }

    pub fn send_full(&self, buf: &mut [u8], len: usize) -> isize {
        let offset = 0;

        let iov = &[IoVec::from_slice(buf)];
        let cmsgs = &[ControlMessage::ScmRights(&[self.write_msgfd])];

        sendmsg(self.ctrl_fd, iov, cmsgs, MsgFlags::empty(), None).expect("char.rs: ERROR ON send_full sendmsg") as isize
    }

    pub fn chr_write(&self, buf: &mut [u8], len:usize) -> isize {
        let res = 0;

        if let Some(sock) = self.stream {
            let mut guard = self.chr_write_lock.lock().unwrap();
            {
                let res = match self.state {
                    ChardevState::ChardevStateConnected => {
                        let ret = self.send_full(buf, len);
                        /* free the written msgfds in any cases
                        * other than ret < 0 */
                        if ret < 0 {
                            self.write_msgfd = 0;
                        }

                        // if (ret < 0 && errno != EAGAIN) {
                        //     if (tcp_chr_read_poll(chr) <= 0) {
                        //         /* Perform disconnect and return error. */
                        //         tcp_chr_disconnect_locked(chr);
                        //     } /* else let the read handler finish it properly */
                        // }

                        ret
                    }
                    _ => -1,
                };
            }
            std::mem::drop(guard);

            res
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

    pub fn chr_fe_set_msgfd(&self, fd: RawFd) -> isize {
        if let Some(dev) = self.chr {
            dev.set_msgfd(fd);
            0
        } else {
            -1
        }
    }

    pub fn chr_fe_set_dataioc(&self, fd: RawFd) -> isize {
        if let Some(dev) = self.chr {
            dev.set_dataioc(fd);
            0
        } else {
            -1
        }
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
            dev.chr_sync_read(&mut buf, len)
        } else {
            -1
        }
    }


}

pub enum Error {
    BindSocket()
}