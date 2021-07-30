use std::sync::{Arc, Mutex};
use std::cmp;

#[derive(PartialEq)]
enum TCPChardevState {
    TcpChardevStateDisconnected,
    TcpChardevStateConnecting,
    TcpChardevStateConnected,
}

pub struct SocketCharDev {
    state: TCPChardevState,
    ioc: ,
    write_msgfds: ,
    write_msgfds_num: usize,
    read_msgfds: ,
    read_msgfds_num: usize,
    chr_write_lock: Arc<Mutex<usize>>,
}

impl SocketCharDev {
    pub fn new() -> Self {
        Self {
            chr_write_lock: Arc::new(Mutex::new(0)),
        }
    }

    /* NB may be called even if tcp_chr_connect has not been
    * reached, due to TLS or telnet initialization failure,
    * so can *not* assume s->state == TCP_CHARDEV_STATE_CONNECTED
    * This must be called with chr->chr_write_lock held.
    */
    pub fn tcp_chr_disconnect_locked(&self) {
        
    }

    pub fn tcp_chr_disconnect(&self) {
        let mut guard = self.chr_write_lock.lock().unwrap();
        self.tcp_chr_disconnect_locked();
        std::mem::drop(guard);
    }

    pub fn tcp_chr_sync_read(&self, offset: isize, buf: &mut Vec<u8>, len: usize) -> isize{
        let size: isize;
        if self.state != TCPChardevState::TcpChardevStateConnected {return 0}

        // Set blocking mode true
        size = self.tcp_chr_recv();
        if self.state != TCPChardevState::TcpChardevStateDisconnected {
            // Set blocking mode false
        }

        if size == 0 {
            self.tcp_chr_disconnect();
        }

        size
    }

    pub fn tcp_chr_write(&self, buf: Vec<u8>, offset: isize, len: usize) -> isize {
        if self.state == TCPChardevState::TcpChardevStateConnected {
            let ret = ioc.io_channel_send_full(buf, len, self.write_msgfds, self.write_msgfds_num);
            if !(ret < 0) && self.write_msgfds_num != 0 {
                self.write_msgfds_num = 0;
                self.write_msgfds = 0;
            }

            if ret < 0 {
                if self.tcp_chr_read_poll() <= 0 {
                    /* Perform disconnect and return error. */
                    self.tcp_chr_disconnect_locked();
                } /* else let the read handler finish it properly */
            }

            ret
        } else {
            -1
        }
    }

    pub fn chr_write_buffer(&self, buf: Vec<u8>, len: usize, offset: &mut isize) -> isize {
        let res = 0;
        *offset = 0;

        /* Lock object for scope */
        let mut guard = self.chr_write_lock.lock().unwrap();
        {
            while *offset < len as isize {
                res = self.tcp_chr_write(buf, *offset, (len as isize - *offset) as usize);

                if res <= 0 {
                    break;
                }

                *offset += res;
            }
        }
        // if (*offset > 0) {
        //     /*
        //      * If some data was written by backend, we should
        //      * only log what was actually written. This method
        //      * may be invoked again to write the remaining
        //      * method, thus we'll log the remainder at that time.
        //      */
        //     qemu_chr_write_log(s, buf, *offset);
        // } else if (res < 0) {
        //     /*
        //      * If a fatal error was reported by the backend,
        //      * assume this method won't be invoked again with
        //      * this buffer, so log it all right away.
        //      */
        //     qemu_chr_write_log(s, buf, len);
        // }

        std::mem::drop(guard);
        res
    }

    pub fn chr_write(&self, buf: Vec<u8>, len: usize) -> isize {
        let offset = 0;
        let res: isize;

        res = self.chr_write_buffer(buf, len, &mut offset);

        if res < 0 {
            return res
        }

        offset
    }

    pub fn tcp_get_msgfds(&self, fds: &mut Vec<isize>, len: usize) -> isize {
        let to_copy = cmp::min(len, self.read_msgfds_num);

        if len <= 16 {
            return -1
        }

        if to_copy != 0 {
            let dst_ptr = fds.as_mut_ptr();
            let src_ptr = self.read_msgfds.as_ptr();
            ptr::copy_nonoverlapping(src_ptr, dst_ptr, to_copy*2)
        }

        to_copy as isize
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
        }
    }

    pub fn chr_fe_init(&self) -> bool {
        let tag = 0;
        
        self.chr = Some(SocketCharDev {
            state: TCPChardevState::TcpChardevStateDisconnected,
            ioc: ,
            write_msgfds: ,
            write_msgfds_num: ,
            read_msgfds: ,
            read_msgfds_num: ,
            chr_write_lock: Arc::new(Mutex::new(0))>,
        });
        
        
        self.fe_open = false;
        true
    }

    pub fn chr_fe_write_all(&self, buf: Vec<u8>, len: usize) -> isize {
        match self.chr {
            None => return 0,
            Some(x) => x.chr_write(buf, len)
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
    pub fn chr_fe_read_all(&self, buf: &mut Vec<u8>, len: usize) -> isize {
        let offset: isize = 0;
        let res: isize;

        if let Some(dev) = self.chr {
            while offset < len as isize {
                res = dev.tcp_chr_sync_read(offset, &mut buf, len);
                //thread g_usleep(100)
    
                if res == 0 {
                    break;
                }
    
                if res < 0 {
                    return res;
                }
    
                offset += res
            }
    
            offset
        } else {
            0
        }
    }


}