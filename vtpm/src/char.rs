use crate::chario::{IOChannel};

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
    write_msgfds_num: ,
}

impl SocketCharDev {
    pub fn new() -> Self {
        Self {
        }
    }

    pub fn chr_write(&self, buf: Vec<u8>, len: usize) {
        if self.state == TCPChardevState::TcpChardevStateConnected {
            let ret = self.ioc.io_channel_send_full(buf, len, self.write_msgfds, self.write_msgfds_num);
        }
    }
}

pub struct CharBackend {
    chr: Option<SocketCharDev>
}

impl CharBackend {
    pub fn new() -> Self {
        Self {
            chr: ,
        }
    }

    pub fn chr_fe_init(&self, s: SocketCharDev) -> bool {
        
    }

    pub fn chr_fe_write_all(&self, buf: Vec<u8>, len: usize) -> usize {
        match self.chr {
            None => return 0,
            Some(x) => self.chr_write
        }
    }

    pub fn chr_fe_read_all(&self, msg: Vec<u8>, msg_len_in: usize) -> usize {
        
    }


}