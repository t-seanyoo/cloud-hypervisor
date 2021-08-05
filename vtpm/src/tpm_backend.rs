extern crate nix;

use crate::tpm_ioctl::{TPMReqHdr, MemberType, Ptm, PtmRes, PtmCap, PtmEst, PtmSetBufferSize, PtmResetEst, PtmLoc, Commands};
use std::env;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, Read, Write};
use std::ops::BitOrAssign;
use std::path::PathBuf;
use std::thread;
use std::mem;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::ptr;
use std::os::unix::io::{RawFd, AsRawFd};
// use crate::tpm::{TPMDevice};
use crate::char::{CharBackend};
use std::option::Option;
use nix::unistd::{read, write};
use nix::sys::uio::IoVec;
use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag, sendmsg, recvfrom, ControlMessage, MsgFlags };


const TPM_TIS_BUFFER_MAX: usize = 4096;
const TPM_REQ_HDR_SIZE: u32 = 10;
const TPM_RESP_HDR_SIZE: usize = 10;

/* capability flags returned by PTM_GET_CAPABILITY */
const PTM_CAP_INIT: u64 = 1;
const PTM_CAP_SHUTDOWN: u64 = 1 << 1;
const PTM_CAP_GET_TPMESTABLISHED: u64 = 1 << 2;
const PTM_CAP_SET_LOCALITY: u64 = 1 << 3;
const PTM_CAP_HASHING: u64 = 1 << 4;
const PTM_CAP_CANCEL_TPM_CMD: u64 = 1 << 5;
const PTM_CAP_STORE_VOLATILE: u64 = 1 << 6;
const PTM_CAP_RESET_TPMESTABLISHED: u64 = 1 << 7;
const PTM_CAP_GET_STATEBLOB: u64 = 1 << 8;
const PTM_CAP_SET_STATEBLOB: u64 = 1 << 9;
const PTM_CAP_STOP: u64 = 1 << 10;
const PTM_CAP_GET_CONFIG: u64 = 1 << 11;
const PTM_CAP_SET_DATAFD: u64 = 1 << 12;
const PTM_CAP_SET_BUFFERSIZE: u64 = 1 << 13;

/* TPM Functions */

pub fn tpm_util_is_selftest(input: Vec<u8>, in_len: u32) -> bool {
    if in_len >= TPM_REQ_HDR_SIZE {
        let ord: &[u8; 4] = input[6..6+4].try_into().expect("tpm_util_is_selftest: slice with incorrect length");
        return u32::from_ne_bytes(*ord).to_be() == 0x53
    }
    false
}

/* TPM Backend Struct */
#[derive(PartialEq, Copy, Clone)]
pub enum TPMVersion {
    TpmVersionUnspec = 0,
    TpmVersionOneTwo = 1,
    TpmVersionTwo = 2,
}

pub enum TPMType {
    TpmTypeEmulator,
    TpmTypePassthrough,
}

#[derive(Clone)]
pub struct TPMBackendCmd {
    pub locty: i8,
    pub input: Vec<u8>,
    pub input_len: u32,
    pub output: Vec<u8>,
    pub output_len: isize,
    pub selftest_done: bool,
}

impl TPMBackendCmd {
    pub fn set_selftest(&mut self, selftest_done: bool) {
        self.selftest_done = selftest_done;
    }
}

// pub trait TPMBackendObject {
//     fn had_startup_error(&self) -> bool;
//     fn get_version(&self) -> TPMVersion;
//     fn get_tpm_established_flag(&mut self) -> bool;
//     fn get_buffer_size(&mut self) -> usize;
//     fn cancel_cmd(&mut self);
//     fn reset_tpm_established_flag(&mut self) -> isize;
//     fn deliver_request(&mut self, cmd: TPMBackendCmd);
//     fn worker_thread(&mut self) -> isize;
//     fn handle_request(&mut self) -> isize;
//     fn set_locality(&mut self) -> isize;
// }

pub struct TPMEmulator {
    had_startup_error: bool,
    cmd: Option<TPMBackendCmd>,
    version: TPMVersion,
    caps: PtmCap, /* capabilities of the TPM */
    ctrl_chr: CharBackend,
    data_ioc: RawFd,
    // tpm: TPMDevice,
    cur_locty_number: i8, /* last set locality */
    mutex: Arc<Mutex<usize>>,
    established_flag_cached: u8,
    established_flag: u8,
}

impl TPMEmulator {
    pub fn new() -> Self {    
        // tpm_emulator_handle_device_ops
        let mut chardev = CharBackend::new();
        if chardev.chr_fe_init() < 0 {
            //ERROR: Chardev cannot be initialized
        }

        let mut res = Self {
            had_startup_error: false,
            cmd: None,
            version: TPMVersion::TpmVersionTwo, // Only TPM2 available
            caps: 0,
            ctrl_chr: chardev,
            data_ioc: -1,
            // tpm: TPMDevice::init_simulator(),
            cur_locty_number: -1,
            mutex: Arc::new(Mutex::new(0)),
            established_flag_cached: 0,
            established_flag: 0,
        };

        if res.tpm_emulator_prepare_data_fd() < 0 {
            res.had_startup_error = true;
            //ERROR: Data FD Creation Error
        }

        if res.tpm_emulator_probe_caps() | res.tpm_emulator_check_caps() != 0 {
            res.had_startup_error = true;
            // ERROR: tpm-emulator: caps errors
        }

        if !res.get_tpm_established_flag() {
            res.had_startup_error = true;
            // ERROR: tpm-emulator: Could not get the TPM established flag:
        }

        res
    }

    fn tpm_emulator_prepare_data_fd(&mut self) -> isize {
        let mut res: PtmRes = 0;

        let (fd1, fd2) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty())
                     .expect("tpm_emulator: Error making socketpair");
        if self.ctrl_chr.chr_fe_set_msgfd(fd2) < 0 {
            return -1;
        }

        if self.tpm_emulator_ctrlcmd(Commands::CmdSetDatafd, &mut res, 0, mem::size_of::<u32>()) < 0 {
            // error_report("tpm-emulator: Failed to send CMD_SET_DATAFD: %s",
            //          strerror(errno));
            // goto err_exit;
            return -1
        }

        self.data_ioc = fd1;
        if self.ctrl_chr.chr_fe_set_dataioc(fd1) < 0 {
            return -1;
        }

        0
    }

    fn tpm_emulator_probe_caps(&mut self) -> isize { 
        let mut caps = self.caps;
        if self.tpm_emulator_ctrlcmd(Commands::CmdGetCapability, &mut caps, 0, mem::size_of::<u64>()) < 0 {
            return -1;
        }

        self.caps = u64::from_be(self.caps);

        return 0;
    }

    fn tpm_emulator_check_caps(&mut self) -> isize {
        let tpm: String;
        let mut caps: PtmCap = 0;

        /* check for min. required capabilities */
        match self.version {
            TPMVersion::TpmVersionOneTwo => {
                caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN | PTM_CAP_GET_TPMESTABLISHED |
                PTM_CAP_SET_LOCALITY | PTM_CAP_SET_DATAFD | PTM_CAP_STOP |
                PTM_CAP_SET_BUFFERSIZE;
                tpm = "1.2".to_string();
            }
            TPMVersion::TpmVersionTwo => {
                caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN | PTM_CAP_GET_TPMESTABLISHED |
                PTM_CAP_SET_LOCALITY | PTM_CAP_RESET_TPMESTABLISHED |
                PTM_CAP_SET_DATAFD | PTM_CAP_STOP | PTM_CAP_SET_BUFFERSIZE;
                tpm = "2".to_string();
            }
            TPMVersion::TpmVersionUnspec => {
                // error_report("tpm-emulator: TPM version has not been set");
                return -1;
            }
        }

        if self.caps & caps != caps {
            // error_report("tpm-emulator: TPM does not implement minimum set of "
            // "required capabilities for TPM %s (0x%x)", tpm, (int)caps);   
            return -1;
        }
        
        0
    }

    fn tpm_emulator_ctrlcmd<'a>(&mut self, cmd: Commands, msg: &'a mut dyn Ptm, msg_len_in: usize, msg_len_out: usize) -> isize {
        // let dev: TPMDevice = self.tpm;
        let cmd_no = (cmd as u32).to_be_bytes();
        let n: isize = (mem::size_of::<u32>() + msg_len_in) as isize;
        let size_of_cmd_no: usize = mem::size_of::<u32>();

        let mut converted_req = msg.convert_to_reqbytes();

        // let mut input_buf; //Create command buf

        /* Lock object for scope */
        let mut guard = self.mutex.lock().unwrap();
        {
            /* ASSUME COMMAND IS CORRECT UP TO THIS POINT */
            // let command = TPMBackendCmd {
            //     locty: 0,
            //     input: input_buf,
            //     input_len: msg_len_in as u32,
            //     output: Vec::<u8>::new(),
            //     output_len: msg_len_out as u32,
            // };
            
            // let len = match dev.perform_work_from_cmd(&mut command) {
            //     Ok(len) => len,
            //         Err(err) => {
            //             std::mem::drop(guard);
            //             return -1;
            //         }
            // };

            let mut buf = Vec::<u8>::with_capacity(n as usize);
            
            let mut dst_ptr = buf.as_mut_ptr();
            let cmdno_ptr = cmd_no.as_ptr();
            //COnfirm if buffer is less than size
            unsafe { ptr::copy_nonoverlapping(cmdno_ptr, dst_ptr, size_of_cmd_no)};

            let msg_ptr = converted_req.as_ptr();
            dst_ptr = unsafe {dst_ptr.offset(size_of_cmd_no as isize)};
            unsafe { ptr::copy_nonoverlapping(msg_ptr, dst_ptr, msg_len_in) };
            // memcpy(buf, &cmd_no, sizeof(cmd_no));
            // memcpy(buf + sizeof(cmd_no), msg, msg_len_in);

            let mut res = self.ctrl_chr.chr_fe_write_all(&mut buf, n as usize);
            if res <= 0 {
                std::mem::drop(guard);
                return -1;
            }

            let mut output = [0 as u8; TPM_TIS_BUFFER_MAX];

            if msg_len_out != 0 {
                res = self.ctrl_chr.chr_fe_read_all(&mut output, msg_len_out);
                if res <= 0 {
                    std::mem::drop(guard);
                    return -1;
                }
                msg.convert_to_ptm(&output);
            } else {
                msg.set_mem(MemberType::Response);
            }
        }
        std::mem::drop(guard);
        0
    }

    fn tpm_emulator_stop_tpm(&mut self) -> isize {
        let mut res: PtmRes = 0;

        if self.tpm_emulator_ctrlcmd(Commands::CmdStop, &mut res, 0, mem::size_of::<u32>()) < 0 {
            // error_report("tpm-emulator: Could not stop TPM: %s", strerror(errno));
            return -1;
        }
        
        res = u32::from_be(res);
        if res != 0 {
            // error_report("tpm-emulator: TPM result for CMD_STOP: 0x%x %s", res,
            //          tpm_emulator_strerror(res));
            return -1;
        }

        0
    }

    fn unix_tx_bufs(&mut self) -> isize {
        let mut is_selftest: bool = false;
        if let Some(ref mut cmd) = self.cmd {
            if cmd.selftest_done {
                cmd.selftest_done = false;
                let input = &cmd.input;
                is_selftest = tpm_util_is_selftest((&input).to_vec(), cmd.input_len);
            }
    
            //qio_channel_write_all
            let iov = &[IoVec::from_slice(cmd.input.as_slice())];
            let ret = sendmsg(self.data_ioc, iov, &[], MsgFlags::empty(), None).expect("char.rs: ERROR ON send_full sendmsg") as isize;
            if ret != 0 {
                return -1
            }
    
            //qio_channel_read_all
            let (size, sock) = recvfrom(self.data_ioc, &mut cmd.output).expect("unix_tx_bufs: sync_read recvmsg error");
            if size < 0 {
                return -1
            }
    
            if is_selftest {
                let errcode: &[u8; 4] = cmd.output[6..6+4].try_into().expect("tpm_util_is_selftest: slice with incorrect length");
                cmd.selftest_done = u32::from_ne_bytes(*errcode).to_be() == 0;
            }
        }

        0
    }

    fn tpm_emulator_set_buffer_size(&mut self, wantedsize: usize, actualsize: &mut usize) -> isize {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new();

        if self.tpm_emulator_stop_tpm() < 0 {
            return -1;
        }

        psbs.req.buffersize = (wantedsize as u32).to_be();

        if self.tpm_emulator_ctrlcmd(Commands::CmdSetBufferSize, &mut psbs, mem::size_of::<u32>(), 4*mem::size_of::<u32>()) < 0 {
            //error_report("tpm-emulator: Could not set buffer size: %s", strerror(errno));
            return -1;
        }

        psbs.tpm_result = u32::from_be(psbs.tpm_result);

        if psbs.tpm_result != 0 {
            // error_report("tpm-emulator: TPM result for set buffer size : 0x%x %s",
            //          psbs.u.resp.tpm_result,
            //          tpm_emulator_strerror(psbs.u.resp.tpm_result));
            return -1;
        }

        if *actualsize != 0 {
            *actualsize = u32::from_be(psbs.resp.bufsize) as usize;
        }
        
        0
    }
// }

// impl TPMBackendObject for TPMEmulator {
    pub fn had_startup_error(&self) -> bool {
        self.had_startup_error
    }

    pub fn get_version(&self) -> TPMVersion {
        self.version
    }

    pub fn get_tpm_established_flag(&mut self) -> bool {
        let mut est: PtmEst = PtmEst::new();

        if self.established_flag_cached == 1 {
            return self.established_flag == 1
        }

        if self.tpm_emulator_ctrlcmd(Commands::CmdGetTpmEstablished, &mut est, 0, 2*mem::size_of::<u32>()) < 0 {
            // error_report("tpm-emulator: Could not get the TPM established flag: %s",
            //         strerror(errno));
            return false;
        }

        self.established_flag_cached = 1;
        self.established_flag = (est.resp.bit != 0) as u8;

        self.established_flag == 1
    }

    pub fn reset_tpm_established_flag(&mut self) -> isize {
        let mut reset_est: PtmResetEst = PtmResetEst::new();

        /* only a TPM 2.0 will support this */
        if self.version != TPMVersion::TpmVersionTwo {
            return 0
        }

        reset_est.req.loc = self.cur_locty_number;
        if self.tpm_emulator_ctrlcmd(Commands::CmdResetTpmEstablished, &mut reset_est, mem::size_of::<u32>(), mem::size_of::<u32>()) < 0 {
            // error_report("tpm-emulator: Could not reset the establishment bit: %s",
            //          strerror(errno));
            return -1;
        }

        let res = u32::from_be(reset_est.tpm_result);
        if res != 0 {
            // error_report(
            //     "tpm-emulator: TPM result for rest established flag: 0x%x %s",
            //     res, tpm_emulator_strerror(res));
            return -1
        }

        self.established_flag_cached = 0;

        0
    }

    pub fn get_buffer_size(&mut self) -> usize {
        let mut actual_size: usize = 0;

        if self.tpm_emulator_set_buffer_size(0, &mut actual_size) < 0 {
            return 4096;
        }

        actual_size
    }

    pub fn cancel_cmd(&mut self) {
        let mut res: PtmRes = 0;

        // If Emulator implements all caps
        if !((self.caps & ((1 << 5))) == ((1 << 5))) {
            return;
        }

        /* FIXME: make the function non-blocking, or it may block a VCPU */
        if self.tpm_emulator_ctrlcmd(Commands::CmdCancelTpmCmd, &mut res, 0, mem::size_of::<u32>()) < 0 {
            // error_report("tpm-emulator: Could not cancel command: %s",strerror(errno));
        } else if res != 0 {
            // error_report("tpm-emulator: Failed to cancel TPM: 0x%x", be32_to_cpu(res));
        }
    }

    pub fn set_locality(&mut self) -> isize {
        let mut loc: PtmLoc = PtmLoc::new();
        let cmd = match self.cmd.clone() {
            None => return -1,
            Some(c) => {c}
        };
        
        if self.cur_locty_number == cmd.locty {
            return 0;
        }

        loc.req.loc = cmd.locty;

        if self.tpm_emulator_ctrlcmd(Commands::CmdSetLocality, &mut loc, mem::size_of::<u32>(), mem::size_of::<u32>()) < 0 {
            // error_setg(errp, "tpm-emulator: could not set locality : %s",
            //    strerror(errno));
            return -1
        }

        loc.tpm_result = u32::from_be(loc.tpm_result);
        if loc.tpm_result != 0 {
            // error_setg(errp, "tpm-emulator: TPM result for set locality : 0x%x",
            //    loc.u.resp.tpm_result);
            return -1
        }

        self.cur_locty_number = cmd.locty;

        0

        

    }


    pub fn handle_request(&mut self) -> isize {
        if let Some(ref mut cmd) = self.cmd {
            if self.set_locality() < 0 || self.unix_tx_bufs() < 0 {
                return -1
            }
    
            return 0
        }
        -1        
    }

    pub fn worker_thread(&mut self) -> isize {
        let err = self.handle_request();
        if err < 0 {
            // error_report_err(err);
            return -1
        }
        0
    }

    pub fn deliver_request(&mut self, cmd: TPMBackendCmd) {
        //tpm_backend_deliver_request
        if self.cmd.is_none() {
            self.cmd = Some(cmd);

            //Start Worker Thread //IMPLEMENT
        }
        //ERROR Command already present
    }
}

pub struct TPMBackend {
    pub backend_type: TPMType,
    pub backend: TPMEmulator,
}

impl TPMBackend {
    pub fn new() -> Self {
        Self {
            backend_type: TPMType::TpmTypeEmulator,
            backend: TPMEmulator::new(),
        }
    }
}