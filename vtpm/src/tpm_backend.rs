use crate::tpm_ioctl::{MemberType, Ptm, PtmRes, PtmCap, PtmEst, PtmSetBufferSize, PtmResetEst, PtmLoc, Commands};
use crate::char::{CharBackend};
use std::mem;
use std::sync::{Arc, Mutex};
use std::ptr;

const TPM_TIS_BUFFER_MAX: usize = 4096;

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

/* TPM Backend Struct */
#[derive(PartialEq)]
enum TPMVersion {
    TpmVersionUnspec = 0,
    TpmVersionOneTwo = 1,
    TpmVersionTwo = 2,
}

enum TPMType {
    TpmTypeEmulator,
    TpmTypePassthrough,
}

pub struct TPMBackendCmd {
    locty: u8,
    input: [u8; TPM_TIS_BUFFER_MAX],
    input_len: u32,
    output: [u8; TPM_TIS_BUFFER_MAX],
    output_len: u32,
}

pub trait TPMBackendObject {
    fn had_startup_error(&self) -> bool;
    fn get_version(&self) -> TPMVersion;
    fn get_tpm_established_flag(&self) -> bool;
    fn get_buffer_size(&self) -> usize;
    fn cancel_cmd(&self);
    fn reset_tpm_established_flag(&self) -> isize;
    fn deliver_request(&self, cmd: TPMBackendCmd);
    fn worker_thread(&self) -> isize;
    fn handle_request(&self) -> isize;
    fn set_locality(&self) -> isize;
}

pub struct TPMEmulator {
    had_startup_error: bool,
    cmd: Option<TPMBackendCmd>,
    version: TPMVersion,
    caps: PtmCap, /* capabilities of the TPM */
    ctrl_chr: CharBackend,
    cur_locty_number: u8, /* last set locality */
    mutex: Arc<Mutex<usize>>,
    established_flag_cached: u8,
    established_flag: u8,
}

impl TPMEmulator {
    pub fn new() -> Self {    
        // tpm_emulator_handle_device_ops
        let res = Self { //IMPLEMENT
            had_startup_error: false,
            cmd: None,
            version: TPMVersion::TpmVersionTwo, // Only TPM2 available
            caps: 0,
            ctrl_chr: CharBackend::new(),
            cur_locty_number: u8::MAX,
            mutex: Arc::new(Mutex::new(0)),
            established_flag_cached: 0,
            established_flag: 0,
        };

        if res.tpm_emulator_probe_caps() | res.tpm_emulator_check_caps() != 0 {
            res.had_startup_error = true;
            // ERROR: tpm-emulator: caps errors
        }

        if !res.get_tpm_established_flag() {
            res.had_startup_error = true;
            // ERROR: tpm-emulator: Could not get the TPM established flag:
        }

        if !res.ctrl_chr.chr_fe_init() {
            res.had_startup_error = true;
            // ERROR: tpm-emulator: Couldn not start Chardev
        }

        res
    }

    fn tpm_emulator_probe_caps(&self) -> isize { 
        if self.tpm_emulator_ctrlcmd(Commands::CmdGetCapability, &self.caps, 0, self.caps.get_size()) < 0 {
            return -1;
        }

        self.caps = u64::from_be(self.caps);

        return 0;
    }

    fn tpm_emulator_check_caps(&self) -> isize {
        let tpm: String;
        let caps: PtmCap = 0;

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

    fn tpm_emulator_ctrlcmd<'a>(&self, cmd: Commands, msg: &'a dyn Ptm, msg_len_in: usize, msg_len_out: usize) -> isize {
        let dev: CharBackend = self.ctrl_chr;
        let cmd_no = (cmd as u32).to_be_bytes();
        let n: isize = (mem::size_of::<u32>() + msg_len_in) as isize;
        let size_of_cmd_no: usize = mem::size_of::<u32>();

        let mut converted_msg = msg.convert_to_bytes();

        /* Lock object for scope */
        let mut guard = self.mutex.lock().unwrap();
        {
            let mut buf = Vec::<u8>::with_capacity(n as usize);
            
            let dst_ptr = buf.as_mut_ptr();
            let cmdno_ptr = cmd_no.as_ptr();
            ptr::copy_nonoverlapping(cmdno_ptr, dst_ptr, size_of_cmd_no);

            let msg_ptr = converted_msg.as_ptr();
            dst_ptr = dst_ptr.offset(size_of_cmd_no as isize);
            ptr::copy_nonoverlapping(msg_ptr, dst_ptr, msg_len_in);
            // memcpy(buf, &cmd_no, sizeof(cmd_no));
            // memcpy(buf + sizeof(cmd_no), msg, msg_len_in);

            n = dev.chr_fe_write_all(buf, buf.len());
            if n <= 0 {
                std::mem::drop(guard);
                return -1;
            }

            if msg_len_out != 0 {
                n = dev.chr_fe_read_all(&mut converted_msg, msg_len_out);
                if n <= 0 {
                    std::mem::drop(guard);
                    return -1;
                }
            }
        }
        std::mem::drop(guard);
        0
    }

    fn tpm_emulator_stop_tpm(&self) -> isize {
        let res: PtmRes = 0;

        if self.tpm_emulator_ctrlcmd(Commands::CmdStop, &res, 0, res.get_size()) < 0 {
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

    fn tpm_emulator_set_buffer_size(&self, wantedsize: usize, actualsize: &mut usize) -> isize {
        let psbs: PtmSetBufferSize;
        psbs.fill(MemberType::Request);

        if self.tpm_emulator_stop_tpm() < 0 {
            return -1;
        }

        psbs.req.buffersize = (wantedsize as u32).to_be();

        if self.tpm_emulator_ctrlcmd(Commands::CmdSetBufferSize, &psbs, mem::size_of::<u32>(), psbs.get_size()) < 0 {
            //error_report("tpm-emulator: Could not set buffer size: %s", strerror(errno));
            return -1;
        }

        psbs.resp.tpm_result = u32::from_be(psbs.resp.tpm_result);

        if psbs.resp.tpm_result != 0 {
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
}

impl TPMBackendObject for TPMEmulator {
    fn had_startup_error(&self) -> bool {
        self.had_startup_error
    }

    fn get_version(&self) -> TPMVersion {
        self.version
    }

    fn get_tpm_established_flag(&self) -> bool {
        let est: PtmEst;
        est.fill(MemberType::Response);

        if self.established_flag_cached == 1 {
            return self.established_flag == 1
        }

        if self.tpm_emulator_ctrlcmd(Commands::CmdGetTpmEstablished, &est, 0, est.get_size()) < 0 {
            // error_report("tpm-emulator: Could not get the TPM established flag: %s",
            //         strerror(errno));
            return false;
        }

        self.established_flag_cached = 1;
        self.established_flag = (est.resp.bit != 0) as u8;

        self.established_flag == 1
    }

    fn reset_tpm_established_flag(&self) -> isize {
        let reset_est: PtmResetEst;
        reset_est.fill(MemberType::Request);
        let res: PtmRes = 0;

        /* only a TPM 2.0 will support this */
        if self.version != TPMVersion::TpmVersionTwo {
            return 0
        }

        reset_est.req.loc = self.cur_locty_number;
        if self.tpm_emulator_ctrlcmd(Commands::CmdResetTpmEstablished, &reset_est, reset_est.get_size(), reset_est.get_size()) < 0 {
            // error_report("tpm-emulator: Could not reset the establishment bit: %s",
            //          strerror(errno));
            return -1;
        }

        res = u32::from_be(reset_est.resp.tpm_result);
        if res != 0 {
            // error_report(
            //     "tpm-emulator: TPM result for rest established flag: 0x%x %s",
            //     res, tpm_emulator_strerror(res));
            return -1
        }

        self.established_flag_cached = 0;

        0
    }

    fn get_buffer_size(&self) -> usize {
        let actual_size: usize;

        if self.tpm_emulator_set_buffer_size(0, &mut actual_size) < 0 {
            return 4096;
        }

        actual_size
    }

    fn cancel_cmd(&self) {
        let res: PtmRes = 0;

        // If Emulator implements all caps
        if !((self.caps & ((1 << 5))) == ((1 << 5))) {
            return;
        }

        /* FIXME: make the function non-blocking, or it may block a VCPU */
        if self.tpm_emulator_ctrlcmd(Commands::CmdCancelTpmCmd, &res, 0, res.get_size()) < 0 {
            // error_report("tpm-emulator: Could not cancel command: %s",strerror(errno));
        } else if res != 0 {
            // error_report("tpm-emulator: Failed to cancel TPM: 0x%x", be32_to_cpu(res));
        }
    }

    fn set_locality(&self) -> isize {
        let loc: PtmLoc;
        loc.fill(MemberType::Request);
        
        if let Some(cmd) = self.cmd {
            if self.cur_locty_number == cmd.locty {
                return 0;
            }

            loc.req.loc = cmd.locty;

            if self.tpm_emulator_ctrlcmd(Commands::CmdSetLocality, &loc, loc.get_size(), loc.get_size())
    
        } else {
            return -1
        }

        

    }

    fn handle_request(&self) -> isize {
        if self.set_locality() < 0 || self.unix_tx_bufs() < 0 {
            self.tpm_util_write_fatal_error_response();
            return -1;
        }

        return 0
    }

    fn worker_thread(&self) -> isize {
        let err = self.handle_request();
        if err < 0 {
            // error_report_err(err);
            return -1
        }
        0
    }

    fn deliver_request(&self, cmd: TPMBackendCmd) {
        //tpm_backend_deliver_request
        match self.cmd {
            Some(a) => {
                // error_report("There is a TPM request pending");
                return;
            }
            None => {
                self.cmd = Some(cmd);

            }
        }
    }
}

pub struct TPMBackend {
    backend_type: TPMType,
    backend: Box<dyn TPMBackendObject>,
}

impl TPMBackend {
    pub fn new() -> Self {
        Self {
            backend_type: TPMType::TpmTypeEmulator,
            backend: Box::new(TPMEmulator::new()),
        }
    }
}