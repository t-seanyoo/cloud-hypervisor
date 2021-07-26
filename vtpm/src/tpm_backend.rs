use crate::tpm_ioctl::{Ptm, Ptmres, Ptmcap, Ptmest, PtmSetBufferSize, Ptmresp, Commands};
use crate::char::{CharBackend};
use std::mem;
use std::sync::{Arc, Mutex};

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
    fn reset_tpm_established_flag() -> usize;
}

pub struct TPMEmulator {
    had_startup_error: bool,
    cmd: Option<TPMBackendCmd>,
    version: TPMVersion,
    caps: Ptmcap, /* capabilities of the TPM */
    ctrl_chr: CharBackend,
    cur_locty_number: u8, /* last set locality */
    mutex: Arc<Mutex<usize>>,
    established_flag_cached: u8,
    established_flag: u8,
}

impl TPMEmulator {
    pub fn new() -> Self {    
        let res = Self { //IMPLEMENT
            had_startup_error: false,
            cmd: None,
            version: TPMVersion::TpmVersionTwo, // Only TPM2 available
            caps: 0,
            ctrl_chr: ,
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

        res
    }

    fn tpm_emulator_probe_caps(&self) -> isize { 
        if self.tpm_emulator_ctrlcmd(Commands::CmdGetCapability, &self.caps, 0, mem::size_of::<Ptmcap>()) < 0 {
            return -1;
        }

        self.caps = u64::from_be(self.caps);

        return 0;
    }

    fn tpm_emulator_check_caps(&self) -> isize {
        let tpm: String;
        let caps: Ptmcap = 0;

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
        let cmd_no: u32 = (cmd as u32).to_be();
        let n: usize = mem::size_of::<u32>() + msg_len_in;
        let buf: u8;

        let converted_msg = msg.convert_to_bytes();

        /* Lock object for scope */
        let mut guard = self.mutex.lock().unwrap();
        {
            let mut buf = Vec::<u8>::new();
            buf.extend_from_slice(&cmd_no.to_be_bytes());
            buf.extend(converted_msg);

            n = dev.chr_fe_write_all(buf, buf.len());
            if n <= 0 {
                std::mem::drop(guard);
                return -1;
            }

            if msg_len_out != 0 {
                n = dev.chr_fe_read_all(converted_msg, msg_len_out);
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
        let res: Ptmres;
        if self.tpm_emulator_ctrlcmd(Commands::CmdStop, &res, 0, mem::size_of::<Ptmres>()) < 0 {
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

        if self.tpm_emulator_stop_tpm() < 0 {
            return -1;
        }

        psbs.req_bufsize = (wantedsize as u32).to_be();

        if self.tpm_emulator_ctrlcmd(Commands::CmdSetBufferSize, &psbs, mem::size_of::<u32>(), mem::size_of::<Ptmresp>()) < 0 {
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
        let est: Ptmest;

        if self.established_flag_cached == 1 {
            return self.established_flag == 1
        }

        if self.tpm_emulator_ctrlcmd(Commands::CmdGetTpmEstablished, &est, 0, mem::size_of::<Ptmest>()) < 0 {
            // error_report("tpm-emulator: Could not get the TPM established flag: %s",
            //         strerror(errno));
            return false;
        }

        self.established_flag_cached = 1;
        self.established_flag = (est.bit != 0) as u8;

        self.established_flag == 1
    }

    fn reset_tpm_established_flag() -> {
        //IMPLEMENT
    }

    fn get_buffer_size(&self) -> usize {
        let actual_size: usize;

        if self.tpm_emulator_set_buffer_size(0, &mut actual_size) < 0 {
            return 4096;
        }

        actual_size
    }

    fn cancel_cmd(&self) {
        let res: Ptmres;

        // If Emulator implements all caps
        if !((self.caps & ((1 << 5))) == ((1 << 5))) {
            return;
        }

        /* FIXME: make the function non-blocking, or it may block a VCPU */
        if self.tpm_emulator_ctrlcmd(Commands::CmdCancelTpmCmd, &res, 0, mem::size_of::<Ptmres>()) < 0 {
            // error_report("tpm-emulator: Could not cancel command: %s",strerror(errno));
        } else if res != 0 {
            // error_report("tpm-emulator: Failed to cancel TPM: 0x%x", be32_to_cpu(res));
        }
    }
}

pub struct TPMBackend<'a> {
    backend_type: TPMType,
    backend: &'a dyn TPMBackendObject,
}

impl<'a> TPMBackend<'a> {
    pub fn new() -> Self {
        Self {
            backend_type: TPMType::TpmTypeEmulator,
            backend: &TPMEmulator::new(),
        }
    }
}