pub trait Ptm {
    fn convert_to_bytes(&self) -> Vec<u8>;
}

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptm_res as the first element.
 * ptm_res corresponds to the error code of a command executed by the TPM.
 */
pub type Ptmres = u32;
impl Ptm for Ptmres {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.to_be_bytes());
        buf
    }
}

pub type Ptmcap = u64;
impl Ptm for Ptmcap {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.to_be_bytes());
        buf
    }
}

/* PTM_GET_TPMESTABLISHED: get the establishment bit */
pub struct Ptmest {
    tpm_result:Ptmres,
    pub bit: u8,
}
impl Ptm for Ptmest {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend(self.tpm_result.convert_to_bytes());
        buf.push(self.bit);
        buf
    }
}

pub struct Ptmresp {
    pub tpm_result: Ptmres,
    pub bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

impl Ptm for Ptmresp {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend(self.tpm_result.convert_to_bytes());
        buf.extend(self.bufsize.convert_to_bytes());
        buf.extend(self.minsize.convert_to_bytes());
        buf.extend(self.maxsize.convert_to_bytes());
        buf
    }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 */
pub struct PtmSetBufferSize{
    /* request */
    pub req_bufsize: u32,
    /* response */
    pub resp: Ptmresp,
}

impl Ptm for PtmSetBufferSize {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend(self.req_bufsize.convert_to_bytes());
        buf.extend(self.resp.convert_to_bytes());
        buf
    }
}


/*
 * Commands used by the non-CUSE TPMs
 *
 * All messages container big-endian data.
 *
 * The return messages only contain the 'resp' part of the unions
 * in the data structures above. Besides that the limits in the
 * buffers above (ptm_hdata:u.req.data and ptm_get_state:u.resp.data
 * and ptm_set_state:u.req.data) are 0xffffffff.
 */
pub enum Commands {
    CmdGetCapability = 1,
    CmdInit,
    CmdShutdown,
    CmdGetTpmEstablished,
    CmdSetLocality,
    CmdHashStart,
    CmdHashData,
    CmdHashEnd,
    CmdCancelTpmCmd,
    CmdStoreVolatile,
    CmdResetTpmEstablished,
    CmdGetStateBlob,
    CmdSetStateBlob,
    CmdStop,
    CmdGetConfig,
    CmdSetDatafd,
    CmdSetBufferSize,
}

