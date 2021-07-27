// Implementing struct in unions

use std::mem;

#[derive(PartialEq)]
pub enum MemberType {
    Request,
    Response,
    Error,
    Cap,
}

pub trait Ptm {
    fn fill(&self, mem:MemberType);
    /* Get size of struct */
    fn get_size(&self) -> usize;
    /* Get which */
    fn get_mem(&self) -> MemberType;
    fn convert_to_bytes(&self) -> Vec<u8>;
}

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptm_res as the first element.
 * ptm_res corresponds to the error code of a command executed by the TPM.
 */
pub type PtmRes = u32;
impl Ptm for PtmRes {
    fn fill(&self, mem: MemberType) {self = &0;}

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.to_be_bytes());
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<u32>()
    }

    fn get_mem(&self) -> MemberType { MemberType::Error }
}

pub type PtmCap = u64;
impl Ptm for PtmCap {
    fn fill(&self, mem: MemberType) {self = &0;}

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.to_be_bytes());
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<u64>()
    }

    fn get_mem(&self) -> MemberType { MemberType::Cap }
}

/* PTM_GET_TPMESTABLISHED: get the establishment bit */
pub struct PtmEstResp {
    pub tpm_result:PtmRes,
    pub bit: u8,
}

pub struct PtmEst {
    mem: MemberType,
    pub resp: PtmEstResp,
}

impl Ptm for PtmEst {
    fn fill(&self, mem: MemberType) {
        self.mem = mem;
        self.resp.tpm_result = 0;
        self.resp.bit = 0;
    }

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend(self.resp.tpm_result.convert_to_bytes());
        buf.push(self.resp.bit);
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<PtmEstResp>()
    }

    fn get_mem(&self) -> MemberType { self.mem }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 */
pub struct PtmSBSResp {
    pub tpm_result: PtmRes,
    pub bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

impl PtmSBSResp {
    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend(self.tpm_result.convert_to_bytes());
        buf.extend(self.bufsize.convert_to_bytes());
        buf.extend(self.minsize.convert_to_bytes());
        buf.extend(self.maxsize.convert_to_bytes());
        buf
    }
}

pub struct PtmSBSReq {
    pub buffersize: u32,
}

pub struct PtmSetBufferSize{
    pub mem: MemberType,
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
}

impl Ptm for PtmSetBufferSize {
    fn fill(&self, mem: MemberType) {
        self.mem = mem;
        self.req = PtmSBSReq {buffersize:0};
        self.resp = PtmSBSResp {tpm_result:0,bufsize:0,minsize:0,maxsize:0}
    }

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        match self.mem {
            MemberType::Request => {
                buf.extend_from_slice(&self.req.buffersize.to_be_bytes());
            }
            MemberType::Response => {
                buf.extend(self.resp.convert_to_bytes());
            }
            _ => {  }
        }
        buf.extend_from_slice(&vec![0; self.get_size()-buf.len()]);
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<PtmSBSResp>()
    }

    fn get_mem(&self) -> MemberType {self.mem}
}

/* PTM_RESET_TPMESTABLISHED: reset establishment bit */
pub struct PtmResEstReq {
    pub loc: u8, /* locality to use */
}
pub struct PtmResEstResp {
    pub tpm_result: PtmRes,
}

pub struct PtmResetEst {
    pub mem: MemberType,
    /* request */
    pub req: PtmResEstReq,
    /* response */
    pub resp: PtmResEstResp,
}

impl Ptm for PtmResetEst {
    fn fill(&self, mem: MemberType) {
        self.req.loc = 0;
        self.resp.tpm_result = 0;
        self.mem = mem;
    }

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        match self.mem {
            MemberType::Request => {
                buf.extend_from_slice(&self.req.loc.to_be_bytes());
            }
            MemberType::Response => {
                buf.extend(self.resp.tpm_result.convert_to_bytes());
            }
            _ => {}
        }
        buf.extend_from_slice(&vec![0; self.get_size()-buf.len()]);
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<PtmResEstResp>()
    }

    fn get_mem(&self) -> MemberType {self.mem}
}

/* PTM_SET_LOCALITY */
pub struct PtmLocReq {
    pub loc: u8,
}
pub struct PtmLocResp {
    pub tpm_result: PtmRes,
}

pub struct PtmLoc {
    pub mem: MemberType,
    /* request */
    pub req: PtmLocReq,
    /* response */
    pub resp: PtmLocResp,
}

impl Ptm for PtmLoc {
    fn fill(&self, mem: MemberType) {
        self.req.loc = 0;
        self.resp.tpm_result = 0;
        self.mem = mem;
    }

    fn convert_to_bytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        match self.mem {
            MemberType::Request => {
                buf.extend_from_slice(&self.req.loc.to_be_bytes());
            }
            MemberType::Response => {
                buf.extend(self.resp.tpm_result.convert_to_bytes());
            }
            _ => {}
        }
        buf.extend_from_slice(&vec![0; self.get_size()-buf.len()]);
        buf
    }

    fn get_size(&self) -> usize {
        mem::size_of::<PtmLocResp>()
    }

    fn get_mem(&self) -> MemberType {self.mem}
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

