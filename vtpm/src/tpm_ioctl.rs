// Implementing struct in unions

use std::mem;
use byteorder::{BigEndian, ReadBytesExt}; // 1.2.7

#[derive(PartialEq)]
pub enum MemberType {
    Request,
    Response,
    Error,
    Cap,
}

pub fn set_response<'a>(ptm: &'a dyn Ptm, buf: &[u8]) -> usize {
    ptm.set_mem(MemberType::Response);
    let res = &buf[0..=3];
    ptm.set_res(res.read_u32::<BigEndian>().unwrap());
    4
}

pub trait Ptm {
    fn fill(&self, mem:MemberType);
    /* Get which */
    fn get_mem(&self) -> MemberType;
    /* Convert to buffer with size of MAX(Req, Res) */
    fn convert_to_reqbytes(&self) -> Vec<u8>;
    fn convert_to_ptm(&self, buf: &[u8]);
    fn set_mem(&self, mem: MemberType);
    fn set_res(&self, res: u32);
}

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptm_res as the first element.
 * ptm_res corresponds to the error code of a command executed by the TPM.
 */
pub type PtmRes = u32;
impl Ptm for PtmRes {
    fn fill(&self, mem: MemberType) {self = &0;}

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { MemberType::Error }

    fn convert_to_ptm(&self, buf: &[u8]) {
        self = &buf.read_u32::<BigEndian>().unwrap();
    }

    fn set_mem(&self, mem:MemberType) {}

    fn set_res(&self, res: u32) {}
}

pub type PtmCap = u64;
impl Ptm for PtmCap {
    fn fill(&self, mem: MemberType) {self = &0;}

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { MemberType::Cap }

    fn convert_to_ptm(&self, buf: &[u8]) {
        self = &buf.read_u64::<BigEndian>().unwrap();
    }

    fn set_mem(&self, mem:MemberType) {}

    fn set_res(&self, res: u32) {}
}

/* PTM_GET_TPMESTABLISHED: get the establishment bit */
pub struct PtmEstResp {
    pub bit: u8,
}

pub struct PtmEst {
    mem: MemberType,
    pub resp: PtmEstResp,
    pub tpm_result:PtmRes,
}

impl Ptm for PtmEst {
    fn fill(&self, mem: MemberType) {
        self.mem = mem;
        self.tpm_result = 0;
        self.resp.bit = 0;
    }

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { self.mem }

    fn convert_to_ptm(&self, buf: &[u8]) {
        let n = set_response(self, buf);
        let bit = &buf[n];
        self.resp.bit = *bit;
    }

    fn set_mem(&self, mem:MemberType) { self.mem = mem }

    fn set_res(&self, res: u32) { self.tpm_result = res }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 */
pub struct PtmSBSReq {
    pub buffersize: u32,
}

pub struct PtmSBSResp {
    pub bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

pub struct PtmSetBufferSize{
    pub mem: MemberType,
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
    pub tpm_result: PtmRes,
}

impl Ptm for PtmSetBufferSize {
    fn fill(&self, mem: MemberType) {
        self.mem = mem;
        self.req = PtmSBSReq {buffersize:0};
        self.resp = PtmSBSResp {bufsize:0,minsize:0,maxsize:0};
        self.tpm_result = 0;
    }

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.buffersize.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&self, buf: &[u8]) {
        let n = set_response(self, buf);

        let bufsize = &buf[n..=n+3];
        n +=3;
        self.resp.bufsize = bufsize.read_u32::<BigEndian>().unwrap();

        let minsize = &buf[n..=n+3];
        n +=3;
        self.resp.minsize = minsize.read_u32::<BigEndian>().unwrap();

        let maxsize = &buf[n..=n+3];
        n +=3;
        self.resp.maxsize = maxsize.read_u32::<BigEndian>().unwrap();
    }

    fn set_mem(&self, mem:MemberType) { self.mem = mem }

    fn set_res(&self, res: u32) { self.tpm_result = res }
}

/* PTM_RESET_TPMESTABLISHED: reset establishment bit */
pub struct PtmResEstReq {
    pub loc: u8, /* locality to use */
}

pub struct PtmResetEst {
    pub mem: MemberType,
    /* request */
    pub req: PtmResEstReq,
    /* response */
    pub tpm_result: PtmRes,
}

impl Ptm for PtmResetEst {
    fn fill(&self, mem: MemberType) {
        self.req.loc = 0;
        self.tpm_result = 0;
        self.mem = mem;
    }

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.loc.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&self, buf: &[u8]) {
        set_response(self, buf);
    }

    fn set_mem(&self, mem:MemberType) { self.mem = mem }

    fn set_res(&self, res: u32) { self.tpm_result = res }
}

/* PTM_SET_LOCALITY */
pub struct PtmLocReq {
    pub loc: u8,
}

pub struct PtmLoc {
    pub mem: MemberType,
    /* request */
    pub req: PtmLocReq,
    /* response */
    pub tpm_result: PtmRes,
}

impl Ptm for PtmLoc {
    fn fill(&self, mem: MemberType) {
        self.req.loc = 0;
        self.tpm_result = 0;
        self.mem = mem;
    }

    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.loc.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&self, buf: &[u8]) {
        set_response(self, buf);
    }

    fn set_mem(&self, mem:MemberType) { self.mem = mem }

    fn set_res(&self, res: u32) { self.tpm_result = res }
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

