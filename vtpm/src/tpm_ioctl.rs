// Implementing struct in unions

use byteorder::{BigEndian, ReadBytesExt}; // 1.2.7
use std::convert::TryInto;

#[derive(Debug)]
pub struct TPMReqHdr {
    tag: u16,
    len: u32,
    ordinal: u32,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum MemberType {
    Request,
    Response,
    Error,
    Cap,
}

pub trait Ptm {
    /* Get which */
    fn get_mem(&self) -> MemberType;
    /* Convert to buffer with size of MAX(Req, Res) */
    fn convert_to_reqbytes(&self) -> Vec<u8>;
    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize;
    fn set_mem(&mut self, mem: MemberType);
    fn set_res(&mut self, res: u32);
}

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptm_res as the first element.
 * ptm_res corresponds to the error code of a command executed by the TPM.
 */
pub type PtmRes = u32;

impl Ptm for PtmRes {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { MemberType::Error }

    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize {
        if buf.len() < 4 {
            return -1
        }
        let num_buf: &[u8; 4] = buf[0..4].try_into().expect("PtmRes convert to req");
        let num: &mut u32 = &mut u32::from_be_bytes(*num_buf);
        *self = *num;
        0
    }

    fn set_mem(&mut self, _mem:MemberType) {}

    fn set_res(&mut self, _res: u32) {}
}

pub type PtmCap = u64;
impl Ptm for PtmCap {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { MemberType::Cap }

    fn convert_to_ptm(&mut self, mut buf: &[u8]) -> isize {
        if buf.len() < 8 {
            return -1
        }
        *self = buf.read_u64::<BigEndian>().unwrap();
        0
    }

    fn set_mem(&mut self, _mem:MemberType) {}

    fn set_res(&mut self, _res: u32) {}
}

/* PTM_GET_TPMESTABLISHED: get the establishment bit */
#[derive(Debug)]
pub struct PtmEstResp {
    pub bit: u8,
}

#[derive(Debug)]
pub struct PtmEst {
    mem: MemberType,
    pub resp: PtmEstResp,
    pub tpm_result: PtmRes,
}

impl PtmEst {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            tpm_result: 0,
            resp: PtmEstResp {
                bit: 0,
            },
        }
    }
}

impl Ptm for PtmEst {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { self.mem }

    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize{
        if buf.len() < 5 {
            return -1
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        let bit = &buf[4];
        self.resp.bit = *bit;
        0
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 */
#[derive(Debug)]
pub struct PtmSBSReq {
    pub buffersize: u32,
}

#[derive(Debug)]
pub struct PtmSBSResp {
    pub bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

#[derive(Debug)]
pub struct PtmSetBufferSize{
    pub mem: MemberType,
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
    pub tpm_result: PtmRes,
}

impl PtmSetBufferSize {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            req: PtmSBSReq {buffersize:0},
            resp: PtmSBSResp {bufsize:0,minsize:0,maxsize:0},
            tpm_result: 0,
        }
    }
}

impl Ptm for PtmSetBufferSize {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.buffersize.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize {
        if buf.len() < 16 {
            return -1
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        
        let mut bufsize = &buf[4..8];
        self.resp.bufsize = bufsize.read_u32::<BigEndian>().unwrap();

        let mut minsize = &buf[8..12];
        self.resp.minsize = minsize.read_u32::<BigEndian>().unwrap();

        let mut maxsize = &buf[12..16];
        self.resp.maxsize = maxsize.read_u32::<BigEndian>().unwrap();

        0
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}

/* PTM_RESET_TPMESTABLISHED: reset establishment bit */
#[derive(Debug)]
pub struct PtmResEstReq {
    pub loc: i8, /* locality to use */
}

#[derive(Debug)]
pub struct PtmResetEst {
    pub mem: MemberType,
    /* request */
    pub req: PtmResEstReq,
    /* response */
    pub tpm_result: PtmRes,
}

impl PtmResetEst {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            req: PtmResEstReq {
                loc: 0,
            },
            tpm_result:0,
            
        }
    }
}

impl Ptm for PtmResetEst {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.loc.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize{
        if buf.len() < 4 {
            return -1
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        0
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}

/* PTM_SET_LOCALITY */
#[derive(Debug)]
pub struct PtmLocReq {
    pub loc: i8,
}

#[derive(Debug)]
pub struct PtmLoc {
    pub mem: MemberType,
    /* request */
    pub req: PtmLocReq,
    /* response */
    pub tpm_result: PtmRes,
}

impl PtmLoc {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            req: PtmLocReq {
                loc: 0,
            },
            tpm_result: 0,
        }
    }
}

impl Ptm for PtmLoc {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.loc.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&mut self, buf: &[u8]) -> isize{
        if buf.len() < 4 {
            return -1
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        
        0
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
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

#[test]
/** tpm_ioctl Testing */
/* PtmRes */
fn test_ptmres() {
    println!("PtmRes Testing:");
    let mut res: PtmRes = 144;
    println!("PtmRes- original value: {}", res);
    println!("PtmRes- convert_to_reqbytes: {:?}", res.convert_to_reqbytes());
    assert_eq!(res.convert_to_reqbytes(), []);
    println!("PtmRes- get_mem: {:?}", res.get_mem());
    assert_eq!(res.get_mem(), MemberType::Error);
    let buf: &[u8] = &[0,0,0,1,1,4];
    res.convert_to_ptm(&buf);
    println!("PtmRes- convert_to_ptm: {:?}", res);
}

/* PtmCap */
fn test_ptmcap() {
    println!("PtmCap Testing");
    let mut cap: PtmCap = 300;
    println!("PtmCap- original value: {}", cap);
    println!("PtmCap- convert_to_reqbytes: {:?}", cap.convert_to_reqbytes());
    assert_eq!(cap.convert_to_reqbytes(), []);
    println!("PtmCes- get_mem: {:?}", cap.get_mem());
    assert_eq!(cap.get_mem(), MemberType::Cap);
    let buf: &[u8] = &[0,0,0,0,0,0,1,1,1,1];
    cap.convert_to_ptm(&buf);
    println!("PtmRes- convert_to_ptm: {:?}", cap);
}

/* PtmEst Testing */
fn test_ptmest() {
    println!("PtmEst Testing");
    let mut est: PtmEst = PtmEst::new();
    println!("PtmEst- original value: {:?}", est);
    println!("PtmEst- convert_to_reqbytes: {:?}", est.convert_to_reqbytes());
    assert_eq!(est.convert_to_reqbytes(), []);
    println!("PtmEst- get_mem: {:?}", est.get_mem());
    assert_eq!(est.get_mem(), MemberType::Request);
    let buf: &[u8] = &[0,0,0,1,1,0,1,1,1,1];
    est.convert_to_ptm(&buf);
    println!("PtmEst- convert_to_ptm: {:?}", est);
    est.set_mem(MemberType::Error);
    println!("PtmEst- set_mem to Error: {:?}", est.get_mem());
    assert_eq!(est.get_mem(), MemberType::Error);
    est.set_res(13);
    println!("PtmEst- set_res: {:?}", est);
}

/* PtmSetBufferSize Testing */
fn test_ptmsetbuffersize() {
    println!("PtmSetBufferSize Testing");
    let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new();
    println!("PtmSetBufferSize- original value: {:?}", psbs);
    psbs.req.buffersize = 266;
    println!("PtmSetBufferSize- convert_to_reqbytes: {:?}", psbs.convert_to_reqbytes());
    println!("PtmSetBufferSize- get_mem: {:?}", psbs.get_mem());
    assert_eq!(psbs.get_mem(), MemberType::Request);
    let buf: &[u8] = &[0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,1];
    psbs.convert_to_ptm(&buf);
    println!("PtmSetBufferSize- convert_to_ptm: {:?}", psbs);
    psbs.set_mem(MemberType::Error);
    println!("PtmSetBufferSize- set_mem to Error: {:?}", psbs.get_mem());
    assert_eq!(psbs.get_mem(), MemberType::Error);
    psbs.set_res(13);
    println!("PtmSetBufferSize- set_res to 13: {:?}", psbs);
}
/* PtmResetEst */
fn test_ptmresetest() {
    println!("PtmResetEst Testing");
    let mut pre: PtmResetEst = PtmResetEst::new();
    println!("PtmResetEst- original value: {:?}", pre);
    pre.req.loc = 17;
    println!("PtmResetEst- convert_to_reqbytes: {:?}", pre.convert_to_reqbytes());
    println!("PtmResetEst- get_mem: {:?}", pre.get_mem());
    assert_eq!(pre.get_mem(), MemberType::Request);
    let buf: &[u8] = &[0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,1];
    pre.convert_to_ptm(&buf);
    println!("PtmResetEst- convert_to_ptm: {:?}", pre);
    pre.set_mem(MemberType::Error);
    println!("PtmResetEst- set_mem to Error: {:?}", pre.get_mem());
    assert_eq!(pre.get_mem(), MemberType::Error);
    pre.set_res(13);
    println!("PtmResetEst- set_res to 13: {:?}", pre);
}

/* PtmLoc Testing */
fn test_ptmloc() {
    println!("PtmLoc Testing");
    let mut loc: PtmLoc = PtmLoc::new();
    println!("PtmLoc- original value: {:?}", loc);
    loc.req.loc = 17;
    println!("Set loc to 17");
    println!("PtmLoc- convert_to_reqbytes: {:?}", loc.convert_to_reqbytes());
    println!("PtmLoc- get_mem: {:?}", loc.get_mem());
    assert_eq!(loc.get_mem(), MemberType::Request);
    let buf: &[u8] = &[0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,1];
    loc.convert_to_ptm(&buf);
    println!("PtmLoc- convert_to_ptm: {:?}", loc);
    loc.set_mem(MemberType::Error);
    println!("PtmLoc- set_mem to Error: {:?}", loc.get_mem());
    assert_eq!(loc.get_mem(), MemberType::Error);
    loc.set_res(13);
    println!("PtmLoc- set_res to 13: {:?}", loc);
}