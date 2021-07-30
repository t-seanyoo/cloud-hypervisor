use crate::tpm_backend::TPMBackendCmd;
use tpm2::{Simulator};
use std::fmt::{self, Display};


// A single queue of size 2. The guest kernel driver will enqueue a single
// descriptor chain containing one command buffer and one response buffer at a
// time.
const QUEUE_SIZE: u16 = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// Maximum command or response message size permitted by this device
// implementation. Named to match the equivalent constant in Linux's tpm.h.
// There is no hard requirement that the value is the same but it makes sense.
const TPM_BUFSIZE: usize = 4096;

pub struct TPMDevice {
    pub simulator: Simulator,
}

impl TPMDevice {
    pub fn init_simulator() -> Self {
        Self {
            simulator: Simulator::singleton_in_current_directory(),
        }
    }

    pub fn perform_work_from_cmd(&mut self, cmd: &mut TPMBackendCmd) -> Result<u32> {
        let mut command = cmd.input;
        let response = self.simulator.execute_command(&command);

        if response.len() > TPM_BUFSIZE {
            return Err(Error::ResponseTooLong {
                size: response.len(),
            });
        }

        if response.len() > cmd.output_len as usize {
            return Err(Error::BufferTooSmall {
                size: cmd.output_len as usize,
                required: response.len(),
            });
        }

        cmd.output.extend(response);
        cmd.output_len = response.len() as u32;

        Ok(response.len() as u32)
    }
}

type Result<T> = std::result::Result<T, Error>;

enum Error {
    CommandTooLong { size: usize },
    ResponseTooLong { size: usize },
    BufferTooSmall { size: usize, required: usize },
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CommandTooLong { size } => write!(
                f,
                "vtpm command is too long: {} > {} bytes",
                size, TPM_BUFSIZE
            ),
            ResponseTooLong { size } => write!(
                f,
                "vtpm simulator generated a response that is unexpectedly long: {} > {} bytes",
                size, TPM_BUFSIZE
            ),
            BufferTooSmall { size, required } => write!(
                f,
                "vtpm response buffer is too small: {} < {} bytes",
                size, required
            ),
        }
    }
}