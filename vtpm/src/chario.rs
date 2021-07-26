#[derive(PartialEq)]
enum QIOChannelFeature {
    QioChannelFeatureFdPass = 0,
    QioChannelFeatureShutdown,
    QioChannelFeatureListen,
}

pub struct IOChannel {
    features: usize,
}

impl IOChannel {
    pub fn new() -> Self {
        Self {
        }
    }
    pub fn io_writeev() -> usize {

    }

    pub fn io_channel_has_feature(&self, feature: QIOChannelFeature) -> bool {
        let val = match feature {
            QioChannelFeatureFdPass => 0,
            QioChannelFeatureShutdown => 1,
            QioChannelFeatureListen => 2,
        };
        self.features & (1 << val) != 0
    }

    pub fn io_channel_writev_full(&self, fds: usize, nfds: usize) -> usize {
        if fds != 0 || nfds != 0 && !self.io_channel_has_feature(QIOChannelFeature::QioChannelFeatureFdPass) {
            return !0;
        }
        self.io_writeev()
    }

    pub fn io_channel_send_full(&self, buf: Vec<u8>, len: usize, fds: usize, nfds: usize) -> usize {
        let offset: usize = 0;
        while offset < len {
            let ret: usize = 0;
            ret 
            offset += ret;
        }
        offset
    }
}