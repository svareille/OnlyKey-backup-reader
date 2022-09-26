use aes::{Aes128, cipher::{KeyInit, generic_array::GenericArray, BlockEncrypt}};
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;
use byteorder::{ByteOrder, LittleEndian};
use std::time::{Instant};
use rand::Rng;

pub const MODHEX: Encoding = new_encoding!{
    symbols: "cbdefghijklnrtuv",
};

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub struct YubicoOtp {
    pub public_id: Vec<u8>,
    pub private_id: [u8; 6],
    pub key: [u8; 16],
    pub use_counter: u16,
    pub timestamp: u32,
    pub session_counter: u8,
    pub random_number: u16,
    pub crc: Option<u16>,
}

impl YubicoOtp {
    pub fn new(public_id: Vec<u8>, private_id: [u8; 6], key: [u8; 16], use_counter: u16, timestamp: u32, session_counter: u8, random_number: u16) -> Self {
        YubicoOtp {
            public_id,
            private_id,
            key,
            use_counter,
            timestamp,
            session_counter,
            random_number,
            crc: None
        }
    }
}

impl ToString for YubicoOtp {
    fn to_string(&self) -> String {
        let mut otp: Vec<u8> = Vec::new();

        otp.extend_from_slice(&self.public_id);

        let mut passcode: Vec<u8> = Vec::with_capacity(16);

        passcode.extend_from_slice(&self.private_id);
        passcode.extend([0,0].iter()); // reserve space for counter
        LittleEndian::write_u16(&mut passcode[6..8], self.use_counter);
        passcode.extend([0,0,0].iter()); // reserve space for timestamp
        LittleEndian::write_u24(&mut passcode[8..11], self.timestamp);
        passcode.push(self.session_counter);
        passcode.extend([0,0]); // reserve space for rand
        LittleEndian::write_u16(&mut passcode[12..14], self.random_number);

        let crc: u16 = crc16(&passcode);

        passcode.extend([0,0]); // reserve space for crc
        LittleEndian::write_u16(&mut passcode[14..16], crc);

        let key = GenericArray::from(self.key);
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut passcode));

        otp.extend_from_slice(&passcode);
        
        MODHEX.encode(&otp)
    }
}

pub fn crc16 (buf: &[u8]) -> u16 {
    let mut m_crc: u16 = 0xffff;
    
    for b in buf {
        m_crc ^= *b as u16;
        let mut j: u16;
        for _ in 0..8 {
            j = m_crc & 1;
            m_crc >>= 1;
            if j != 0 {
                m_crc ^= 0x8408;
            }
        }
    }
    m_crc
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub struct YubicoSeed {
    pub public_id: Vec<u8>,
    pub private_id: [u8; 6],
    pub key: [u8; 16],
    pub counter: u16,
    session_counter: u8,
    timestamp: u32,
    instant: Instant,
}

impl YubicoSeed {
    pub fn new(public_id: Vec<u8>, private_id: [u8; 6], key: [u8; 16], counter: u16) -> Self {
        let timestamp: u32 = rand::thread_rng().gen::<u32>() % 16777216;
        YubicoSeed{ public_id, private_id, key, counter, session_counter: 0, timestamp, instant: Instant::now()}
    }

    pub fn generate_otp(&mut self) -> YubicoOtp {
        // This lossy conversion is not a problem. The timestamp should not overlap.
        let timestamp = (self.timestamp + (self.instant.elapsed().as_millis()/125) as u32) % 16777216;

        self.session_counter = match self.session_counter.checked_add(1) {
            Some(c) => c,
            None => {
                self.counter += 1;
                0
            }
        };
        
        YubicoOtp{
            public_id: self.public_id.clone(),
            private_id: self.private_id,
            key: self.key,
            use_counter: self.counter,
            timestamp,
            session_counter: self.session_counter,
            random_number: rand::thread_rng().gen(),
            crc: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{YubicoSeed, crc16};

    #[test]
    fn creation() {
        let seed = YubicoSeed::new(
            vec![1u8,1,1,1,1,1,],
            [2,2,2,2,2,2],
            [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
            0,
        );

        assert_eq!(seed.public_id, vec![1u8,1,1,1,1,1,]);
        assert_eq!(seed.private_id, [2,2,2,2,2,2]);
        assert_eq!(seed.key, [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]);
        assert_eq!(seed.counter, 0);
        assert_eq!(seed.session_counter, 0);
    }

    #[test]
    fn generation() {
        let mut seed = YubicoSeed::new(
            vec![1u8,1,1,1,1,1,],
            [2,2,2,2,2,2],
            [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
            0,
        );

        assert_eq!(&seed.generate_otp().to_string()[0..12], "cbcbcbcbcbcb");
    }

    #[test]
    fn crc() {
        assert_eq!(crc16(&[0xff, 0xff]), 0x0000);
        assert_eq!(crc16(&[]), 0xffff);
        assert_eq!(crc16(&[49, 50, 51, 52 ,53, 54, 55, 56, 57, 48]), 0xb4ec);
    }
}
