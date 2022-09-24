
#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub struct YubicoOtp {
    pub public_id: [u8; 6],
    pub private_id: [u8; 6],
    pub key: [u8; 16],
    pub use_counter: u16,
    pub timestamp: [u8; 3],
    pub session_counter: u8,
    pub random_number: u16,
    pub crc: u16,
}

#[derive(Clone, Default)]
#[derive(PartialEq, Debug)]
pub struct YubicoSeed {
    pub public_id: Vec<u8>,
    pub private_id: [u8; 6],
    pub key: [u8; 16],
    pub counter: u16,
    session_counter: u8,
}

impl YubicoSeed {
    pub fn new(public_id: Vec<u8>, private_id: [u8; 6], key: [u8; 16], counter: u16) -> Self {
        YubicoSeed{ public_id, private_id, key, counter, session_counter: 0 }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
