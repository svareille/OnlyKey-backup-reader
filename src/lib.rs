use anyhow::{anyhow, Result, bail, ensure};
use num_bigint_dig::ModInverse;
use rsa::{RsaPrivateKey, BigUint};
use thiserror::Error;
use data_encoding::{BASE32, BASE64};
use log::{debug, info, error, trace, warn};
use sha2::{Sha256, Digest};
use aes_gcm::aead::{Aead, NewAead};
use ed25519_dalek::{SecretKey, PublicKey};
use x25519_dalek::x25519;
use salsa20::hsalsa20;
use generic_array::GenericArray;
use num_enum::TryFromPrimitive;
use std::{convert::{TryInto}, fmt};

use google_authenticator::GoogleAuthenticator;

use bitflags::bitflags;

#[derive(Error, Debug)]
pub enum OnlyKeyError {
    #[error("the ECC key slot must be between 1 and 32 but was `{0}`")]
    ECCNotFound(usize),
    #[error("the RSA key slot must be between 1 and 4 but was `{0}`")]
    RSANotFound(usize),
    #[error("the account name `{0}` is not valid")]
    WrongAccountName(String),
    #[error("not a backup")]
    NotABackup,
}

#[derive(Error, Debug)]
pub enum BackupError{
    #[error("the provided backup is empty")]
    EmptyBackup,
    #[error("wrong key type")]
    KeyTypeNoMatch,
    #[error("no backup key set")]
    NoKeySet,
    #[error("unexpected slot number `{0}`")]
    UnexpectedSlotNumber(u8),
    #[error("unexpected byte `0x{0:02x}`")]
    UnexpecteByte(u8),
    #[error("computation error `{0}`")]
    ComputationError(String)
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
#[derive(TryFromPrimitive)]
#[repr(u8)]
pub enum CharAfter {
    None = 0,
    Tab = 1,
    Return = 2,
}

impl Default for CharAfter {
    fn default() -> Self {
        CharAfter::None
    }
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub enum OTP {
    None,
    TOTP(String),
}

impl Default for OTP {
    fn default() -> Self {
        OTP::None
    }
}

impl OTP {
    pub fn compute(&self) -> String {
        match self {
            OTP::None => String::new(),
            OTP::TOTP(seed) => {
                let auth = GoogleAuthenticator::new();
                auth.get_code(seed,0).unwrap_or_default()
            },
        }
    }
}

#[derive(Clone,Default)]
#[derive(PartialEq, Debug)]
pub struct AccountSlot {
    pub label: String,
    pub url: String,
    pub username: String,
    // TODO: Using plain String to store sensitive data is not best practice
    pub password: String,
    pub otp: OTP,

    pub after_password: CharAfter,

    pub delay_before_password: u8,
}

impl AccountSlot {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn to_string(&self, show_secrets: bool) -> String {
        let mut res = String::from("");
        res += &format!("label: {}\n", self.label);
        res += &format!("url: {}\n", self.url);
        res += &format!("username: {}\n", self.username);
        res += &match show_secrets {
            true => format!("password: {}\n", self.password),
            false => format!("password: {}\n", if self.password.is_empty() {""} else {"****"}),
        };
        res += &format!("delay before password: {}\n", self.delay_before_password);
        res
    }
}

/*#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub enum KeyFeature {
    Decryption = 32,
    Signature = 64,
    Backup = 32 + 128,
}*/
bitflags! {
    pub struct KeyFeature: u8 {
        const DECRYPTION = 32;
        const SIGNATURE = 64;
        const BACKUP = 128;
    }
}

pub trait KeySlot {
    /// Decrypt the provided backup.
    /// 
    /// # Error
    /// 
    /// Returns an error if the decryption failed. The error kind can be:
    /// - [`KeyTypeNoMatch`](BackupError::KeyTypeNoMatch) if the decryption key type does not match
    /// the encryption key type.
    fn decrypt_backup(&self, backup: Vec<u8>) -> Result<Vec<u8>>;
    /// Returns the public key
    fn public_key(&self) -> Vec<u8>;
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub struct RSAKeySlot {
    pub label: String,
    pub feature: KeyFeature,
    /// Key length: 1024, 2048, 3072, 4096
    pub r#type: u16,
    pub private_key: Option<RsaPrivateKey>,
}

impl RSAKeySlot {
    pub fn new() -> Self {
        trace!("Creating new RSAKeySlot");
        RSAKeySlot { label: String::new(), feature: KeyFeature::DECRYPTION, r#type: 0, private_key: None }
    }

    pub fn new_from_p_q(p: &[u8], q: &[u8], label: &str, feature: KeyFeature) -> Result<Self> {
        // Key length is p.len()*2 in bytes, thus p.len()*2*8 in bits
        let keylen = p.len()*8*2;
        let p = BigUint::from_bytes_be(p);
        let q = BigUint::from_bytes_be(q);
        let e = BigUint::from(65537u32);
        let n = p.clone()*q.clone();
        let primes = vec![p.clone(), q.clone()];
        let d = match e.clone().mod_inverse((p-1u32)*(q-1u32)).and_then(|d| d.to_biguint()) {
            Some(d) => d,
            None => {
                error!("Could not find the modular inverse of e for provided p and q for key");
                bail!(BackupError::ComputationError("Could not find the modular inverse of e for provided key".to_owned()));
            },
        };
        let private_key = Some(RsaPrivateKey::from_components(n, e, d, primes));

        Ok(RSAKeySlot {
            label: label.to_owned(),
            feature,
            r#type: keylen as u16,
            private_key,
        })
    }
}

impl Default for RSAKeySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySlot for RSAKeySlot {
    fn decrypt_backup(&self, backup: Vec<u8>) -> Result<Vec<u8>> {
        trace!("Decrypting backup with RSA key");
        let backup_type = backup.last().ok_or_else(||anyhow!(BackupError::EmptyBackup))?;

        if self.r#type / 1024 != *backup_type as u16 {
            error!("Key type used for backup does not match");
            bail!(BackupError::KeyTypeNoMatch)
        }

        trace!("RSA keys match");

        let payload_len = backup.len() - 1 - (*backup_type as usize*128) ;

        let encrypted_key = &backup[payload_len..payload_len+(*backup_type as usize*128)];

        if self.private_key.is_none() {
            error!("RSA key is not set");
            bail!(BackupError::NoKeySet)
        }

        let aes_key = self.private_key.as_ref().unwrap().decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, encrypted_key)?;

        trace!("AES key decrypted");

        let cipher = match aes_gcm::Aes256Gcm::new_from_slice(&aes_key) {
            Ok(cipher) => cipher,
            Err(e) => {
                error!("Cound not create AES cipher: {}", e);
                bail!(e);
            },
        };

        trace!("Cipher created");
        let nonce = aes_gcm::Nonce::from_slice(b"BACKUP12345\0");

        // The `decrypt` method of Aes256Gcm check the tag's validity.
        // However we don't have the tag, thus the `decrypt` method always fail.
        // With AES, encryption and decryption are the same algorithm. We thus "encrypt" our data to
        // decrypt it, then discard the generated Tag (last 16 bytes).
        let decrypted = cipher.encrypt(nonce, &backup[..payload_len]);
        let mut decrypted = decrypted.map_err(|e| {anyhow!(e)})?;
        decrypted.resize(payload_len, 0);

        Ok(decrypted)
    }
    fn public_key(&self) -> Vec<u8> {
        unimplemented!()
    }
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub enum ECCKeyType {
    X25519 = 1,
    NIST256P1 = 2,
    SECP256K1 = 3,
}

//#[derive(Clone)]
#[derive(Debug)]
pub struct ECCKeySlot {
    pub label: String,
    pub feature: KeyFeature,
    pub r#type: ECCKeyType,
    pub private_key: SecretKey,
}

impl ECCKeySlot {
    pub fn new() -> Self {
        ECCKeySlot { label: String::new(), feature: KeyFeature::DECRYPTION, r#type: ECCKeyType::X25519, private_key: SecretKey::from_bytes(&[0; 32]).unwrap() }
    }
}

impl Default for ECCKeySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ECCKeySlot {
    fn clone(&self) -> Self {
        Self { label: self.label.clone(), feature: self.feature, r#type: self.r#type.clone(), private_key: SecretKey::from_bytes(self.private_key.as_bytes()).unwrap_or_else(|_| SecretKey::from_bytes(&[0; 32]).unwrap()) }
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

impl KeySlot for ECCKeySlot {

    fn decrypt_backup(&self, backup: Vec<u8>) -> Result<Vec<u8>> {
        let backup_type = backup.last().ok_or_else(||anyhow!(BackupError::EmptyBackup))?;

        if self.r#type.clone() as u16 + 100 != *backup_type as u16 {
            error!("Key type used for backup does not match");
            bail!(BackupError::KeyTypeNoMatch)
        }

        let payload_len = backup.len() - 1 - 12;

        let iv = &backup[payload_len..payload_len+12];

        let shared_secret = hsalsa20(
            GenericArray::from_slice(&x25519(
                *self.private_key.as_bytes(),
                self.public_key().as_slice().try_into().expect("Public key should have been 32 bytes long"))),
            &GenericArray::default(),
        );

        let aes_key = Sha256::new()
            .chain_update(shared_secret)
            .chain_update(self.public_key())
            .chain_update(iv)
            .finalize();

        let cipher = aes_gcm::Aes256Gcm::new(&aes_key);
        let nonce = aes_gcm::Nonce::from_slice(iv);

        // The `decrypt` method of Aes256Gcm check the tag's validity.
        // However we don't have the tag, thus the `decrypt` method always fail.
        // With AES, encryption and decryption are the same algorithm. We thus "encrypt" our data to
        // decrypt it, then discard the generated Tag (last 16 bytes).
        let decrypted = cipher.encrypt(nonce, &backup[..payload_len]);
        let mut decrypted = decrypted.map_err(|e| {anyhow!(e)})?;
        decrypted.resize(payload_len, 0);

        Ok(decrypted)
    }

    fn public_key(&self) -> Vec<u8> {
        let public_key: PublicKey = (&self.private_key).into();
        return public_key.as_bytes().to_vec();
    }
}

impl PartialEq for ECCKeySlot {
    fn eq(&self, other: &Self) -> bool {
        let private_key_same = self.private_key.as_bytes() == other.private_key.as_bytes();
        self.label == other.label && self.feature == other.feature && self.r#type == other.r#type && private_key_same
    }
}

#[derive(Clone)]
#[derive(PartialEq, Debug)]
pub struct Profile {
    accounts: Vec<Option<AccountSlot>>,
}

impl Profile {
    pub fn new() -> Self {
        let accounts = vec![None; 12];
        Profile {accounts}
    }

    /// Return the account from an account name.
    /// 
    /// This method return a clone of the actual account. To get a mutable reference, use 
    /// [`get_account_by_name_mut`].
    /// 
    /// Account name can be one of `1a`, `2a`, `3a`, `4a`, `5a`, `6a`, `1b`, `2b`, `3b`, `4b`, `5b`
    /// or `6b` 
    /// 
    /// # Error
    /// 
    /// Returns [`WrongAccountName`](OnlyKeyError::WrongAccountName) if the provided account name
    /// was not one of the above.
    /// 
    pub fn get_account_by_name(&self, name: &str) -> Result<AccountSlot> {
        trace!("Getting account by name");
        let slot_names = ["1a", "2a", "3a", "4a", "5a", "6a", "1b", "2b", "3b", "4b", "5b", "6b"];
        let slot_nb = match slot_names.iter().position(|&n| name == n) {
            Some(slot_nb) => slot_nb,
            None => bail!(OnlyKeyError::WrongAccountName(name.to_owned())),
        };

        match &self.accounts[slot_nb] {
            Some(account) => Ok(account.clone()),
            None => Ok(AccountSlot::new()),
        }
    }

    /// Return the account from an account name as a mutable reference.
    /// 
    /// This method return a mutable reference of the actual account. To get a copy, use 
    /// [`get_account_by_name`].
    /// 
    /// Account name can be one of `1a`, `2a`, `3a`, `4a`, `5a`, `6a`, `1b`, `2b`, `3b`, `4b`, `5b`
    /// or `6b` 
    /// 
    /// # Error
    /// 
    /// Returns [`WrongAccountName`](OnlyKeyError::WrongAccountName) if the provided account name
    /// was not one of the above.
    /// 
    pub fn get_account_by_name_mut(&mut self, name: &str) -> Result<&mut AccountSlot> {
        trace!("Getting account by name (mut)");
        let slot_names = ["1a", "2a", "3a", "4a", "5a", "6a", "1b", "2b", "3b", "4b", "5b", "6b"];
        let slot_nb = match slot_names.iter().position(|&n| name == n) {
            Some(slot_nb) => slot_nb,
            None => bail!(OnlyKeyError::WrongAccountName(name.to_owned())),
        };

        if self.accounts[slot_nb].is_none() {
            self.accounts[slot_nb] = Some(AccountSlot::new());
        }

        Ok(self.accounts[slot_nb].as_mut().unwrap())
    }

}

impl Default for Profile {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot_names = ["1a", "2a", "3a", "4a", "5a", "6a", "1b", "2b", "3b", "4b", "5b", "6b"];
        for (index, account) in self.accounts.iter().enumerate() {
            if let Some(account) = account {
                writeln!(f, "Slot {}: {}", slot_names[index], account.label)?;
            }
        }
        Ok(())
    }
}


/*#[derive(PartialEq, Debug)]
pub enum BackupKeyID {
    ECC(usize),
    RSA(usize),
    PassPhrase,
    None,
}*/

#[derive(PartialEq, Debug)]
enum BackupKey {
    Ecc(ECCKeySlot),
    Rsa(Box<RSAKeySlot>),
    None,
}

#[derive(PartialEq, Debug)]
pub struct OnlyKey {
    pub profile1: Profile,
    pub profile2: Profile,

    rsa_keys: [Option<RSAKeySlot>; 4],
    ecc_keys: [Option<ECCKeySlot>; 32],
    //passphrase_key: Option<ECCKeySlot>,

    //backup_key_id: BackupKeyID,
    backup_key: BackupKey,
}

impl OnlyKey {
    pub fn new() -> Self {
        OnlyKey {
            profile1: Profile::new(),
            profile2: Profile::new(),
            rsa_keys: Default::default(),
            ecc_keys: Default::default(),
            //passphrase_key: None,
            //backup_key_id: BackupKeyID::None,
            backup_key: BackupKey::None,
        }
    }

    /// Set the specified slot with the provided ECC key.
    /// 
    /// # Errors
    /// Returns [`ECCNotFound`](OnlyKeyError::ECCNotFound) if the slot is not between 1 and 32.
    pub fn set_ecc_key_slot(&mut self, slot: usize, key: ECCKeySlot) -> Result<()>{
        trace!("Setting ECC key slot {}", slot);
        if (1..=32).contains(&slot) {
            self.ecc_keys[slot-1] = Some(key);
            return Ok(());
        }
        bail!(OnlyKeyError::ECCNotFound(slot))
    }

    /// Remove the ECC key from the specified slot.
    /// 
    /// # Errors
    /// Returns [`ECCNotFound`](OnlyKeyError::ECCNotFound) if the slot is not between 1 and 32.
    pub fn remove_ecc_key_slot(&mut self, slot: usize) -> Result<()> {
        trace!("Removing ECC key slot {}", slot);
        if (1..=32).contains(&slot) {
            self.ecc_keys[slot-1] = None;
            return Ok(());
        }
        bail!(OnlyKeyError::ECCNotFound(slot))
    }

    /// Get the ECC key from the specified slot.
    /// 
    /// # Errors
    /// Returns [`ECCNotFound`](OnlyKeyError::ECCNotFound) if the slot is not between 1 and 32.
    pub fn get_ecc_key(&self, slot: usize) -> Result<Option<&ECCKeySlot>> {
        trace!("Getting ECC key slot {}", slot);
        if (1..=32).contains(&slot) {
            return Ok(self.ecc_keys[slot-1].as_ref());
        }
        bail!(OnlyKeyError::ECCNotFound(slot))
    }

    /// Set the specified slot with the provided RSA key.
    /// 
    /// # Errors
    /// Returns [`RSANotFound`](OnlyKeyError::RSANotFound) if the slot is not between 1 and 4.
    pub fn set_rsa_key_slot(&mut self, slot: usize, key: RSAKeySlot) -> Result<()>{
        trace!("Setting RSA key slt {}", slot);
        if (1..=4).contains(&slot) {
            self.rsa_keys[slot-1] = Some(key);
            return Ok(());
        }
        bail!(OnlyKeyError::RSANotFound(slot))
    }

    /// Remove the RSA key from the specified slot.
    /// 
    /// # Errors
    /// Returns [`RSANotFound`](OnlyKeyError::RSANotFound) if the slot is not between 1 and 4.
    pub fn remove_rsa_key_slot(&mut self, slot: usize) -> Result<()> {
        trace!("Removing RSA key slot {}", slot);
        if (1..=4).contains(&slot) {
            self.rsa_keys[slot-1] = None;
            return Ok(());
        }
        bail!(OnlyKeyError::RSANotFound(slot))
    }

    /// Get the RSA key from the specified slot.
    /// 
    /// # Errors
    /// Returns [`RSANotFound`](OnlyKeyError::RSANotFound) if the slot is not between 1 and 4.
    pub fn get_rsa_key(&self, slot: usize) -> Result<Option<&RSAKeySlot>> {
        trace!("Getting RSA key slot {}", slot);
        if (1..=4).contains(&slot) {
            return Ok(self.rsa_keys[slot-1].as_ref());
        }
        bail!(OnlyKeyError::RSANotFound(slot))
    }

    /// Returns the designated backup key as a reference.
    pub fn backup_key(&self, ) -> Option<& dyn KeySlot> {
        trace!("Getting bakup key");
        match &self.backup_key {
            BackupKey::Ecc(key) => {
                Some(key)
            },
            BackupKey::Rsa(key) => {
                Some(&(**key))
            },
            BackupKey::None => None,
        }
    }

    /// Set the given passphrase as the backup key.
    pub fn set_backup_passphrase(&mut self, passphrase: &str){
        trace!("Setting passphrase backup key");
        let key = ECCKeySlot{
            label: String::new(),
            feature: KeyFeature::DECRYPTION | KeyFeature::BACKUP,
            r#type: ECCKeyType::X25519,
            private_key: SecretKey::from_bytes(&Sha256::new()
                .chain_update(passphrase)
                .finalize()).expect("Problem generating secret key"),
        };
        self.backup_key = BackupKey::Ecc(key);
    }

    /// Set the given ECC key as the backup key.
    /// 
    /// # Errors
    /// 
    /// Returns a [`ed25519_dalek::SignatureError`] if the key is not a valid ECC key.
    /// 
    pub fn set_backup_ecc_key(&mut self, key: Vec<u8>, key_type: ECCKeyType) -> Result<()> {
        trace!("Setting ECC backup key");
        let ecc_key = ECCKeySlot {
            label: String::new(),
            feature: KeyFeature::DECRYPTION | KeyFeature::BACKUP,
            r#type: key_type,
            private_key: SecretKey::from_bytes(&key)?,
        };
        self.backup_key = BackupKey::Ecc(ecc_key);
        Ok(())
    }

    /// Set the given RSA private key as the backup key.
    /// 
    /// The key must be the `p` and `q` factors concatenated as bytes.
    /// 
    /// For example:
    /// ```ignore
    /// p = 01010101
    /// q = 02020202
    /// key = 0101010102020202
    /// ```
    /// 
    /// # Errors
    /// 
    /// Returns [`BackupError::ComputationError`] if the `d` value couldn't be computed.
    /// 
    pub fn set_backup_rsa_key(&mut self, key: Vec<u8>) -> Result<()> {
        trace!("Setting RSA backup key");
        let key_length = key.len();
        
        let rsa_key = RSAKeySlot::new_from_p_q(
            &key[0..key_length/2],
            &key[key_length/2..],
            "", 
            KeyFeature::DECRYPTION | KeyFeature::BACKUP,
        )?;

        self.backup_key = BackupKey::Rsa(Box::new(rsa_key));

        Ok(())
    }

    /// Loads the provided base64-encoded backup.
    /// 
    /// # Errors
    /// 
    /// Returns an error if the loading failed. The error kind can be:
    /// - [`DecodeError`](data_encoding::DecodeError) if the base64 decoder failed.
    /// - [`NoKeySet`](BackupError::NoKeySet) if no backup key was set.
    /// - [`KeyTypeNoMatch`](BackupError::KeyTypeNoMatch) if the backup key is wrong.
    /// - [`UnexpectedSlotNumber`](BackupError::UnexpectedSlotNumber) if a slot number was not expected.
    /// - [`UnexpecteByte`](BackupError::UnexpecteByte) if a byte was not expected.
    /// 
    pub fn load_backup(&mut self, backup: &str) -> Result<()> {
        let mut encrypted= Vec::<u8>::new();

        // Read backup, decoding the base64 content
        info!("Decoding backup");
        for mut line in backup.lines() {
            line = line.trim();
            if line.starts_with("--") {
                continue;
            }
            else
            {
                encrypted.append(&mut BASE64.decode(line.as_bytes())?);
            }
        }

        info!("Decrypting backup");
        let backup_key = self.backup_key().ok_or_else(|| anyhow!(BackupError::NoKeySet))?;

        let decrypted = backup_key.decrypt_backup(encrypted)?;

        let mut index = 0;
        info!("Parsing backup");
        while index < decrypted.len() {
            match decrypted[index] {
                0xFF => {
                    index += 1;
                    let slot_nb = decrypted[index];
                    index += 1;
                    let r#type = decrypted[index];
                    index += 1;

                    let slot_names = ["1a", "2a", "3a", "4a", "5a", "6a", "1b", "2b", "3b", "4b", "5b", "6b"];
                    let next_block = match decrypted[index+1..].iter().position(|b| b == &0xFC || b == &0xFD || b == &0xFE || b == &0xFF) {
                        Some(pos) => pos+index+1,
                        None => decrypted.len(),
                    };

                    match r#type {
                        1 => {// Label
                            trace!("Parsing label {}", slot_nb);
                            let label = std::str::from_utf8(&decrypted[index..index + 16]).unwrap_or_else(|e| {warn!("Label for slot {} is not valid UTF8: {:?}", slot_nb, e); ""});
                            let label = label.trim_matches(char::from(0));
                            index += 16;
                            match slot_nb {
                                mut nb @ 1..=24 => { // Account
                                    let profile = match nb {
                                        1..=12 => {
                                            nb -= 1;
                                            &mut self.profile1
                                        },
                                        13..=24 => {
                                            nb -= 13;
                                            &mut self.profile2
                                        },
                                        nb => {
                                            error!("Error reading backup: unexpected slot number {}", nb);
                                            bail!(BackupError::UnexpectedSlotNumber(nb))
                                        },
                                    };
                                    let slot_name = slot_names[nb as usize];
                                    let account = profile.get_account_by_name_mut(slot_name).unwrap();
                                    account.label = label.to_string();
                                },
                                mut nb @ 25..=28 => {// RSA
                                    nb -= 25;
                                    
                                    if self.rsa_keys[nb as usize].is_none() {
                                        self.rsa_keys[nb as usize] = Some(RSAKeySlot::new());
                                    }

                                    let mut rsa_key = self.rsa_keys[nb as usize].as_mut().unwrap();

                                    rsa_key.label = label.to_string();
                                },
                                mut nb @ 29..=44 => {// ECC
                                    nb -= 29;
                                    
                                    if self.ecc_keys[nb as usize].is_none() {
                                        self.ecc_keys[nb as usize] = Some(ECCKeySlot::new());
                                    }

                                    let mut ecc_key = self.ecc_keys[nb as usize].as_mut().unwrap();

                                    ecc_key.label = label.to_string();
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            }
                        },
                        2 => {// Username
                            trace!("Parsing username {}", slot_nb);
                            let username = std::str::from_utf8(&decrypted[index..next_block]).unwrap_or_else(|e| {warn!("Username for slot {} is not valid UTF8: {:?}", slot_nb, e); ""});
                            index = next_block;
                            let mut slot_nb = slot_nb;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.username = username.to_string();
                        }
                        3 => {// After password
                            trace!("Parsing after password {}", slot_nb);
                            let mut slot_nb = slot_nb;
                            let after_password = decrypted[index];
                            index += 1;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.after_password = match after_password {
                                0 => CharAfter::None,
                                1 => CharAfter::Tab,
                                2 => CharAfter::Return,
                                n => {
                                    error!("Error reading backup: unexpected after password value {}", n);
                                    bail!(BackupError::UnexpecteByte(n))
                                },
                            };
                        },
                        4 => {// Delay before Password
                            trace!("Parsing delay before password {}", slot_nb);
                            let mut slot_nb = slot_nb;
                            let delay_before_password = decrypted[index];
                            index += 1;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.delay_before_password = delay_before_password;
                        },
                        5 => {// Password
                            trace!("Parsing password {}", slot_nb);
                            let password = std::str::from_utf8(&decrypted[index..next_block]).unwrap_or_else(|e| {warn!("Password for slot {} is not valid UTF8: {:?}", slot_nb, e); ""});
                            index = next_block;
                            let mut slot_nb = slot_nb;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.password = password.to_string();
                        },
                        9 => {// TOTP
                            trace!("Parsing TOTP {}", slot_nb);
                            let data_len = decrypted[index];
                            index += 1;
                            let totp = &decrypted[index..index + data_len as usize];
                            let totp = BASE32.encode(totp);

                            let mut slot_nb = slot_nb;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.otp = OTP::TOTP(totp);
                            index += data_len as usize;
                        },
                        10 => {// Yubikey
                            warn!("Ignoring Yubikey OTP {}", slot_nb);
                            // TODO
                            index += 6 + 6 + 16;
                        },
                        15 => {// URL
                            trace!("Parsing URL {}", slot_nb);
                            let url = std::str::from_utf8(&decrypted[index..next_block]).unwrap_or_else(|e| {warn!("URL for slot {} is not valid UTF8: {:?}", slot_nb, e); ""});
                            index = next_block;
                            let mut slot_nb = slot_nb;
                            let profile = match slot_nb {
                                1..=12 => {
                                    slot_nb -= 1;
                                    &mut self.profile1
                                },
                                13..=24 => {
                                    slot_nb -= 13;
                                    &mut self.profile2
                                },
                                nb => {
                                    error!("Error reading backup: unexpected slot number {}", nb);
                                    bail!(BackupError::UnexpectedSlotNumber(nb))
                                },
                            };
                            let slot_name = slot_names[slot_nb as usize];
                            let account = profile.get_account_by_name_mut(slot_name).unwrap();
                            account.url = url.to_string();
                        }
                        n => {
                            warn!("Ignoring entry type {}", n);
                            index = next_block
                        },
                    }
                },
                0xFE => {
                    index += 1;
                    let mut slot_nb = decrypted[index];
                    index += 1;

                    match slot_nb {
                        0 => {
                            // Authenticator state
                            warn!("Ignoring Authenticator State");
                            // TODO
                            index += 208;
                        }
                        1..=4 => {
                            // RSA
                            debug!("Parsing RSA key {}", slot_nb);
                            slot_nb -= 1;
                            let r#type = decrypted[index];
                            index += 1;

                            if self.rsa_keys[slot_nb as usize].is_none() {
                                self.rsa_keys[slot_nb as usize] = Some(RSAKeySlot::new());
                            }

                            let rsa_key = self.rsa_keys[slot_nb as usize].as_ref().unwrap().clone();

                            let key_length = (r#type & 0x0F) as usize * 128;

                            self.rsa_keys[slot_nb as usize] = Some(RSAKeySlot::new_from_p_q(
                                &decrypted[index..index+key_length/2],
                                &decrypted[index+key_length/2..index+key_length],
                                &rsa_key.label, 
                                match KeyFeature::from_bits(r#type & 0xF0) {
                                    Some(feature) => feature,
                                    None => {
                                        error!("Unknown RSA key feature 0x{:02x}", r#type & 0xF0);
                                        bail!(BackupError::UnexpecteByte(r#type))
                                    },
                                },
                            )?);
                            trace!("RSA key created");
                            index += key_length;
                        }
                        101..=116 => {
                            // ECC
                            debug!("Parsing ECC key {}", slot_nb);
                            slot_nb -= 101;
                            let r#type = decrypted[index];
                            index += 1;
                            let raw_key = &decrypted[index..index+32];

                            if self.ecc_keys[slot_nb as usize].is_none() {
                                self.ecc_keys[slot_nb as usize] = Some(ECCKeySlot::new());
                            }

                            let mut ecc_key = self.ecc_keys[slot_nb as usize].as_mut().unwrap();

                            debug!("ECC type: 0x{:02x}", r#type);

                            ecc_key.feature = match KeyFeature::from_bits(r#type & 0xF0) {
                                Some(feature) => feature,
                                None => {
                                    error!("Unknown ECC key feature 0x{:02x}", r#type & 0xF0);
                                    bail!(BackupError::UnexpecteByte(r#type))
                                },
                            };
                            
                            ecc_key.r#type = match r#type & 0x0F {
                                1 => ECCKeyType::X25519,
                                2 => ECCKeyType::NIST256P1,
                                3 => ECCKeyType::SECP256K1,
                                n => {
                                    error!("Unknown ECC key type 0x{:02x}", n);
                                    bail!(BackupError::UnexpecteByte(r#type))
                                },
                            };
                            ecc_key.private_key = SecretKey::from_bytes(raw_key).unwrap_or_else(|e| {
                                warn!("Could not create secret ECC key: {:?}", e); SecretKey::from_bytes(&[0; 32]).unwrap()
                            });
                            
                            index += 32;
                        }
                        128 => {
                            warn!("Ignoring unknown ECC key (slot 128)");
                            // TODO
                            index += 33;
                        }
                        129 | 130 => {
                            // HMAC
                            warn!("Ignoring HMAC key");
                            // TODO
                            index += 33;
                        }
                        131 => {
                            // Backup passphrase hash
                            info!("Ignoring backup passphrase because already known");
                            // TODO? The backup passphrase's hash can still be present if a
                            // passphrase has once been set.
                            index += 33;
                        }
                        132 => {
                            warn!("Ignoring unknown ECC key (slot 132)");
                            // TODO
                            index += 33;
                        }
                        200.. => {
                            // Resident Key
                            warn!("Ignoring resident key");
                            index += 441;
                        }
                        n => {
                            // Slots 117..=127 seem unused. Gotta check the firmware's code to
                            // confirm that.
                            error!("Slot number {} invalid", n);
                            bail!(BackupError::UnexpectedSlotNumber(n))
                        }
                    }
                },
                num => {
                    error!("Error reading backup: unexpected byte 0x{:x}", num);
                    bail!(BackupError::UnexpecteByte(num))
                }
            }
        }

        info!("Successfully parsed backup");
        Ok(())
    }
}

impl Default for OnlyKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify the provided backup.
/// 
/// Returns `false` if the backup is corrupted, `true` otherwise.
/// 
/// # Errors
/// 
/// Returns an error if `backup` is invalid. The error kind can be:
/// - [`NotABackup`](OnlyKeyError::NotABackup) if the provided string is not a backup.
/// - [`DecodeError`](data_encoding::DecodeError) if the base64 decoder failed.
pub fn verify_backup(backup: &str) -> Result<bool> {
    let mut stored_hash = vec![0; 32];
    let mut computed_hash = vec![0; 32];

    info!("Verifying backup");

    ensure!(backup.starts_with("-----BEGIN ONLYKEY BACKUP-----"), OnlyKeyError::NotABackup);

    for mut line in backup.lines() {
        line = line.trim();
        if line == "-----BEGIN ONLYKEY BACKUP-----" {
            continue;
        }
        else if line == "-----END ONLYKEY BACKUP-----" {
            break;
        }
        else if let Some(base64hash) = line.strip_prefix("--") {
            // base64-encoded sha256 hash
            trace!("Parsing sha256 hash");
            stored_hash = BASE64.decode(base64hash.as_bytes())?;
        }
        else
        {
            let decoded = BASE64.decode(line.as_bytes())?;
            computed_hash = Sha256::new()
                .chain_update(computed_hash)
                .chain_update(decoded)
                .finalize().to_vec();
        }
    }
    Ok(computed_hash == stored_hash)
}

#[cfg(test)]
mod tests {
    
}