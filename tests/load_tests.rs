use ok_backup::{verify_backup, OnlyKey, ECCKeySlot, CharAfter, OTP, KeyFeature, ECCKeyType};

mod common;

use ed25519_dalek::SecretKey;

fn construct_expected_onlykey_passphrase() -> OnlyKey {
    let mut onlykey = OnlyKey::new();
    onlykey.set_backup_passphrase("azerty");
    let account = onlykey.profile1.get_account_by_name_mut("1a").unwrap();
    account.label = "Application 1a".to_string();
    account.otp = OTP::TOTP("AEAQCAIBAEAQCAIB".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("2a").unwrap();
    account.label = "Application 2a".to_string();
    account.otp = OTP::TOTP("AIBAEAQCAIBAEAQC".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("3a").unwrap();
    account.label = "Application 3a".to_string();
    account.otp = OTP::TOTP("AMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQ====".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("4a").unwrap();
    account.label = "Application 4a".to_string();
    account.otp = OTP::TOTP("AQCAIBAEAQCAIBAE".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("5a").unwrap();
    account.label = "Application 5a".to_string();
    account.otp = OTP::TOTP("AUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIF".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("6a").unwrap();
    account.label = "A test 6a".to_string();
    account.username = "my_user".to_string();
    account.password = "mypassword".to_string();
    account.url = "https://www.example.com".to_string();
    account.after_password = CharAfter::Return;
    account.delay_before_password = 1;
    account.otp = OTP::TOTP("TESTBAUTHENTICATOQ======".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("1b").unwrap();
    account.label = "Application 1b".to_string();
    account.otp = OTP::TOTP("A4DQOBYHA4DQOBYH".to_string());

    let account = onlykey.profile2.get_account_by_name_mut("1a").unwrap();
    account.label = "Application 1a2".to_string();
    account.otp = OTP::TOTP("BUGQ2DINBUGQ2DINBUGQ2DINBU======".to_string());
    

    let mut encryption_key = ECCKeySlot::new();
    encryption_key.label = "Encryption".to_string();
    encryption_key.feature = KeyFeature::DECRYPTION;
    encryption_key.r#type = ECCKeyType::X25519;
    encryption_key.private_key = SecretKey::from_bytes(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 16, 1, 1]).unwrap();
    onlykey.set_ecc_key_slot(1, encryption_key).unwrap();

    let mut signature_key = ECCKeySlot::new();
    signature_key.label = "Signature".to_string();
    signature_key.feature = KeyFeature::SIGNATURE;
    signature_key.r#type = ECCKeyType::X25519;
    signature_key.private_key = SecretKey::from_bytes(&[0x02; 32]).unwrap();
    onlykey.set_ecc_key_slot(2, signature_key).unwrap();

    onlykey
}

fn construct_expected_onlykey_ecc() -> OnlyKey {
    let mut onlykey = OnlyKey::new();
    let account = onlykey.profile1.get_account_by_name_mut("1a").unwrap();
    account.label = "Application 1a".to_string();
    account.otp = OTP::TOTP("AEAQCAIBAEAQCAIB".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("2a").unwrap();
    account.label = "Application 2a".to_string();
    account.otp = OTP::TOTP("AIBAEAQCAIBAEAQC".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("3a").unwrap();
    account.label = "Application 3a".to_string();
    account.otp = OTP::TOTP("AMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQ====".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("4a").unwrap();
    account.label = "Application 4a".to_string();
    account.otp = OTP::TOTP("AQCAIBAEAQCAIBAE".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("5a").unwrap();
    account.label = "Application 5a".to_string();
    account.otp = OTP::TOTP("AUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIF".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("6a").unwrap();
    account.label = "Application 6a".to_string();
    account.otp = OTP::TOTP("AYDAMBQGAYDAMBQG".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("1b").unwrap();
    account.label = "Application 1b".to_string();
    account.otp = OTP::TOTP("A4DQOBYHA4DQOBYH".to_string());
    let account = onlykey.profile1.get_account_by_name_mut("6b").unwrap();
    account.label = "Application 6b".to_string();
    account.otp = OTP::TOTP("BQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAM".to_string());

    let account = onlykey.profile2.get_account_by_name_mut("1a").unwrap();
    account.label = "Application 1a2".to_string();
    account.otp = OTP::TOTP("BUGQ2DINBUGQ2DINBUGQ2DINBU======".to_string());
    

    let mut encryption_key = ECCKeySlot::new();
    encryption_key.label = "Encryption".to_string();
    encryption_key.feature = KeyFeature::DECRYPTION | KeyFeature::BACKUP;
    encryption_key.r#type = ECCKeyType::X25519;
    encryption_key.private_key = SecretKey::from_bytes(&[0x01; 32]).unwrap();
    onlykey.set_ecc_key_slot(1, encryption_key).unwrap();

    let mut signature_key = ECCKeySlot::new();
    signature_key.label = "Signature".to_string();
    signature_key.feature = KeyFeature::SIGNATURE;
    signature_key.r#type = ECCKeyType::X25519;
    signature_key.private_key = SecretKey::from_bytes(&[0x02; 32]).unwrap();
    onlykey.set_ecc_key_slot(2, signature_key).unwrap();

    onlykey.set_backup_ecc_key(vec![0x01; 32], ECCKeyType::X25519).unwrap();

    onlykey
}

fn install_test_logger() {
    // This'll fail if called twice; don't worry.
    let _ = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(fern::Output::call(|record| println!("{}", record.args())))
        .apply();
}

#[test]
fn load_good_backup_with_passphrase() {
    install_test_logger();
    let mut onlykey: OnlyKey = OnlyKey::new();
    let expected_onlykey = construct_expected_onlykey_passphrase(); 
    onlykey.set_backup_passphrase("azerty");
    onlykey.load_backup(common::BACKUP_PW_STR).unwrap();
    
    assert_eq!(onlykey, expected_onlykey);
}

#[test]
fn load_good_backup_with_ecc() {
    install_test_logger();
    let mut onlykey: OnlyKey = OnlyKey::new();
    let expected_onlykey = construct_expected_onlykey_ecc(); 
    onlykey.set_backup_ecc_key(vec![0x01; 32], ECCKeyType::X25519).expect("Problem setting backup ECC key");
    onlykey.load_backup(common::BACKUP_ECC_STR).unwrap();

    println!("Expected: {:#?}", expected_onlykey);
    println!("Got: {:#?}", onlykey);
    
    assert_eq!(onlykey, expected_onlykey);
}

#[test]
fn verify_backup_good() {
    install_test_logger();
    assert!(verify_backup(common::BACKUP_STR).unwrap());
}

#[test]
fn verify_backup_bad() {
    install_test_logger();
    assert!(!verify_backup(common::BACKUP_BAD_STR).unwrap());
}