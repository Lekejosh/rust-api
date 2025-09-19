use argon2::{password_hash::{rand_core::OsRng,PasswordHash,PasswordHasher,PasswordVerifier,SaltString}, Argon2};
use crate::error::ErrorMessage;

const MAX_PASSWORD_LENGTH: usize = 64;

pub fn hash(password:impl Into<String>) -> Result<String, ErrorMessage> {
    let password = password.into();
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string();
    Ok(hashed_password)
}

pub fn compare(stored_hash: &str, password: impl Into<String>) -> Result<bool, ErrorMessage> {
    let password = password.into();
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }
    let parsed_hash = PasswordHash::new(stored_hash).map_err(|_| ErrorMessage::InvalidHashFormat)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}