use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use serde::{Deserialize, Serialize};

use crate::error::{ErrorMessage, HttpError};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_token(
    user_id: &str,
    secret: &[u8],
    expiration_minutes: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSubject),
        ));
    }
    let now = Utc::now();
    let exp = now + Duration::minutes(expiration_minutes);
    let claims = TokenClaims {
        sub: user_id.to_owned(),
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidSubject.into())
}

pub fn decode_token(token: &str, secret: &[u8]) -> Result<String, HttpError> {
    let decode = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256),
    );
    match decode {
        Ok(token_data) => Ok(token_data.claims.sub),
        Err(_) => Err(HttpError {
            status: StatusCode::UNAUTHORIZED,
            message: ErrorMessage::InvalidToken.to_string(),
        }),
    }
}
