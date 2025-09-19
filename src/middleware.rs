use core::str;
use std::sync::Arc;
use axum::{extract::Request, http::{header, StatusCode}, middleware::Next, response::{IntoResponse, Response}, Extension};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use crate::{AppState, error::{HttpError,ErrorMessage},db::UserEx,models::{User,UserRole},utlis::token};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthMiddleware {
    pub user: User,
}

pub  async fn auth(
    cookie_jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next,
)-> Result<Response, HttpError> {
    let cookies = cookie_jar.get("token").map(|cookie| cookie.value().to_string()).or_else(|| {
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|header_value| header_value.to_str().ok())
            .and_then(|auth_str| {
                if auth_str.starts_with("Bearer ") {
                    Some(auth_str[7..].to_string())
                } else {
                    None
                }
            })
    });
    let token = match cookies {
        Some(token) => token,
        None => {
            return Err(HttpError {
                status: StatusCode::UNAUTHORIZED,
                message: ErrorMessage::TokenNotProvided.to_string(),
            });
        }
    };
    let user_id_str = token::decode_token(&token, state.env.jwt_secret.as_bytes())?;
    let user_id = uuid::Uuid::parse_str(&user_id_str).map_err(|_| HttpError {
        status: StatusCode::UNAUTHORIZED,
        message: ErrorMessage::UserNotAuthenticated.to_string(),
    })?;
    let user = state.db_client.get_user(Some(user_id), None, None, None).await.map_err(|_| HttpError {
        status: StatusCode::UNAUTHORIZED,
        message: ErrorMessage::UserNotAuthenticated.to_string(),
    })?;
 let user = user.ok_or_else(|| {
        HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string())
    })?;

    req.extensions_mut().insert(JWTAuthMiddleware {
        user: user.clone(),
    });

    Ok(next.run(req).await)
}

pub async fn role_check(
    Extension(_state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
        required_roles: Vec<UserRole>,
) -> Result<impl IntoResponse, HttpError> {
    let user = req
            .extensions()
            .get::<JWTAuthMiddleware>()
            .ok_or_else(|| {
                HttpError::unauthorized(ErrorMessage::UserNotAuthenticated.to_string())
            })?;
    
    if !required_roles.contains(&user.user.role) {
        return Err(HttpError::new(ErrorMessage::PermissionDenied.to_string(), StatusCode::FORBIDDEN));
    }


    Ok(next.run(req).await)
}