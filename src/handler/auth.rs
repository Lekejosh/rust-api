use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, put},
};
use axum_extra::extract::cookie::Cookie;
use chrono::{Duration, Utc};
use time::util;
use validator::Validate;

use crate::{
    AppState,
    db::UserEx,
    dto::{LoginResponseDto, LoginUserDto, RegisterUserDto, VerifyEmailQueryDto},
    error::{ErrorMessage, HttpError},
    helper::mailer::mail::send_verification_email,
    utlis::{password, token},
};

pub fn auth_handler() -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/verify/email", put(verify_email))
}

async fn login(
    Extension(state): Extension<std::sync::Arc<crate::AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = state
        .db_client
        .get_user(None, Some(&body.email), None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let user =
        user.ok_or_else(|| HttpError::unauthorized("Invalid email or password".to_string()))?;

    if !password::compare(&user.password, &body.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?
    {
        return Err(HttpError::unauthorized(
            "Invalid email or password".to_string(),
        ));
    }
    let token = token::create_token(&user.id.to_string(), &state.env.jwt_secret.as_bytes(), 3600)
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let cookie_duration = time::Duration::hours(1);
    let cookie = Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .build();

    let response = LoginResponseDto {
        status: "success".to_string(),
        token,
    };
    Ok(Json(response))
}
async fn register(
    Extension(state): Extension<std::sync::Arc<crate::AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let existing_user = state
        .db_client
        .get_user(None, Some(&body.email), None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if existing_user.is_some() {
        return Err(HttpError::bad_request("Email already in use".to_string()));
    }
    let hashed_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;
    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

    let _ = state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hashed_password,
            &verification_token,
            expires_at,
        )
        .await;
    send_verification_email(&body.email, &verification_token).await;
    #[derive(serde::Serialize)]
    struct RegisterResponse {
        status: String,
        message: String,
    }

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            status: "success".to_string(),
            message: "User registered successfully".to_string(),
        }),
    ))
}
async fn verify_email(
    Query(query_params): Query<VerifyEmailQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&query_params.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request(
                "Verification token has expired".to_string(),
            ))?;
        }
    } else {
        return Err(HttpError::bad_request(
            "Invalid verification token".to_string(),
        ))?;
    }

    app_state
        .db_client
        .verifed_token(&query_params.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": "Email verified successfully"
        })),
    ))
}
