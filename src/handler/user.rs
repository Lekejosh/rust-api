use std::{sync::Arc, vec};

use axum::{
    Extension, Json, Router,
    extract::Query,
    middleware,
    response::IntoResponse,
    routing::{get, put},
};
use validator::Validate;

use crate::{
    AppState,
    db::UserEx,
    dto::{
        FilterUserDto, NameUpdateDto, RequestQueryDto, Response, RoleUpdateDto, UserData,
        UserListResponseDto, UserPasswordUpdateDto, UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::{JWTAuthMiddleware, role_check},
    models::UserRole,
    utlis::password,
};

pub fn users_handler() -> Router {
    Router::new()
        .route(
            "/",
            get(get_users).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        // .route("/:id", get(get_user_by_id))
        .route(
            "/me",
            get(get_current_user).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin, UserRole::User])
            })),
        )
        .route("/me/name", put(update_user_name))
        .route("/{id}/role", put(update_user_role))
}

pub async fn get_current_user(
    Extension(_state): Extension<std::sync::Arc<crate::AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<Json<UserResponseDto>, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);
    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };
    Ok(Json(response_data))
}
// pub async fn get_user_by_id(
//     Extension(state): Extension<std::sync::Arc<crate::AppState>>,
//     Extension(_user): Extension<JWTAuthMiddleware>,
//     axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
// ) -> Result<Json<UserResponseDto>, HttpError> {
//     let user = state
//         .db_client
//         .get_user(Some(id), None, None, None)
//         .await?
//         .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;
//     let filtered_user = FilterUserDto::filter_user(&user);
//     let response_data = UserResponseDto {
//         status: "success".to_string(),
//         data: UserData {
//             user: filtered_user,
//         },
//     };
//     Ok(Json(response_data))
// }
pub async fn get_users(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let users = app_state
        .db_client
        .get_users(page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_count = app_state
        .db_client
        .get_user_count()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&users),
        results: user_count,
    };

    Ok(Json(response))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<NameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_name(user_id.clone(), &body.name)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}
pub async fn update_user_role(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<RoleUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_role(user_id.clone(), body.role)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}
pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .get_user(Some(user_id.clone()), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    let password_match = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !password_match {
        return Err(HttpError::bad_request(
            "Old password is incorrect".to_string(),
        ));
    }

    let hash_password =
        password::hash(&body.new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password updated Successfully".to_string(),
        status: "success",
    };

    Ok(Json(response))
}
