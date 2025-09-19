
use core::str;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, UserRole};

#[derive(Debug, Deserialize, Serialize, Validate, Clone)]
pub struct RegisterUserDto {
    #[validate(length(min = 1, message = "Name cannot be empty"))]
    pub name: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters long"))]
    pub password: String,
    #[validate(must_match(other = "password", message = "Passwords do not match"))]
    pub confirm_password: String,
}

#[derive(Debug, Deserialize, Serialize, Validate, Clone)]
pub struct LoginUserDto {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters long"))]
    pub password: String,
}

#[derive(Deserialize, Serialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterUserDto {
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Option<UserRole>,
    pub verified: Option<bool>,
}
impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            name: Some(user.name.clone()),
            email: Some(user.email.clone()),
            role: Some(user.role),
            verified: Some(user.verified),
        }
    }
    pub fn filter_users(users: &Vec<User>) -> Vec<Self> {
        users.iter().map(|user| Self::filter_user(user)).collect()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub results: i64,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name cannot be empty"))]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdateDto {
    pub role: UserRole,
}
fn validate_user_role(role: &UserRole) -> Result<(), validator::ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
    }
}

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateDto {
    #[validate(length(min = 6, message = "new password must be at least 6 characters"))]
    pub new_password: String,

    #[validate(
        length(
            min = 6,
            message = "new password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,

    #[validate(length(min = 6, message = "Old password must be at least 6 characters"))]
    pub old_password: String,
}
#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct ResetPasswordRequestDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,

    #[validate(length(
        min = 6,
        message = "New password is required and must be at least 6 characters"
    ))]
    pub new_password: String,

    #[validate(
        length(
            min = 6,
            message = "new password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,
}
