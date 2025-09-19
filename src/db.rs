use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{ Pool, Postgres};
use uuid::Uuid;

use crate::models::{User, UserRole};

#[derive(Debug, Clone)]
pub struct DbClient {
    pool: Pool<Postgres>,
}

impl DbClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DbClient { pool }
    }
}

#[async_trait]
pub trait UserEx {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        email: Option<&str>,
        name: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;
    async fn get_users(&self, page: u32, limit: u32) -> Result<Vec<User>, sqlx::Error>;
    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expiry_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error>;
    async fn update_user<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: Option<T>,
    ) -> Result<User, sqlx::Error>;
    async fn get_user_count(&self) -> Result<i64, sqlx::Error>;
    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;

    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error>;

    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;
}

#[async_trait]
impl UserEx for DbClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        email: Option<&str>,
        name: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;
        if let Some(user_id) = user_id {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE id = $1"#,
                user_id
            )
            .fetch_optional(&self.pool)
            .await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE email = $1"#,
                email
            )
            .fetch_optional(&self.pool)
            .await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE name = $1"#,
                name
            )
            .fetch_optional(&self.pool)
            .await?;
        } else if let Some(token) = token {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE verification_token = $1"#,
                token
            )
            .fetch_optional(&self.pool)
            .await?;
        }
        Ok(user)
    }
    async fn get_users(&self, page: u32, limit: u32) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit;
        let users = sqlx::query_as!(
            User,
            r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }
    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expiry_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"INSERT INTO users (name, email, password, verification_token, token_expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole""#,
            name.into(),
            email.into(),
            password.into(),
            verification_token.into(),
            token_expiry_at
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }
    async fn update_user<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: Option<T>,
    ) -> Result<User, sqlx::Error> {
        let user = if let Some(name) = name {
            sqlx::query_as!(
                User,
                r#"UPDATE users SET name = $1, updated_at = NOW() WHERE id =    $2 RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole""#,
                name.into(),
                user_id
            )
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE id = $1"#,
                user_id
            )
            .fetch_one(&self.pool)
            .await?
        };
        Ok(user)
    }
    async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }
    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole""#,
            name.into(),
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }
    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole""#,
            role as UserRole,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }
    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole""#,
            password,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }
    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"UPDATE users SET verified = TRUE, verification_token = NULL, token_expires_at = NULL, updated_at = NOW() WHERE verification_token = $1 AND token_expires_at > NOW() RETURNING id"#,
            token
        )
        .fetch_optional(&self.pool)
        .await?;
        if result.is_some() {
            Ok(())
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    }
    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"UPDATE users SET verification_token = $1, token_expires_at = $2, updated_at = NOW() WHERE id = $3 RETURNING id"#,
            token,
            expires_at,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        if result.is_some() {
            Ok(())
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    }
}
