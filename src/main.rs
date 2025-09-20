use std::sync::Arc;

use axum::{Extension, Router};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{self, CorsLayer};

use crate::{db::DbClient, routes::create_router};

mod config;
mod db;
mod dto;
mod error;
mod models;
mod utlis;
mod middleware;
mod routes;
mod handler;
mod helper;
// Define the AppState struct
#[derive(Clone)]
pub struct AppState {
    pub env: config::Config,
    pub db_client: DbClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv().ok();

    let config = config::Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("Connected to the database successfully.");
            pool
        }
        Err(e) => {
            eprintln!("Failed to connect to the database: {}", e);
            std::process::exit(1);
        }
    };
    let db_client = DbClient::new(pool);
    let app_state = AppState {
        env: config,
        db_client,
    };
     let app = create_router(Arc::new(app_state.clone()));

    
    println!(
        "{}",
        format!("🚀 Server is running on http://localhost:{}", app_state.env.server_port)
    );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &app_state.env.server_port))
    .await
    .unwrap();
    axum::serve(listener, app).await.unwrap();
}
