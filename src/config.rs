#[derive(Debug,Clone)]
pub struct Config {
    pub database_url: String,
    pub server_port: u16,
    pub jwt_secret: String,
    pub smtp_host: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
}

impl Config {
    pub fn init() -> Self {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let server_port = std::env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("SERVER_PORT must be a valid u16");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let smtp_host = std::env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
        let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
        let smtp_from_address = std::env::var("SMTP_FROM_ADDRESS").expect("SMTP_FROM_ADDRESS must be set");

        Config {
            database_url,
            server_port,
            jwt_secret,
            smtp_host,
            smtp_username,
            smtp_password,
            smtp_from_address,
        }
    }
    
}