use std::env;

use dotenv::dotenv;
use lettre::{
    Message, SmtpTransport, Transport, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};

use crate::config;

pub async fn send_email(
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[DEBUG] Loading environment variables...");
    dotenv().ok();

    let config = config::Config::init();

    println!("[DEBUG] Reading SMTP configuration...");
    let smtp_server = config.smtp_host.clone();
    let smtp_username = config.smtp_username.clone();
    let smtp_password = config.smtp_password.clone();
    let smtp_from_address = config.smtp_from_address.clone();
    let smtp_port: u16 = config.smtp_port;

    let email = match Message::builder()
        .from(smtp_from_address.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body.to_string())
    {
        Ok(email) => email,
        Err(e) => {
            println!("[ERROR] Failed to build email message: {:?}", e);
            return Err(Box::new(e));
        }
    };

    let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());

  
    let mailer = match SmtpTransport::relay(&smtp_server) {
        Ok(builder) => builder.port(smtp_port).credentials(creds).build(),
        Err(e) => {
            println!("[ERROR] Failed to build SMTP transport: {:?}", e);
            return Err(Box::new(e));
        }
    };

    println!("[DEBUG] Sending email...");
    let result = mailer.send(&email);
    match result {
        Ok(_) => {
            println!("Email sent successfully!");
            Ok(())
        }
        Err(e) => {
            println!("[ERROR] Failed to send email: {:?}", e);
            Err(Box::new(e))
        }
    }
}
