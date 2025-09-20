use lettre::message::header::Subject;

use crate::helper::mailer::mailer::send_email;

pub async fn send_verification_email(
    to: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {

    let subject = "Verify your email address";

    let url = format!("http://0.0.0.0:8000/api/users/verify?token={}", token);

    let body = format!(
        "<h1>Email Verification</h1>
     <p>Please click the link below to verify your email address:</p>
     <a href=\"{}\">Verify Email</a>",
        url
    );


    // Add error context to help debug where the error comes from
    send_email(to, subject, &body)
        .await
        .map_err(|e| {
            eprintln!("Error sending email: {:?}", e);
            e.into()
        })
}
