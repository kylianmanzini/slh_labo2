use anyhow::{Result, anyhow};
use jsonwebtoken::{decode, Algorithm, Validation, DecodingKey};

pub enum Role {
    Access,
    Refresh,
}
/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid
/// Return an error if the JWT is invalid
/// DONE Verify
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
    let secret_key = "🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿🗿"; // TODO : Generate a clean key

    let decoding_key = match role {
        Role::Access => DecodingKey::from_secret(secret_key.as_ref()),
        Role::Refresh => DecodingKey::from_secret(secret_key.as_ref()),
    };

    let validation = Validation {
        algorithms: vec![Algorithm::HS256],
        ..Validation::default()
    };

    match decode::<Claims>(
        jwt.into().as_str(),
        &decoding_key,
        &validation,
    ) {
        Ok(token) => Ok(token.claims.email),
        Err(err) => Err(anyhow!("JWT verification failed: {}", err)),
    }
}

#[derive(Debug, serde::Deserialize)]
struct Claims {
    email: String
}
