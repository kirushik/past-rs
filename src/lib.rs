extern crate chrono;
use chrono::{DateTime, TimeZone, Utc};

extern crate base64;
use base64::decode as decode_base64;

use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum Version {
    V1,
    V2
}

impl Version {
    fn parse(version: &str) -> Result<Self, ()> {
        match version {
            "v1" => Ok(Version::V1),
            "v2" => Ok(Version::V2),
            _ => Err(())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Purpose {
    Enc,
    Auth,
    Sign,
    Seal
}

impl Purpose {
    fn parse(purpose: &str) -> Result<Self, ()> {
        match purpose {
            "enc" => Ok(Purpose::Enc),
            "auth" => Ok(Purpose::Auth),
            "sign" => Ok(Purpose::Sign),
            "seal" => Ok(Purpose::Seal),
            _ => Err(())
        }
    }
}

pub struct Token<'a> {
    pub version: Version,
    pub purpose: Purpose,
    payload: HashMap<&'a str, &'a str>
}

impl<'a> Token<'a> {
    fn claim(&self, claim: &str) -> Option<Cow<'a, str>> {
        self.payload.get(claim).map(|s| Cow::Borrowed(*s))
    }
    fn expiration(&self) -> DateTime<Utc> {
        let exp = self.claim("exp".into()).unwrap();
        DateTime::from_str(&exp).unwrap()
    }
}

pub struct Parser<'a> {
    key: &'a[u8]
}

impl<'a> Parser<'a> {
    pub fn new(key: &'a[u8]) -> Self {
        Parser{key: key}
    }

    pub fn parse(&self, token: &str) -> Result<Token, ()> {
        let mut token_parts = token.split('.');
        let version = token_parts.next().map(Version::parse).unwrap().unwrap();
        let purpose = token_parts.next().map(Purpose::parse).unwrap().unwrap();

        let payload = token_parts.next().map(decode_base64).unwrap().unwrap();
        let payload = String::from_utf8_lossy(&payload);
        println!("{:?}", payload);

        Ok(Token{
            version: version,
            purpose: purpose,
            payload: HashMap::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_version() {
        let parser = Parser::new(b"");

        let v1token = "v1.auth.JEEQ-GXQAK2qNYilKVXynuLhlXUw8xdeHNhsBH8OMA6mS_sYMzavZ_kUrdMgmNKr.Q3VvbiBBbHBpbnVz";
        let parsed = parser.parse(v1token).unwrap();
        assert_eq!(parsed.version, Version::V1);

        let v2token = "v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9VpWy4KU60YnKUzTkixFi9foXhXKTHbcDBtpg7oWllm8=";
        let parsed = parser.parse(v2token).unwrap();
        assert_eq!(parsed.version, Version::V2);
    }

    #[test]
    fn it_parses_purpose() {
        let parser = Parser::new(b"");

        let auth_token = "v1.auth.RnJhbmsgRGVuaXMgcm9ja3OvktwlGNM0U3P2mAbLVKRcHWC33xXQwVN-IlE8M3idKitswqz33kA5q2ThfOT4uqU=";
        let parsed = parser.parse(auth_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Auth);

        let enc_token = "v2.enc.fQ4M1i14faUzIeZjx2IhUO81i-WKGCcl-mq7aZy7DoCjzfSP56R0Q-BetD4=";
        let parsed = parser.parse(enc_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Enc);

        let sign_token = "v2.sign.dGVzdJsRKYq_t46b7FkYA4hl9tZOZfeUTU7LZtYqZfXHLBnsyKnQpZLbLi4a5eyaFXDNQ6XyoK_TynN3wTs4L58eFwY=";
        let parsed = parser.parse(sign_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Sign);

        let seal_token = "v2.seal.mvzgGLk3_3KKJHgexR1XB5mQWg_w5a1LbWJxvz3PXUQ=.fN43buRTs_qcW3Jd3QAJXtRZV9rgCttzK9XCQmCc09EDJ-PpcDfUBYoC7SQ=";
        let parsed = parser.parse(seal_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Seal);
    }

    mod v2 {
        use super::super::*;

        #[test]
        fn it_verifies_auth() {
            let parser = Parser::new(b"");
            let token = "v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9VpWy4KU60YnKUzTkixFi9foXhXKTHbcDBtpg7oWllm8";

            let parsed = parser.parse(token).unwrap();

            assert_eq!(parsed.expiration(), Utc.ymd(2039, 01, 01).and_hms(0, 0, 0));
            assert!(parsed.claim("data").is_some());
            assert_eq!(parsed.claim("data").unwrap(), "this is a signed message");
        }
    }

}
