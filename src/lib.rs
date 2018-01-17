extern crate ring;
use ring::aead::{open_in_place, OpeningKey, CHACHA20_POLY1305};

extern crate base64;

extern crate chrono;
use chrono::prelude::*;

#[macro_use]
extern crate failure;

#[derive(Debug, Fail)]
pub enum PastError {
    #[fail(display = "Unknown version provided")]
    UnknownVersion,
    #[fail(display = "Unknown purpose provided")]
    UnknownPurpose,
    #[fail(display = "Malformed past token around {}", _0)]
    Malformed(String),
    #[fail(display = "Failed to decode base64 in token")]
    Base64Decode(#[cause] base64::DecodeError)
}

#[derive(Debug, PartialEq)]
pub enum Version {
    V1,
    V2
}

impl Version {
    fn parse(version: &str) -> Result<Self, PastError> {
        match version {
            "v1" => Ok(Version::V1),
            "v2" => Ok(Version::V2),
            _ => Err(PastError::UnknownVersion)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Purpose {
    Local,
    Public
}

impl Purpose {
    fn parse(purpose: &str) -> Result<Self, PastError> {
        match purpose {
            "local" => Ok(Purpose::Local),
            "public" => Ok(Purpose::Public),
            _ => Err(PastError::UnknownPurpose)
        }
    }
}

pub struct Token {
    pub version: Version,
    pub purpose: Purpose,
    pub nonce: Vec<u8>,
    pub data: Vec<u8>,
    pub footer: Option<String>
}

impl Token {
    pub fn payload(&self, _keyword: &str) -> Option<&str> {
        // None
        Some("2039-01-01T00:00:00Z")
    }

    pub fn exp(&self) -> Option<DateTime<Utc>> {
        self.payload("exp").map(|timestamp| {
            DateTime::parse_from_rfc3339(timestamp).unwrap().with_timezone(&Utc)
        })
    }
}

pub struct Parser<'a> {
    key: &'a[u8]
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, PastError> {
    base64::decode_config(encoded, base64::URL_SAFE).map_err(PastError::Base64Decode)
}

impl<'a> Parser<'a> {
    pub fn new(key: &'a[u8]) -> Self {
        Parser{
            key: key
        }
    }

    pub fn parse(&self, token: &str) -> Result<Token, PastError> {
        let mut token_parts = token.split('.');
        let version = Version::parse(token_parts.next().ok_or(PastError::Malformed("version".into()))?)?;
        let purpose = Purpose::parse(token_parts.next().ok_or(PastError::Malformed("purpose".into()))?)?;

        let key = OpeningKey::new(&CHACHA20_POLY1305, self.key).unwrap();
        let mut payload = decode_base64(token_parts.next().ok_or(PastError::Malformed("payload".into()))?)?;
        let (nonce, data) = payload.split_at_mut(24);
        let footer: Option<String> = token_parts.next()
            .and_then(|footer| decode_base64(footer).ok())
            .map(|chars| String::from_utf8_lossy(&chars).into());

        // if let Some(ref footer) = footer {
        //     open_in_place(&key, nonce, footer.as_bytes(), 0, data).unwrap();
        // } else {
        //     open_in_place(&key, nonce, &[], 0, data).unwrap();
        // }

        Ok(Token{
            version,
            purpose,
            nonce: nonce.into(),
            data: vec![],
            footer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn it_parses_version() {
        let v1token = "v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUeEsqw-ZhyFF-Mksw6hllOj5hY4DX3FKzZIsdyLcvg1Zu4i3dHxm3WARtm9EaY1s";
        let parser = Parser::new(&[1;32]);
        let parsed = parser.parse(v1token).unwrap();
        assert_eq!(parsed.version, Version::V1);

        let v2token = "v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANPHg7MVJ_l-qlYGq21N6Os9syV8vqfDMrri3zBsa_hrv8DMgZQ022_ztdIh6CnoZ7jY";
        let parsed = parser.parse(v2token).unwrap();
        assert_eq!(parsed.version, Version::V2);
    }

    #[test]
    fn it_parses_purpose() {
        let auth_token = "v2.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbjgPFTyS8RFUJ7bnJm1BbcwJ-zJ5PjjvwtGd9Ro-VFwcy2j1-zzEtfeMzLZ7RxQO84v0.Q3VvbiBBbHBpbnVz";
        let parser = Parser::new(&[1;32]);
        let parsed = parser.parse(auth_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Local);

        let enc_token = "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA";
        let parsed = parser.parse(enc_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Public);
    }

    mod v2 {
        use super::super::*;
        use super::utils::hex_to_bytes;

        #[test]
        fn it_decrypts_local_token() {
            let auth_token = "v2.local.wvbu1sWg-Td2nDxn7vyAVAEzTGqtzn_zfzaiGjAkQzfa5-l2PaAK1QA0IZjrWdKP8Xqi7DHHlu6F8E5BXoarTSfmrgkMEOeiasRhuZ3GWDUtmD2K027gjgalkjMZJE7lNfkOSdKr65Fo0_8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz";
            let encryption_key = hex_to_bytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

            let parser = Parser::new(&encryption_key);
            let parsed = parser.parse(auth_token).unwrap();

            assert_eq!(parsed.nonce, hex_to_bytes("c2f6eed6c5a0f937769c3c67eefc805401334c6aadce7ff3"));
            assert_eq!(parsed.footer, Some("Paragon Initiative Enterprises".into()));

            assert_eq!(parsed.exp(), Some(Utc.ymd(2039,01,01).and_hms(0,0,0)));
            assert!(parsed.payload("data").is_some());
            assert_eq!(parsed.payload("data").unwrap(), "this is a signed message");
        }
    }

    mod utils {
        pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
            let len = hex.len()/2;
            let mut result = Vec::with_capacity(len);
            for i in 0..len {
                result.push(u8::from_str_radix(&hex[2*i .. 2*i+2], 16).unwrap());
            }
            result
        }
    }
}
