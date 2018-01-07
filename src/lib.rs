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
    Local,
    Public
}

impl Purpose {
    fn parse(purpose: &str) -> Result<Self, ()> {
        match purpose {
            "local" => Ok(Purpose::Local),
            "public" => Ok(Purpose::Public),
            _ => Err(())
        }
    }
}

pub struct Token {
    pub version: Version,
    pub purpose: Purpose,
    pub data: Vec<u8>
}

impl Token {
    pub fn parse(token: &str) -> Result<Self, ()> {
        let mut token_parts = token.split('.');
        let version = token_parts.next().map(Version::parse).unwrap().unwrap();
        let purpose = token_parts.next().map(Purpose::parse).unwrap().unwrap();
        Ok(Token{
            version: version,
            purpose: purpose,
            data: vec![]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_version() {
        let v1token = "v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUeEsqw-ZhyFF-Mksw6hllOj5hY4DX3FKzZIsdyLcvg1Zu4i3dHxm3WARtm9EaY1s";
        let parsed = Token::parse(v1token).unwrap();
        assert_eq!(parsed.version, Version::V1);

        let v2token = "v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANPHg7MVJ_l-qlYGq21N6Os9syV8vqfDMrri3zBsa_hrv8DMgZQ022_ztdIh6CnoZ7jY";
        let parsed = Token::parse(v2token).unwrap();
        assert_eq!(parsed.version, Version::V2);
    }

    #[test]
    fn it_parses_purpose() {
        let auth_token = "v2.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbjgPFTyS8RFUJ7bnJm1BbcwJ-zJ5PjjvwtGd9Ro-VFwcy2j1-zzEtfeMzLZ7RxQO84v0.Q3VvbiBBbHBpbnVz";
        let parsed = Token::parse(auth_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Local);

        let enc_token = "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA";
        let parsed = Token::parse(enc_token).unwrap();
        assert_eq!(parsed.purpose, Purpose::Public);
    }
}
