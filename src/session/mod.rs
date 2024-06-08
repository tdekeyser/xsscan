use regex::Regex;
use reqwest::header::COOKIE;
use reqwest::Request;

use crate::traits::{ParseToken};

#[derive(PartialEq, Debug)]
pub struct SessionCookie(String);

impl SessionCookie {
    pub fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

pub struct SessionCookieParser {}

impl ParseToken<SessionCookie> for SessionCookieParser {
    fn parse(&self, request: &Request) -> Option<SessionCookie> {
        let session_cookie_names = [
            "JSESSIONID",
            "PHPSESSID",
            "ASP\\.NET_SessionId",
            "ASPSESSIONID",
            "session",
            "sessid",
            "connect\\.sid",
            "sid"
        ];

        let pattern = format!(r"(?i)({})\s*=([^&]+)", session_cookie_names.join("|"));
        let re = Regex::new(&pattern).unwrap();

        let cookies = Self::get_cookies(request);

        match re.captures(cookies.as_str()) {
            Some(caps) => Some(SessionCookie(caps[2].to_string())),
            None => None
        }
    }
}

impl SessionCookieParser {
    fn new() -> SessionCookieParser {
        SessionCookieParser {}
    }

    fn get_cookies(request: &Request) -> String {
        request.headers()
            .get(COOKIE)
            .and_then(|cookies| cookies.to_str().ok())
            .unwrap_or_default()
            .to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use reqwest::header::COOKIE;

    use crate::session::{SessionCookie, SessionCookieParser};
    use crate::traits::ParseToken;

    #[test]
    fn find_session_cookie() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "JSESSIONID=1234sess==&username=hello")
            .build()
            .unwrap();

        assert_eq!(SessionCookieParser::new().parse(&request),
                   Some(SessionCookie::new("1234sess==")));
    }

    #[test]
    fn find_session_cookie2() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "ASP.NET_SessionId=1234sess==")
            .build()
            .unwrap();

        assert_eq!(SessionCookieParser::new().parse(&request),
                   Some(SessionCookie::new("1234sess==")));
    }

    #[test]
    fn find_session_cookie_does_not_exist() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "username=hello")
            .build()
            .unwrap();

        assert_eq!(SessionCookieParser::new().parse(&request), None);
    }

    #[test]
    fn find_session_cookie_no_cookies() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .build()
            .unwrap();

        assert_eq!(SessionCookieParser::new().parse(&request), None);
    }
}
