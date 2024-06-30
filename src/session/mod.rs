use http::Request;
use regex::Regex;

use crate::shared_kernel::http::{Body, RequestParser};

#[derive(PartialEq, Debug)]
pub struct SessionCookie(String);

impl SessionCookie {
    pub fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

pub struct SessionCookieParser;

impl RequestParser<SessionCookie> for SessionCookieParser {
    fn parse(&self, request: &Request<Body>) -> Option<SessionCookie> {
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

        let cookies = Self::get_cookies(request);

        let pattern = format!(r"(?i)({})\s*=([^&]+)", session_cookie_names.join("|"));
        let re = Regex::new(&pattern).unwrap();

        re.captures(cookies.as_str())
            .map(|caps| SessionCookie(caps[2].to_string()))
    }
}

impl SessionCookieParser {
    fn get_cookies(request: &Request<Body>) -> String {
        request.headers()
            .get("Cookie")
            .and_then(|cookies| cookies.to_str().ok())
            .unwrap_or_default()
            .to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{SessionCookie, SessionCookieParser};
    use crate::shared_kernel::http::{Body, RequestParser};

    const EMPTY_BODY: Body = Body::Text(String::new());

    #[test]
    fn find_session_cookie() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .header("Cookie", "JSESSIONID=1234sess==&username=hello")
            .body(EMPTY_BODY)
            .unwrap();

        assert_eq!(SessionCookieParser.parse(&request),
                   Some(SessionCookie::new("1234sess==")));
    }

    #[test]
    fn find_session_cookie2() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .header("Cookie", "ASP.NET_SessionId=1234sess==")
            .body(EMPTY_BODY)
            .unwrap();

        assert_eq!(SessionCookieParser.parse(&request),
                   Some(SessionCookie::new("1234sess==")));
    }

    #[test]
    fn find_session_cookie_does_not_exist() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .header("Cookie", "username=hello")
            .body(EMPTY_BODY)
            .unwrap();

        assert_eq!(SessionCookieParser.parse(&request), None);
    }

    #[test]
    fn find_session_cookie_no_cookies() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .body(EMPTY_BODY)
            .unwrap();

        assert_eq!(SessionCookieParser.parse(&request), None);
    }
}
