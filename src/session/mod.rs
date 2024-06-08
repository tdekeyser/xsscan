use regex::Regex;
use reqwest::header::COOKIE;
use reqwest::Request;

use crate::traits::DetectSession;

pub struct SessionCookieDetector {}

impl DetectSession for SessionCookieDetector {
    fn uses_session(&self, request: &Request) -> bool {
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

        let pattern = format!(r"(?i)({})\s*=", session_cookie_names.join("|"));
        let re = Regex::new(&pattern).unwrap();

        let cookies = Self::get_cookies(request);
        re.is_match(cookies.as_str())
    }
}

impl SessionCookieDetector {
    fn new() -> SessionCookieDetector {
        SessionCookieDetector {}
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

    use crate::session::{DetectSession, SessionCookieDetector};

    #[test]
    fn find_session_cookie() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "JSESSIONID=1234sess==&username=hello")
            .build()
            .unwrap();

        assert!(SessionCookieDetector::new().uses_session(&request));
    }

    #[test]
    fn find_session_cookie_does_not_exist() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "username=hello")
            .build()
            .unwrap();

        assert!(!SessionCookieDetector::new().uses_session(&request));
    }

    #[test]
    fn find_session_cookie_no_cookies() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .build()
            .unwrap();

        assert!(!SessionCookieDetector::new().uses_session(&request));
    }
}
