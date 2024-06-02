use regex::Regex;
use reqwest::header::COOKIE;
use reqwest::Request;

pub struct SessionDetector {}

impl SessionDetector {
    pub fn uses_session_cookie(request: &Request) -> bool {
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

    use crate::session::SessionDetector;

    #[test]
    fn find_session_cookie() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "JSESSIONID=1234sess==&username=hello")
            .build()
            .unwrap();

        assert!(SessionDetector::uses_session_cookie(&request));
    }

    #[test]
    fn find_session_cookie_does_not_exist() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(COOKIE, "username=hello")
            .build()
            .unwrap();

        assert!(!SessionDetector::uses_session_cookie(&request));
    }

    #[test]
    fn find_session_cookie_no_cookies() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .build()
            .unwrap();

        assert!(!SessionDetector::uses_session_cookie(&request));
    }
}
