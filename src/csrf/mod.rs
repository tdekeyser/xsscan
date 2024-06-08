use reqwest::Request;

use crate::csrf::token::CsrfToken;
use crate::traits::{DetectSession, ExtractToken};

mod token;
mod exploit;

#[derive(PartialEq, Debug, Clone)]
pub struct VulnerableRequest {
    url: String,
    method: String,
    body: String,
}

impl From<&Request> for VulnerableRequest {
    fn from(r: &Request) -> Self {
        Self {
            url: r.url().to_string(),
            method: r.method().to_string(),
            body: match r.body() {
                Some(b) => String::from_utf8(b.as_bytes().unwrap_or_default().into()).ok().unwrap(),
                None => String::new(),
            },
        }
    }
}

struct CsrfTester {
    detect_session: Box<dyn DetectSession>,
    token_extraction: Box<dyn ExtractToken<CsrfToken>>,
}

impl CsrfTester {
    pub fn new(detect_session: Box<dyn DetectSession>,
               token_extraction: Box<dyn ExtractToken<CsrfToken>>) -> Self {
        Self { detect_session, token_extraction }
    }

    fn test_vulnerability(&self, request: &Request) -> Option<VulnerableRequest> {
        if !self.detect_session.uses_session(&request) {
            return None
        }

        match self.token_extraction.extract_token(&request) {
            Some(csrf_token) => None,
            None => Some(VulnerableRequest::from(request))
        }
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Request;

    use crate::csrf::{CsrfTester, VulnerableRequest};
    use crate::csrf::token::CsrfToken;
    use crate::traits::{DetectSession, ExtractToken};

    #[derive(Clone)]
    pub struct MockDetector {
        has_session: bool,
        csrf_token: fn() -> Option<CsrfToken>,
    }

    impl DetectSession for MockDetector {
        fn uses_session(&self, _: &Request) -> bool {
            self.has_session
        }
    }

    impl ExtractToken<CsrfToken> for MockDetector {
        fn extract_token(&self, _: &Request) -> Option<CsrfToken> {
            (self.csrf_token)()
        }
    }

    #[test]
    fn not_vulnerable_if_no_session_cookies() {
        let mock: MockDetector = MockDetector {
            has_session: false,
            csrf_token: || None,
        };
        let tester = CsrfTester::new(Box::new(mock.clone()), Box::new(mock.clone()));

        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .build()
            .unwrap();

        assert_eq!(tester.test_vulnerability(&request), None);
    }

    #[test]
    fn vulnerable_if_session_cookie_and_no_csrf_token() {
        let mock = MockDetector {
            has_session: true,
            csrf_token: || None,
        };
        let tester = CsrfTester::new(Box::new(mock.clone()), Box::new(mock.clone()));

        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .build()
            .unwrap();

        assert_eq!(tester.test_vulnerability(&request), Some(VulnerableRequest {
            url: String::from("https://example.com/change-email"),
            method: String::from("POST"),
            body: String::new(),
        }));
    }
}
