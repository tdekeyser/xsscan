use reqwest::Request;

use crate::csrf::token::CsrfToken;
use crate::session::SessionCookie;
use crate::traits::ParseToken;

mod token;
mod exploit;
mod origin;
mod csp;
mod samesite;

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
    session: Box<dyn ParseToken<SessionCookie>>,
    csrf_token: Box<dyn ParseToken<CsrfToken>>,
}

impl CsrfTester {
    pub fn new(session: Box<dyn ParseToken<SessionCookie>>,
               csrf_token: Box<dyn ParseToken<CsrfToken>>) -> Self {
        Self { session, csrf_token }
    }

    fn test_vulnerability(&self, request: &Request) -> Option<VulnerableRequest> {
        if let None = self.session.parse(&request) {
            return None;
        }

        match self.csrf_token.parse(&request) {
            Some(_) => None,
            None => Some(VulnerableRequest::from(request))
        }
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Request;

    use crate::csrf::{CsrfTester, VulnerableRequest};
    use crate::csrf::token::CsrfToken;
    use crate::session::SessionCookie;
    use crate::traits::ParseToken;

    #[derive(Clone)]
    pub struct MockParser {
        session: fn() -> Option<SessionCookie>,
        csrf_token: fn() -> Option<CsrfToken>,
    }

    impl ParseToken<SessionCookie> for MockParser {
        fn parse(&self, _: &Request) -> Option<SessionCookie> {
            (self.session)()
        }
    }

    impl ParseToken<CsrfToken> for MockParser {
        fn parse(&self, _: &Request) -> Option<CsrfToken> {
            (self.csrf_token)()
        }
    }

    #[test]
    fn not_vulnerable_if_no_session_cookies() {
        let mock: MockParser = MockParser {
            session: || None,
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
        let mock = MockParser {
            session: || Some(SessionCookie::new("a-session")),
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
