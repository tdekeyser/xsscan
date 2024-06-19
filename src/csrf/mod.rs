use http::Request;

use crate::csrf::token::CsrfToken;
use crate::session::SessionCookie;
use crate::traits::{Body, RequestParser};

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

impl From<&Request<Body>> for VulnerableRequest {
    fn from(r: &Request<Body>) -> Self {
        Self {
            url: r.uri().to_string(),
            method: r.method().to_string(),
            body: match r.body() {
                Body::Text(b) => b.to_string(),
            },
        }
    }
}

struct CsrfTester {
    session: Box<dyn RequestParser<SessionCookie>>,
    csrf_token: Box<dyn RequestParser<CsrfToken>>,
}

impl CsrfTester {
    pub fn new(session: Box<dyn RequestParser<SessionCookie>>,
               csrf_token: Box<dyn RequestParser<CsrfToken>>) -> Self {
        Self { session, csrf_token }
    }

    fn test_vulnerability(&self, request: &Request<Body>) -> Option<VulnerableRequest> {
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
    use http::Request;

    use crate::csrf::{CsrfTester, VulnerableRequest};
    use crate::csrf::token::CsrfToken;
    use crate::session::SessionCookie;
    use crate::traits::{Body, RequestParser};

    const EMPTY_BODY: Body = Body::Text(String::new());

    #[derive(Clone)]
    pub struct MockParser {
        session: fn() -> Option<SessionCookie>,
        csrf_token: fn() -> Option<CsrfToken>,
    }

    impl RequestParser<SessionCookie> for MockParser {
        fn parse(&self, _: &Request<Body>) -> Option<SessionCookie> {
            (self.session)()
        }
    }

    impl RequestParser<CsrfToken> for MockParser {
        fn parse(&self, _: &Request<Body>) -> Option<CsrfToken> {
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

        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .body(EMPTY_BODY)
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

        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .body(EMPTY_BODY)
            .unwrap();

        assert_eq!(tester.test_vulnerability(&request), Some(VulnerableRequest {
            url: String::from("https://example.com/change-email"),
            method: String::from("POST"),
            body: String::new(),
        }));
    }
}
