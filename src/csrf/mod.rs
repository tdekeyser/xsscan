use http::Request;

use crate::csrf::token::CsrfToken;
use crate::session::SessionCookie;
use crate::shared_kernel::http::{Body, RequestParser};

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

struct CsrfTester<S, C>
    where
        S: RequestParser<SessionCookie>,
        C: RequestParser<CsrfToken>,
{
    session: S,
    csrf_token: C,
}

impl<S, C> CsrfTester<S, C>
    where
        S: RequestParser<SessionCookie>,
        C: RequestParser<CsrfToken>,
{
    pub fn new(session: S, csrf_token: C) -> Self {
        Self { session, csrf_token }
    }

    fn test_vulnerability(&self, request: &Request<Body>) -> Option<VulnerableRequest> {
        if self.session.parse(&request).is_none() {
            return None;
        }
        if self.csrf_token.parse(&request).is_some() {
            return None;
        }
        Some(VulnerableRequest::from(request))
    }
}

#[cfg(test)]
mod tests {
    use http::Request;

    use crate::csrf::{CsrfTester, VulnerableRequest};
    use crate::csrf::token::CsrfToken;
    use crate::session::SessionCookie;
    use crate::shared_kernel::http::{Body, RequestParser};

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
        let tester = CsrfTester::new(mock.clone(), mock.clone());

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
        let tester = CsrfTester::new(mock.clone(), mock.clone());

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
