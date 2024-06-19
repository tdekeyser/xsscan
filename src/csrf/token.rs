use http::Request;
use regex::Regex;

use crate::traits::{Body, RequestParser};

#[derive(Debug, PartialEq)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

pub struct CsrfTokenParser {}

impl RequestParser<CsrfToken> for CsrfTokenParser {
    fn parse(&self, request: &Request<Body>) -> Option<CsrfToken> {
        Self::extract_token_from_body(request)
            .or(Self::extract_token_from_headers(request))
    }
}

impl CsrfTokenParser {
    pub fn new() -> Self {
        Self {}
    }

    fn extract_token_from_body(request: &Request<Body>) -> Option<CsrfToken> {
        match request.body() {
            Body::Text(s) => Self::capture_token(s),
        }
    }

    fn capture_token(body: &String) -> Option<CsrfToken> {
        let token_matcher = "[cx]srf[_-]?token|authenticity[_-]?token|token|[cx]srf";
        let regex = format!(
            r#"(?i)({})["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_=]+)["']?"#,
            token_matcher
        );

        Regex::new(regex.as_str())
            .unwrap()
            .captures(body.as_str())
            .and_then(|caps| Some(CsrfToken(caps[2].to_string())))
    }

    fn extract_token_from_headers(request: &Request<Body>) -> Option<CsrfToken> {
        let possible_headers = [
            "X-XSRF-TOKEN",  // Angular default
            "X-CSRF-TOKEN",  // Laravel default
        ];

        for header in &possible_headers {
            if let Some(token) = request.headers().get(*header) {
                return Some(CsrfToken::new(token.to_str().unwrap_or_default()));
            }
        }
        None
    }
}


#[cfg(test)]
mod tests {
    use reqwest::header::CONTENT_TYPE;

    use crate::csrf::token::{CsrfToken, CsrfTokenParser};
    use crate::traits::{Body, RequestParser};

    macro_rules! find_token_in_request {
        ( $( $name:ident : ( $body_token_name:expr , $header_token_name:expr ) , )* ) => {
            $(
                #[test]
                fn $name() {
                    let request = http::Request::builder()
                        .method("POST")
                        .uri("https://example.com/change-email")
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .header($header_token_name, "1RANDOM_CSRF_TOKEN34==")
                        .body(Body::Text(format!("{}=1RANDOM_CSRF_TOKEN34==&email=test@hello.com", $body_token_name)))
                        .unwrap();

                    let result = CsrfTokenParser::new().parse(&request);
                    assert_eq!(result, Some(CsrfToken::new("1RANDOM_CSRF_TOKEN34==")));
                }
            )*
        }
    }

    find_token_in_request! {
        test_with_header_xsrf: ("nothing", "X-XSRF-TOKEN"),
        test_with_header_csrf: ("nothing", "X-CSRF-TOKEN"),
        test_with_body_token: ("token", "UNUSED"),
        test_with_body__token: ("_token", "UNUSED"),
        test_with_body__csrf: ("_csrf", "UNUSED"),
        test_with_body_xsrf_token: ("xsrf-token", "UNUSED"),
        test_with_body_xsrf: ("xsrf", "UNUSED"),
        test_with_body_token_cap: ("Token", "UNUSED"),
        test_with_body_csrf_token: ("csrf_token", "UNUSED"),
        test_with_body_csrf_token_cap: ("CsrfToken", "UNUSED"),
        test_with_body_capitalized: ("CSRFToken", "UNUSED"),
        test_with_body_authenticity: ("authenticity_token", "UNUSED"),
    }

    #[test]
    fn no_token_found() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/change-email")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::Text("email=test@hello.com".to_string()))
            .unwrap();

        assert_eq!(CsrfTokenParser::new().parse(&request), None);
    }
}
