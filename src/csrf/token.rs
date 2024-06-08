use regex::Regex;
use reqwest::Request;

use crate::traits::ParseToken;

#[derive(Debug, PartialEq)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

pub struct CsrfTokenParser {}

impl ParseToken<CsrfToken> for CsrfTokenParser {
    fn parse(&self, request: &Request) -> Option<CsrfToken> {
        Self::extract_token_from_body(request)
            .or(Self::extract_token_from_headers(request))
    }
}

impl CsrfTokenParser {
    pub fn new() -> Self {
        Self {}
    }

    fn extract_token_from_body(request: &Request) -> Option<CsrfToken> {
        request.body()?
            .as_bytes()
            .and_then(|b| String::from_utf8(b.into()).ok())
            .and_then(Self::capture_token)
    }

    fn capture_token(body: String) -> Option<CsrfToken> {
        Regex::new(r#"(?i)(csrf[_-]?token|authenticity[_-]?token|token|csrf)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_=]+)["']?"#)
            .unwrap()
            .captures(body.as_str())
            .and_then(|caps| Some(CsrfToken(caps[2].to_string())))
    }

    fn extract_token_from_headers(request: &Request) -> Option<CsrfToken> {
        let possible_headers = [
            "X-XSRF-TOKEN",  // Angular default
            "X-CSRF-TOKEN",  // Laravel default
        ];

        for header in &possible_headers {
            if let Some(token) = request.headers().get(*header) {
                return Some(CsrfToken(token.to_str().unwrap_or_default().to_string()));
            }
        }
        None
    }
}


#[cfg(test)]
mod tests {
    use reqwest::header::CONTENT_TYPE;

    use crate::csrf::token::{CsrfToken, CsrfTokenParser};
    use crate::traits::ParseToken;

    macro_rules! find_token_in_request {
        ( $( $name:ident : ( $body_token_name:expr , $header_token_name:expr ) , )* ) => {
            $(
                #[test]
                fn $name() {
                    let request = reqwest::Client::new()
                        .post("https://example.com/change-email")
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .header($header_token_name, "1RANDOM_CSRF_TOKEN34==")
                        .body(format!("{}=1RANDOM_CSRF_TOKEN34==&email=test@hello.com", $body_token_name))
                        .build()
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
        test_with_body_token: ("token", "user-agent"),
        test_with_body_u_token: ("_token", "user-agent"),
        test_with_body_u_csrf: ("_csrf", "user-agent"),
        test_with_body_token_cap: ("Token", "user-agent"),
        test_with_body_csrf_token: ("csrf_token", "user-agent"),
        test_with_body_csrf_token_cap: ("CsrfToken", "user-agent"),
        test_with_body_capitalized: ("CSRFToken", "user-agent"),
        test_with_body_authenticity: ("authenticity_token", "user-agent"),
    }

    #[test]
    fn no_token_found() {
        let request = reqwest::Client::new()
            .post("https://example.com/change-email")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("email=test@hello.com")
            .build()
            .unwrap();

        assert_eq!(CsrfTokenParser::new().parse(&request), None);
    }
}
