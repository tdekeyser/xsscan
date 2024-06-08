use regex::Regex;
use reqwest::Request;

use crate::traits::ExtractToken;

#[derive(Debug, PartialEq)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

pub struct CsrfTokenExtractor {}

impl ExtractToken<CsrfToken> for CsrfTokenExtractor {
    fn extract_token(&self, request: &Request) -> Option<CsrfToken> {
        if let Some(body_token) = Self::extract_token_from_body(request) {
            return Some(CsrfToken(body_token));
        }
        Self::extract_token_from_headers(request)
    }
}

impl CsrfTokenExtractor {
    pub fn new() -> Self {
        Self {}
    }

    fn extract_token_from_body(request: &Request) -> Option<String> {
        request.body()?
            .as_bytes()
            .and_then(|b| String::from_utf8(b.into()).ok())
            .and_then(Self::capture_token)
    }

    fn capture_token(body: String) -> Option<String> {
        let re = Regex::new(r#"(?i)(csrf[_-]?token|authenticity[_-]?token|token|csrf)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_=]+)["']?"#).unwrap();
        if let Some(caps) = re.captures(body.as_str()) {
            return Some(caps[2].to_string());
        }
        None
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

    use crate::csrf::token::{CsrfToken, CsrfTokenExtractor};
    use crate::traits::ExtractToken;

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

                    let result = CsrfTokenExtractor::new().extract_token(&request);
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
}
