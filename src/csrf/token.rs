use regex::Regex;
use reqwest::Request;

#[derive(Debug, PartialEq)]
struct CsrfToken(String);

pub struct CsrfTokenExtractor {}

impl CsrfTokenExtractor {
    pub fn extract(request: &Request) -> Option<CsrfToken> {
        if let Some(body_token) = Self::extract_token_from_body(request) {
            return Some(CsrfToken(body_token));
        }

        Self::extract_token_from_headers(request)
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

                    let result = CsrfTokenExtractor::extract(&request);
                    assert_eq!(result, Some(CsrfToken("1RANDOM_CSRF_TOKEN34==".to_string())));
                }
            )*
        }
    }

    find_token_in_request! {
        test_with_header_xsrf: ("nothing", "X-XSRF-TOKEN"),
        test_with_header_csrf: ("nothing", "X-CSRF-TOKEN"),
        test_with_body_token: ("token", "user-agent"),
        test_with_body__token: ("_token", "user-agent"),
        test_with_body__csrf: ("_csrf", "user-agent"),
        test_with_body_token_cap: ("Token", "user-agent"),
        test_with_body_csrf_token: ("csrf_token", "user-agent"),
        test_with_body_csrf_token_cap: ("CsrfToken", "user-agent"),
        test_with_body_capitalized: ("CSRFToken", "user-agent"),
        test_with_body_authenticity: ("authenticity_token", "user-agent"),
    }
}
