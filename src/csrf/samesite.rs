// https://datatracker.ietf.org/doc/html/draft-west-first-party-cookies-07#section-5

use std::future::Future;
use std::str::FromStr;

use http::{HeaderValue, Response};
use http::header::SET_COOKIE;
use regex::Regex;

use crate::traits::{Body, RequestParser, ResponseParser};

#[derive(Debug, PartialEq)]
enum SameSiteCookie {
    None,
    Lax,
    Strict,
}

impl FromStr for SameSiteCookie {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(SameSiteCookie::None),
            "Lax" => Ok(SameSiteCookie::Lax),
            "Strict" => Ok(SameSiteCookie::Strict),
            _ => Err(format!("SameSiteCookie not found '{}'", s))
        }
    }
}

struct SameSiteParser {}

impl ResponseParser<SameSiteCookie> for SameSiteParser {
    fn parse(&self, response: &Response<Body>) -> Option<SameSiteCookie> {
        let h = response.headers();

        response.headers()
            .get(SET_COOKIE)
            .map(Self::get_samesite_cookie)
            .flatten()
    }
}

impl SameSiteParser {
    pub fn new() -> Self {
        Self {}
    }

    fn get_samesite_cookie(header: &HeaderValue) -> Option<SameSiteCookie> {
        Regex::new(r"SameSite=(Strict|Lax|None)")
            .unwrap()
            .captures(header.to_str().unwrap_or_default())
            .and_then(|caps| Some(SameSiteCookie::from_str(&caps[1]).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use http::header::SET_COOKIE;

    use crate::csrf::samesite::{SameSiteCookie, SameSiteParser};
    use crate::traits::{Body, ResponseParser};

    #[tokio::test]
    async fn fuzzer_keyword_in_headers() -> Result<(), String> {
        let response = http::Response::builder()
            .header(SET_COOKIE, "JSESSIONID=7699A0931EC31829B895BB9C9D5421C1; HttpOnly; SameSite=Strict")
            .body(Body::Text("".to_string()))
            .unwrap();

        let cookie = SameSiteParser::new().parse(&response);

        assert_eq!(cookie, Some(SameSiteCookie::Strict));

        Ok(())
    }
}
