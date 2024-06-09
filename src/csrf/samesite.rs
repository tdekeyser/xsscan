// https://datatracker.ietf.org/doc/html/draft-west-first-party-cookies-07#section-5

use reqwest::{Client, Request};

use crate::traits::ParseToken;

enum SameSiteCookie {
    None,
    Lax,
    Strict,
}

struct SameSiteParser {}

impl ParseToken<SameSiteCookie> for SameSiteParser {
    async fn parse(&self, request: &Request) -> Option<SameSiteCookie> {
        let mut base = request.url().clone();
        base.set_path("");

        Client::new().get(base).send().await.ok();
        todo!()
    }
}
