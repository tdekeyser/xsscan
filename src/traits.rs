use reqwest::Request;

pub trait ParseToken<T> {
    fn parse(&self, request: &Request) -> Option<T>;
}
