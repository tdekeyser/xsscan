use http::{Request, Response};

pub enum Body {
    Text(String),
}

pub trait RequestParser<T> {
    fn parse(&self, request: &Request<Body>) -> Option<T>;
}

pub trait ResponseParser<T> {
    fn parse(&self, response: &Response<Body>) -> Option<T>;
}
