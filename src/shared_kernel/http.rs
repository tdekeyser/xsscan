
pub type Request = http::Request<Body>;
pub type Response = http::Response<Body>;

pub enum Body {
    Text(String),
}

pub enum HttpExchange {
    Request(Request),
    Response(Response),
}

pub trait VulnerabilityChecker<T> {
    fn check_vulnerability(&self, exchange: Vec<HttpExchange>) -> Option<T>;
}

pub trait RequestParser<T> {
    fn parse(&self, request: &Request) -> Option<T>;
}

pub trait ResponseParser<T> {
    fn parse(&self, response: &Response) -> Option<T>;
}
