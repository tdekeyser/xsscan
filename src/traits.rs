use reqwest::Request;

pub trait DetectSession {
    fn uses_session(&self, request: &Request) -> bool;
}

pub trait ExtractToken<T> {
    fn extract_token(&self, request: &Request) -> Option<T>;
}
