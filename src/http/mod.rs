use httparse::Status;
use httparse::Status::Complete;

fn parse_request(r: &str) -> Result<(), httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let x: Status<usize> = req.parse(r.as_bytes())?;

    if let Complete(offset) = req.parse(r.as_bytes())? {
        let body = &r[offset..];
        return Ok(())
    }

    Err(httparse::Error::TooManyHeaders)
}


#[cfg(test)]
mod tests {
    use crate::http::parse_request;

    #[test]
    fn can_read_raw_http_request() -> Result<(), httparse::Error> {
        let s = "POST /my-account/change-email?email=hello@test.net HTTP/1.1
Host: 0a9a00f1045d5c8f8154f20800a30003.web-security-academy.net
Cookie: session=N755ezqhJblYThHK4FcZekNusjF2k2lh
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a9a00f1045d5c8f8154f20800a30003.web-security-academy.net/my-account?id=wiener
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: https://0a9a00f1045d5c8f8154f20800a30003.web-security-academy.net
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=1
Te: trailers

email=test%40test.net";
        parse_request(s)
    }
}
