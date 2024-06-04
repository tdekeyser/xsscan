use reqwest::Request;

mod token;

struct VulnerableRequest {}

struct CsrfTester {}

impl CsrfTester {
    fn test_vulnerability(request: &Request) -> Option<VulnerableRequest> {
        None
    }
}

struct CsrfExploitGenerator {}

struct CsrfExploit(String);

impl CsrfExploitGenerator {
    fn generate(request: VulnerableRequest) -> CsrfExploit {
        CsrfExploit("".to_string())
    }
}
