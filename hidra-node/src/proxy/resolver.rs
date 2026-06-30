/// DNS resolution strategy for HidraNet proxy.
///
/// Internet domain names are NEVER resolved locally — they are passed as-is
/// through the onion circuit to the exit relay, which performs DNS resolution.
/// This prevents DNS leaks that could reveal the client's browsing activity.
///
/// `.hidra` internal domains are kept within the network for DHT-based resolution.

pub fn is_hidra_domain(host: &str) -> bool {
    host.ends_with(".hidra")
}

pub fn target_host(host: &str) -> TargetResolution {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return TargetResolution::DirectIp;
    }
    if is_hidra_domain(host) {
        return TargetResolution::HidraInternal;
    }
    TargetResolution::RemoteDns
}

#[derive(Debug, PartialEq, Eq)]
pub enum TargetResolution {
    DirectIp,
    HidraInternal,
    RemoteDns,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_address_is_direct() {
        assert_eq!(target_host("127.0.0.1"), TargetResolution::DirectIp);
        assert_eq!(target_host("::1"), TargetResolution::DirectIp);
    }

    #[test]
    fn hidra_domain_is_internal() {
        assert_eq!(target_host("chat.hidra"), TargetResolution::HidraInternal);
        assert_eq!(target_host("service.node.hidra"), TargetResolution::HidraInternal);
    }

    #[test]
    fn internet_domain_is_remote_dns() {
        assert_eq!(target_host("example.com"), TargetResolution::RemoteDns);
        assert_eq!(target_host("google.com"), TargetResolution::RemoteDns);
    }
}
