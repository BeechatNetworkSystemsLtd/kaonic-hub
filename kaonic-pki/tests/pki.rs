use kaonic_pki::{CertRequest, Certificate, Error, Identity, SigningKey};

const ISSUED_AT: u64 = 1_792_000_000; // 2026-10

/// A deterministic identity whose Ed25519 half matches the returned key.
fn identity(seed: u8) -> (Identity, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let identity = Identity {
        x25519: [seed.wrapping_add(100); 32],
        ed25519: key.verifying_key().to_bytes(),
    };
    (identity, key)
}

struct Network {
    admin: Identity,
    admin_key: SigningKey,
    root: Certificate,
}

fn network(seed: u8) -> Network {
    let (admin, admin_key) = identity(seed);
    let root = Certificate::new_root(&admin, &admin_key, ISSUED_AT).unwrap();
    Network {
        admin,
        admin_key,
        root,
    }
}

fn provision(net: &Network, node: &Identity, node_key: &SigningKey) -> Certificate {
    let request = CertRequest::create(node, node_key, b"link-id-16-bytes").unwrap();
    let request = CertRequest::from_der(request.der()).unwrap();
    net.root
        .issue(&net.admin_key, &request, node, ISSUED_AT)
        .unwrap()
}

#[test]
fn root_is_self_signed_and_round_trips() {
    let net = network(1);
    assert!(net.root.is_root());
    assert_eq!(net.root.identity_hash(), net.admin.hash());
    let parsed = Certificate::from_der(net.root.der()).unwrap();
    assert_eq!(parsed, net.root);
    net.root.check_identity(&net.admin).unwrap();
}

#[test]
fn provisioning_flow_issues_a_verifiable_node_certificate() {
    let net = network(1);
    let (node, node_key) = identity(2);
    let cert = provision(&net, &node, &node_key);

    let cert = Certificate::from_der(cert.der()).unwrap();
    assert!(!cert.is_root());
    cert.verify_issued_by(&net.root).unwrap();
    cert.check_identity(&node).unwrap();
    assert_eq!(cert.public_key(), &node.ed25519);
    // Must fit one radio frame together with the rest of the AUTH message.
    assert!(cert.der().len() < 450, "{} bytes", cert.der().len());
}

#[test]
fn request_carries_its_challenge() {
    let (node, key) = identity(2);
    let request = CertRequest::create(&node, &key, &[0xab; 16]).unwrap();
    let parsed = CertRequest::from_der(request.der()).unwrap();
    assert_eq!(parsed.challenge(), &[0xab; 16]);
    assert_eq!(parsed.identity_hash(), node.hash());
}

#[test]
fn another_networks_root_does_not_verify() {
    let net = network(1);
    let other = network(9);
    let (node, node_key) = identity(2);
    let cert = provision(&net, &node, &node_key);
    assert!(matches!(
        cert.verify_issued_by(&other.root),
        Err(Error::NotIssuedBy)
    ));
}

#[test]
fn certificate_is_bound_to_both_halves_of_the_identity() {
    let net = network(1);
    let (node, node_key) = identity(2);
    let cert = provision(&net, &node, &node_key);

    let mut other_x25519 = node;
    other_x25519.x25519[0] ^= 1;
    let (other, _) = identity(3);
    for wrong in [other_x25519, other] {
        assert!(matches!(
            cert.check_identity(&wrong),
            Err(Error::IdentityMismatch)
        ));
    }
}

#[test]
fn admin_issues_only_for_the_identity_it_knows() {
    let net = network(1);
    let (node, node_key) = identity(2);
    let (impostor, _) = identity(3);
    let request = CertRequest::create(&node, &node_key, b"challenge").unwrap();
    assert!(matches!(
        net.root
            .issue(&net.admin_key, &request, &impostor, ISSUED_AT),
        Err(Error::IdentityMismatch)
    ));
}

#[test]
fn only_a_root_with_its_own_key_can_issue() {
    let net = network(1);
    let (node, node_key) = identity(2);
    let cert = provision(&net, &node, &node_key);
    let request = CertRequest::create(&node, &node_key, b"challenge").unwrap();

    assert!(matches!(
        cert.issue(&node_key, &request, &node, ISSUED_AT),
        Err(Error::NotIssuedBy)
    ));
    assert!(matches!(
        net.root.issue(&node_key, &request, &node, ISSUED_AT),
        Err(Error::WrongSigningKey)
    ));
}

#[test]
fn signing_key_must_match_the_identity() {
    let (node, _) = identity(2);
    let (_, other_key) = identity(3);
    assert!(matches!(
        Certificate::new_root(&node, &other_key, ISSUED_AT),
        Err(Error::WrongSigningKey)
    ));
    assert!(matches!(
        CertRequest::create(&node, &other_key, b"challenge"),
        Err(Error::WrongSigningKey)
    ));
}

#[test]
fn any_flipped_bit_is_rejected() {
    let net = network(1);
    let (node, node_key) = identity(2);
    let cert = provision(&net, &node, &node_key);
    let request = CertRequest::create(&node, &node_key, b"challenge").unwrap();

    for i in 0..cert.der().len() {
        let mut der = cert.der().to_vec();
        der[i] ^= 0x01;
        let ok = Certificate::from_der(&der)
            .and_then(|c| {
                c.verify_issued_by(&net.root)?;
                c.check_identity(&node)
            })
            .is_ok();
        assert!(!ok, "certificate accepted with bit flipped in byte {i}");
    }
    for i in 0..request.der().len() {
        let mut der = request.der().to_vec();
        der[i] ^= 0x01;
        let ok = CertRequest::from_der(&der)
            .and_then(|r| r.check_identity(&node))
            .is_ok();
        assert!(!ok, "request accepted with bit flipped in byte {i}");
    }
}

#[test]
fn issue_time_after_2049_uses_generalized_time() {
    let (admin, key) = identity(1);
    let root = Certificate::new_root(&admin, &key, 2_600_000_000).unwrap();
    Certificate::from_der(root.der()).unwrap();
}
