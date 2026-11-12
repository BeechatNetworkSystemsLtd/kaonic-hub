use kaonic_pki::{CertRequest, SigningKey};
use kaonic_trust::{Allowlist, Certificate, Error, Identity, Peer, Trust};

const ISSUED_AT: u64 = 1_792_000_000;

fn identity(seed: u8) -> (Identity, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let identity = Identity {
        x25519: [seed.wrapping_add(100); 32],
        ed25519: key.verifying_key().to_bytes(),
    };
    (identity, key)
}

struct Admin {
    identity: Identity,
    key: SigningKey,
    root: Certificate,
}

impl Admin {
    fn new(seed: u8) -> Self {
        let (identity, key) = identity(seed);
        let root = Certificate::new_root(&identity, &key, ISSUED_AT).unwrap();
        Self {
            identity,
            key,
            root,
        }
    }

    fn certify(&self, node: &Identity, node_key: &SigningKey) -> Certificate {
        let request = CertRequest::create(node, node_key, b"link").unwrap();
        self.root
            .issue(&self.key, &request, node, ISSUED_AT)
            .unwrap()
    }

    fn allowlist(&self, seq: u64, nodes: &[&Identity]) -> Allowlist {
        Allowlist::sign(&self.key, seq, nodes.iter().map(|n| n.hash())).unwrap()
    }

    /// The trust state a provisioned node would hold.
    fn trust_for(&self, node: &Identity, node_key: &SigningKey, list: &Allowlist) -> Trust {
        let own = self.certify(node, node_key);
        Trust::from_der(self.root.der(), own.der(), list.as_bytes()).unwrap()
    }
}

#[test]
fn allowlist_round_trips_and_is_canonical() {
    let admin = Admin::new(1);
    let (a, _) = identity(2);
    let (b, _) = identity(3);
    let list = admin.allowlist(7, &[&b, &a, &a]);
    let parsed = Allowlist::from_bytes(list.as_bytes(), &admin.identity.ed25519).unwrap();
    assert_eq!(parsed, list);
    assert_eq!(parsed.seq(), 7);
    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains(&a.hash()) && parsed.contains(&b.hash()));
}

#[test]
fn allowlist_from_another_admin_or_tampered_is_rejected() {
    let admin = Admin::new(1);
    let other = Admin::new(9);
    let (a, _) = identity(2);
    let list = admin.allowlist(1, &[&a]);
    assert!(matches!(
        Allowlist::from_bytes(list.as_bytes(), &other.identity.ed25519),
        Err(Error::BadSignature)
    ));
    for i in 0..list.as_bytes().len() {
        let mut bytes = list.as_bytes().to_vec();
        bytes[i] ^= 0x01;
        assert!(
            Allowlist::from_bytes(&bytes, &admin.identity.ed25519).is_err(),
            "accepted with byte {i} flipped"
        );
    }
}

#[test]
fn unsorted_allowlist_is_rejected_even_when_signed() {
    let admin = Admin::new(1);
    let mut body = b"KALW\x01".to_vec();
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[9u8; 16]);
    body.extend_from_slice(&[1u8; 16]);
    use ed25519_dalek::Signer;
    let signature = admin.key.sign(&body);
    body.extend_from_slice(&signature.to_bytes());
    assert!(matches!(
        Allowlist::from_bytes(&body, &admin.identity.ed25519),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn listed_node_with_valid_certificate_is_trusted() {
    let admin = Admin::new(1);
    let (me, my_key) = identity(2);
    let (peer, peer_key) = identity(3);
    let trust = admin.trust_for(&me, &my_key, &admin.allowlist(1, &[&me, &peer]));
    let cert = admin.certify(&peer, &peer_key);
    assert_eq!(trust.verify_peer(&peer, &cert).unwrap(), Peer::Node);
}

#[test]
fn certified_but_unlisted_node_is_refused() {
    let admin = Admin::new(1);
    let (me, my_key) = identity(2);
    let (peer, peer_key) = identity(3);
    let trust = admin.trust_for(&me, &my_key, &admin.allowlist(1, &[&me]));
    let cert = admin.certify(&peer, &peer_key);
    assert!(matches!(
        trust.verify_peer(&peer, &cert),
        Err(Error::NotAllowed)
    ));
}

#[test]
fn admin_is_trusted_without_being_listed() {
    let admin = Admin::new(1);
    let (me, my_key) = identity(2);
    let trust = admin.trust_for(&me, &my_key, &admin.allowlist(1, &[]));
    assert_eq!(
        trust.verify_peer(&admin.identity, &admin.root).unwrap(),
        Peer::Admin
    );
}

#[test]
fn other_network_and_stolen_certificates_are_refused() {
    let admin = Admin::new(1);
    let other = Admin::new(9);
    let (me, my_key) = identity(2);
    let (peer, peer_key) = identity(3);
    let (impostor, _) = identity(4);
    let trust = admin.trust_for(&me, &my_key, &admin.allowlist(1, &[&me, &peer, &impostor]));

    let foreign = other.certify(&peer, &peer_key);
    assert!(matches!(
        trust.verify_peer(&peer, &foreign),
        Err(Error::NotIssued)
    ));
    assert!(matches!(
        trust.verify_peer(&other.identity, &other.root),
        Err(Error::NotIssued)
    ));

    // A valid certificate presented with somebody else's identity.
    let stolen = admin.certify(&peer, &peer_key);
    assert!(matches!(
        trust.verify_peer(&impostor, &stolen),
        Err(Error::IdentityMismatch)
    ));
}

#[test]
fn newer_allowlist_revokes_and_older_cannot_roll_back() {
    let admin = Admin::new(1);
    let (me, my_key) = identity(2);
    let (peer, peer_key) = identity(3);
    let v1 = admin.allowlist(1, &[&me, &peer]);
    let v2 = admin.allowlist(2, &[&me]);
    let mut trust = admin.trust_for(&me, &my_key, &v1);
    let cert = admin.certify(&peer, &peer_key);
    assert!(trust.verify_peer(&peer, &cert).is_ok());

    assert!(trust.update_allowlist(v2.as_bytes()).unwrap());
    assert!(matches!(
        trust.verify_peer(&peer, &cert),
        Err(Error::NotAllowed)
    ));

    assert!(!trust.update_allowlist(v1.as_bytes()).unwrap());
    assert!(!trust.update_allowlist(v2.as_bytes()).unwrap());
    assert_eq!(trust.allowlist().seq(), 2);

    let forged = Admin::new(9).allowlist(3, &[&me, &peer]);
    assert!(trust.update_allowlist(forged.as_bytes()).is_err());
}

#[test]
fn trust_parts_must_belong_together() {
    let admin = Admin::new(1);
    let other = Admin::new(9);
    let (me, my_key) = identity(2);
    let own = admin.certify(&me, &my_key);
    let list = admin.allowlist(1, &[&me]);

    assert!(Trust::from_der(admin.root.der(), own.der(), list.as_bytes()).is_ok());
    assert!(Trust::from_der(other.root.der(), own.der(), list.as_bytes()).is_err());
    assert!(Trust::from_der(own.der(), own.der(), list.as_bytes()).is_err());
    let other_list = other.allowlist(1, &[&me]);
    assert!(Trust::from_der(admin.root.der(), own.der(), other_list.as_bytes()).is_err());
    // The admin device trusts with its own root as its certificate.
    assert!(Trust::from_der(admin.root.der(), admin.root.der(), list.as_bytes()).is_ok());
}

#[test]
fn blocked_list_round_trips_and_v1_stays_v1() {
    let admin = Admin::new(1);
    let (a, _) = identity(2);
    let (b, _) = identity(3);
    let (c, _) = identity(4);

    let plain = admin.allowlist(1, &[&a]);
    assert_eq!(plain.as_bytes()[4], 1, "nobody blocked: still a v1 list");
    assert_eq!(Allowlist::encoded_len(plain.as_bytes()), Some(plain.as_bytes().len()));

    // Blocking wins over allowing.
    let list = Allowlist::sign_with_blocked(&admin.key, 2, [a.hash(), b.hash()], [c.hash(), b.hash()]).unwrap();
    assert_eq!(list.as_bytes()[4], 2);
    let parsed = Allowlist::from_bytes(list.as_bytes(), &admin.identity.ed25519).unwrap();
    assert_eq!(parsed, list);
    assert!(parsed.contains(&a.hash()) && !parsed.contains(&b.hash()));
    assert!(parsed.is_blocked(&b.hash()) && parsed.is_blocked(&c.hash()) && !parsed.is_blocked(&a.hash()));
    assert_eq!(parsed.blocked().count(), 2);

    let mut followed = list.as_bytes().to_vec();
    followed.extend_from_slice(b"after");
    assert_eq!(Allowlist::encoded_len(&followed), Some(list.as_bytes().len()));
    assert_eq!(Allowlist::encoded_len(&list.as_bytes()[..list.as_bytes().len() - 1]), None);

    for i in 0..list.as_bytes().len() {
        let mut bytes = list.as_bytes().to_vec();
        bytes[i] ^= 0x01;
        assert!(Allowlist::from_bytes(&bytes, &admin.identity.ed25519).is_err(), "accepted with byte {i} flipped");
    }
}

#[test]
fn blocked_identity_is_refused_even_with_a_certificate() {
    let admin = Admin::new(1);
    let (me, my_key) = identity(2);
    let (peer, peer_key) = identity(3);
    let cert = admin.certify(&peer, &peer_key);
    let mut trust = admin.trust_for(&me, &my_key, &admin.allowlist(1, &[&me, &peer]));
    assert_eq!(trust.verify_peer(&peer, &cert).unwrap(), Peer::Node);

    let blocked = Allowlist::sign_with_blocked(&admin.key, 2, [me.hash()], [peer.hash()]).unwrap();
    assert!(trust.update_allowlist(blocked.as_bytes()).unwrap());
    assert!(matches!(trust.verify_peer(&peer, &cert), Err(Error::Blocked)));
    // The admin itself is always trusted.
    assert_eq!(trust.verify_peer(&admin.identity, &admin.root).unwrap(), Peer::Admin);
}
