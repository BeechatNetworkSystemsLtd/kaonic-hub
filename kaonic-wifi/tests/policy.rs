use kaonic_wifi::policy::*;

fn seen(ssid: &str, dbm: i32) -> Seen {
    Seen { ssid: ssid.into(), signal_dbm: dbm, security: Security::Wpa2, frequency_mhz: 2437 }
}

/// Saved networks in this order, client on, and a scan that saw `scan`.
fn running(saved: &[&str], scan: Vec<Seen>) -> (Policy, Vec<Action>) {
    let mut policy = Policy::new(saved.iter().map(|ssid| Saved::new(*ssid, true)).collect());
    assert_eq!(policy.set_enabled(true, 0), vec![Action::Scan]);
    let actions = policy.handle(Event::ScanResults(scan), 1);
    (policy, actions)
}

fn connect(policy: &mut Policy, ssid: &str, now: Secs) {
    policy.handle(Event::Associated(ssid.into()), now);
    policy.handle(Event::AddressAcquired, now);
    assert!(matches!(policy.state(), State::Connected { ssid: s, .. } if s == ssid));
}

#[test]
fn joins_the_first_saved_network_in_range_whatever_its_signal() {
    let (policy, actions) = running(&["home", "office"], vec![seen("office", -40), seen("home", -80), seen("cafe", -30)]);
    assert_eq!(actions, vec![Action::Join("home".into())]);
    assert!(matches!(policy.state(), State::Connecting { ssid, .. } if ssid == "home"));
}

#[test]
fn skips_networks_not_allowed_to_auto_connect() {
    let mut policy = Policy::new(vec![Saved::new("home", true), Saved::new("office", true)]);
    policy.set_auto_connect("home", false, 0).unwrap();
    policy.set_enabled(true, 0);
    let actions = policy.handle(Event::ScanResults(vec![seen("home", -40), seen("office", -60)]), 1);
    assert_eq!(actions, vec![Action::Join("office".into())]);
}

#[test]
fn nothing_in_range_keeps_searching_and_scans_fast_then_slow() {
    let (mut policy, actions) = running(&["home"], vec![seen("cafe", -50)]);
    assert!(actions.is_empty());
    assert!(matches!(policy.state(), State::Searching { .. }));
    assert_eq!(policy.next_deadline(), Some(1 + SCAN_SEARCHING));

    assert_eq!(policy.tick(1 + SCAN_SEARCHING), vec![Action::Scan]);
    // After five minutes of searching it slows down.
    policy.handle(Event::ScanResults(vec![]), SEARCH_FAST_FOR + 5);
    assert_eq!(policy.next_deadline(), Some(SEARCH_FAST_FOR + 5 + SCAN_SEARCHING_SLOW));
}

#[test]
fn a_wrong_password_moves_on_and_is_not_retried_until_the_password_changes() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("home", -50), seen("office", -60)]);
    let actions = policy.handle(Event::Failed("home".into(), Problem::WrongPassword), 5);
    assert_eq!(actions, vec![Action::Join("office".into())]);
    assert_eq!(policy.attempt().unwrap().problem, Problem::WrongPassword);
    let home = &policy.saved()[0];
    assert_eq!((home.problem, home.retry_at), (Some(Problem::WrongPassword), None));

    // Office goes away too: home is still not tried, however long we wait.
    let actions = policy.handle(Event::Failed("office".into(), Problem::NotFound), 6);
    assert_eq!(actions, vec![Action::Disconnect, Action::Scan]);
    policy.handle(Event::ScanResults(vec![seen("home", -50)]), 10_000);
    assert!(matches!(policy.state(), State::Searching { .. }));

    // A new password lets it try at once.
    assert_eq!(policy.password_changed("home", true, 10_001).unwrap(), vec![Action::Join("home".into())]);
}

#[test]
fn failures_back_off_and_a_success_resets_them() {
    let (mut policy, _) = running(&["home"], vec![seen("home", -50)]);
    policy.handle(Event::Failed("home".into(), Problem::Rejected), 10);
    assert_eq!(policy.saved()[0].retry_at, Some(10 + RETRY_FIRST));

    // Too early: nothing. On time: it tries again.
    assert!(!policy.tick(10 + RETRY_FIRST - 1).contains(&Action::Join("home".into())));
    assert!(policy.tick(10 + RETRY_FIRST).contains(&Action::Join("home".into())));

    policy.handle(Event::Failed("home".into(), Problem::Rejected), 100);
    assert_eq!(policy.saved()[0].retry_at, Some(100 + 2 * RETRY_FIRST));

    // The waits stop growing at the cap.
    let mut now = 100;
    for _ in 0..10 {
        now = policy.saved()[0].retry_at.unwrap();
        policy.tick(now);
        policy.handle(Event::Failed("home".into(), Problem::Rejected), now);
    }
    assert_eq!(policy.saved()[0].retry_at, Some(now + RETRY_MAX));

    now = policy.saved()[0].retry_at.unwrap();
    policy.tick(now);
    connect(&mut policy, "home", now);
    assert_eq!(policy.saved()[0].problem, None);
    assert_eq!(policy.attempt(), None);
}

#[test]
fn a_join_that_hangs_times_out_and_one_without_an_address_too() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("home", -50), seen("office", -60)]);
    let actions = policy.tick(1 + JOIN_TIMEOUT);
    assert_eq!(actions[0], Action::Join("office".into()));
    assert_eq!(policy.saved()[0].problem, Some(Problem::Timeout));

    policy.handle(Event::Associated("office".into()), 30);
    policy.tick(30 + JOIN_TIMEOUT);
    assert_eq!(policy.saved()[1].problem, Some(Problem::NoAddress));
}

#[test]
fn keeps_a_working_connection_and_roams_up_only_after_two_strong_scans() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("office", -60)]);
    connect(&mut policy, "office", 2);
    assert_eq!(policy.next_deadline(), Some(2 + SCAN_CONNECTED));

    // Home appears, but weak: stay.
    assert!(policy.handle(Event::ScanResults(vec![seen("office", -60), seen("home", -80)]), 10).is_empty());
    // Strong once: still stay.
    assert!(policy.handle(Event::ScanResults(vec![seen("office", -60), seen("home", -60)]), 20).is_empty());
    // Strong twice in a row: move.
    assert_eq!(policy.handle(Event::ScanResults(vec![seen("office", -60), seen("home", -60)]), 30), vec![Action::Join("home".into())]);
}

#[test]
fn never_roams_down_the_order_while_connected() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("home", -85)]);
    connect(&mut policy, "home", 2);
    for now in [10, 20, 30] {
        assert!(policy.handle(Event::ScanResults(vec![seen("home", -85), seen("office", -30)]), now).is_empty());
    }
}

#[test]
fn a_manual_join_is_pinned_until_it_fails() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("home", -50), seen("office", -60)]);
    connect(&mut policy, "home", 2);
    assert_eq!(policy.connect("office", 3).unwrap(), vec![Action::Join("office".into())]);
    connect(&mut policy, "office", 4);
    assert_eq!(policy.pinned(), Some("office"));

    // A preferred network, however strong, does not pull it away.
    for now in [10, 20, 30] {
        assert!(policy.handle(Event::ScanResults(vec![seen("home", -30), seen("office", -60)]), now).is_empty());
    }
    // Unpinning keeps the working connection; roaming applies again from the next scans.
    assert!(policy.unpin(31).is_empty());
    policy.handle(Event::ScanResults(vec![seen("home", -30), seen("office", -60)]), 40);
    assert_eq!(policy.handle(Event::ScanResults(vec![seen("home", -30), seen("office", -60)]), 50), vec![Action::Join("home".into())]);
}

#[test]
fn saving_a_network_puts_it_first_and_joins_it_even_before_a_scan_saw_it() {
    let (mut policy, _) = running(&["home"], vec![]);
    let actions = policy.save(Saved::new("new", true), 5);
    assert_eq!(actions, vec![Action::Join("new".into())]);
    assert_eq!(policy.saved()[0].ssid, "new");
    assert_eq!(policy.pinned(), Some("new"));
}

#[test]
fn a_failed_manual_join_stays_explained_after_falling_back() {
    let (mut policy, _) = running(&["home"], vec![seen("home", -50)]);
    connect(&mut policy, "home", 2);
    policy.save(Saved::new("absent", true), 3);
    assert_eq!(policy.handle(Event::Failed("absent".into(), Problem::NotFound), 5), vec![Action::Join("home".into())]);
    connect(&mut policy, "home", 6);
    assert_eq!(policy.attempt().map(|a| (a.ssid.as_str(), a.problem)), Some(("absent", Problem::NotFound)));
}

#[test]
fn a_restarted_hub_takes_over_the_connection_without_joining_again() {
    let mut policy = Policy::new(vec![Saved::new("home", true), Saved::new("office", true)]);
    assert_eq!(policy.resume("office", 0).unwrap(), vec![]);
    policy.handle(Event::AddressAcquired, 1);
    assert!(matches!(policy.state(), State::Connected { ssid, .. } if ssid == "office"));
    assert_eq!(policy.resume("nowhere", 2), Err(PolicyError::NotSaved));
}

#[test]
fn an_expired_wait_is_no_longer_a_deadline() {
    let (mut policy, _) = running(&["home"], vec![]);
    policy.save(Saved::new("absent", true), 1);
    policy.handle(Event::Failed("absent".into(), Problem::NotFound), 2);
    policy.tick(2 + RETRY_FIRST);
    assert_eq!(policy.saved().iter().find(|s| s.ssid == "absent").unwrap().retry_at, None);
    assert!(policy.next_deadline().is_none_or(|deadline| deadline > 2 + RETRY_FIRST));
}

#[test]
fn losing_the_connection_rejoins_without_penalty() {
    let (mut policy, _) = running(&["home"], vec![seen("home", -50)]);
    connect(&mut policy, "home", 2);
    assert_eq!(policy.handle(Event::Disconnected, 10), vec![Action::Join("home".into())]);
    assert_eq!(policy.saved()[0].problem, None);
}

#[test]
fn forgetting_the_current_network_moves_to_the_next() {
    let (mut policy, _) = running(&["home", "office"], vec![seen("home", -50), seen("office", -60)]);
    connect(&mut policy, "home", 2);
    assert_eq!(policy.forget("home", 3).unwrap(), vec![Action::Join("office".into())]);
    assert_eq!(policy.forget("home", 4), Err(PolicyError::NotSaved));
}

#[test]
fn reorder_must_name_every_network_once() {
    let mut policy = Policy::new(vec![Saved::new("a", true), Saved::new("b", true)]);
    assert_eq!(policy.reorder(&["a".into()], 0), Err(PolicyError::BadOrder));
    assert_eq!(policy.reorder(&["a".into(), "a".into()], 0), Err(PolicyError::BadOrder));
    policy.reorder(&["b".into(), "a".into()], 0).unwrap();
    assert_eq!(policy.saved()[0].ssid, "b");
}

#[test]
fn switching_off_disconnects_and_stops_scanning() {
    let (mut policy, _) = running(&["home"], vec![seen("home", -50)]);
    assert_eq!(policy.set_enabled(false, 5), vec![Action::Disconnect]);
    assert_eq!(policy.state(), &State::Off);
    assert_eq!(policy.next_deadline(), None);
    assert!(policy.request_scan(6).is_empty());
}

#[test]
fn one_scan_at_a_time_and_a_lost_one_is_given_up() {
    let mut policy = Policy::new(vec![]);
    policy.set_enabled(true, 0);
    assert!(policy.request_scan(1).is_empty());
    assert_eq!(policy.tick(SCAN_TIMEOUT), vec![]);
    assert_eq!(policy.request_scan(SCAN_TIMEOUT + 1), vec![Action::Scan]);
}

#[test]
fn scan_keeps_one_entry_per_name_strongest_first() {
    let (policy, _) = running(&[], vec![seen("a", -70), seen("b", -40), seen("a", -50), seen("", -20)]);
    let names: Vec<_> = policy.scan().iter().map(|s| (s.ssid.as_str(), s.signal_dbm)).collect();
    assert_eq!(names, vec![("b", -40), ("a", -50)]);
}
