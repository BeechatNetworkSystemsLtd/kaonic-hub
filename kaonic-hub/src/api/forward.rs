//! `/vpn/forward`: the rules by which UDP multicast and broadcast of this node's client
//! networks are carried to the other nodes' (`kaonic_vpn::forward`), with their counters. The
//! rules are kept in the store and given to the VPN at start; a change applies at once.

use std::net::Ipv4Addr;

use kaonic_vpn::ip::Cidr;
use axum::extract::State;
use axum::response::Response;
use kaonic_vpn::forward::{self, Counters, Direction, Rule, RuleStatus};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};

const FORWARD_KEY: &str = "vpn.forward";

/// A rule as the API takes it and the store keeps it. Only the name and the address are
/// required: without a port the rule is for every port, and the rest has the defaults of
/// [`Rule::new`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBody {
    name: String,
    enabled: Option<bool>,
    address: String,
    port: Option<u16>,
    port_end: Option<u16>,
    direction: Option<String>,
    interfaces: Option<Vec<String>>,
    rate: Option<u32>,
    burst: Option<u32>,
    max_bytes: Option<usize>,
    dedup_secs: Option<u32>,
    ttl: Option<u8>,
    keep_source: Option<bool>,
}

fn rule_of(body: RuleBody) -> Result<Rule, (&'static str, String)> {
    // One address, or a range of groups as a prefix.
    let address: Cidr = match body.address.parse::<Ipv4Addr>() {
        Ok(address) => Cidr::new(address, 32).expect("valid prefix"),
        Err(_) => body.address.parse().map_err(|_| ("address", format!("{} is not an IPv4 address or a prefix like 239.0.0.0/8.", body.address)))?,
    };
    let defaults = Rule::range(&body.name, address);
    let direction = match body.direction {
        Some(text) => Direction::parse(&text).ok_or(("direction", "Use both, to_mesh, from_mesh or block.".to_owned()))?,
        None => defaults.direction,
    };
    let ports = match (body.port, body.port_end) {
        (Some(port), end) => (port, end.unwrap_or(port)),
        (None, None) => forward::ANY_PORT,
        (None, Some(_)) => return Err(("port", "A last port needs a first one.".to_owned())),
    };
    Ok(Rule {
        enabled: body.enabled.unwrap_or(true),
        ports,
        direction,
        interfaces: body.interfaces.unwrap_or_default(),
        rate: body.rate.unwrap_or(defaults.rate),
        burst: body.burst.unwrap_or(defaults.burst),
        max_bytes: body.max_bytes.unwrap_or(defaults.max_bytes),
        dedup_secs: body.dedup_secs.unwrap_or(defaults.dedup_secs),
        ttl: body.ttl.unwrap_or(defaults.ttl),
        keep_source: body.keep_source.unwrap_or(defaults.keep_source),
        ..defaults
    })
}

fn rule_json(rule: &Rule) -> Value {
    json!({
        "name": rule.name,
        "enabled": rule.enabled,
        "address": if rule.address.prefix_len() == 32 { rule.address.network().to_string() } else { rule.address.to_string() },
        "port": rule.ports.0,
        "port_end": rule.ports.1,
        "direction": rule.direction.as_str(),
        "interfaces": rule.interfaces,
        "rate": rule.rate,
        "burst": rule.burst,
        "max_bytes": rule.max_bytes,
        "dedup_secs": rule.dedup_secs,
        "ttl": rule.ttl,
        "keep_source": rule.keep_source,
    })
}

fn counters_json(counters: &Counters) -> Value {
    json!({
        "to_mesh_packets": counters.to_mesh_packets,
        "to_mesh_bytes": counters.to_mesh_bytes,
        "from_mesh_packets": counters.from_mesh_packets,
        "from_mesh_bytes": counters.from_mesh_bytes,
        "dropped": {
            "rate_limited": counters.rate_limited,
            "duplicate": counters.duplicates,
            "too_large": counters.too_large,
            "looped": counters.looped,
            "foreign_source": counters.foreign_source,
            "not_sent": counters.not_sent,
            "emit_error": counters.emit_errors,
        },
        "last_to_mesh_ts": counters.last_to_mesh_ms.map(|ms| ms / 1000),
        "last_from_mesh_ts": counters.last_from_mesh_ms.map(|ms| ms / 1000),
    })
}

/// Rules from stored or sent JSON (`{ "rules": [...] }`), checked as a whole.
fn rules_of(value: Value) -> ApiResult<Vec<Rule>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        rules: Vec<RuleBody>,
    }
    let body: Body = serde_json::from_value(value).map_err(|error| ApiError::field("rules", format!("Not a list of rules: {error}.")))?;
    let described = |index: usize, name: &str, message: String| format!("Rule {} ({name}): {message}", index + 1);
    let mut rules = Vec::with_capacity(body.rules.len());
    for (index, rule) in body.rules.into_iter().enumerate() {
        let name = rule.name.clone();
        rules.push(rule_of(rule).map_err(|(field, message)| ApiError::field(field, described(index, &name, message)))?);
    }
    forward::validate(&rules).map_err(|invalid| {
        let name = rules.get(invalid.rule).map_or("", |rule| rule.name.as_str());
        ApiError::field(invalid.field, if invalid.field == "rules" { invalid.message } else { described(invalid.rule, name, invalid.message) })
    })?;
    Ok(rules)
}

fn stored_json(rules: &[Rule]) -> Value {
    json!({ "rules": rules.iter().map(rule_json).collect::<Vec<_>>() })
}

/// The rules the API saved; until it saves any (an empty list is one), the defaults: every
/// multicast group and broadcast of the client networks ([`forward::defaults`]).
pub async fn stored(app: &App) -> Vec<Rule> {
    let text = app.store.call(|c| kaonic_store::settings::get(c, FORWARD_KEY)).await.ok().flatten();
    let Some(text) = text else { return forward::defaults() };
    match serde_json::from_str::<Value>(&text).map_err(|error| error.to_string()).and_then(|value| rules_of(value).map_err(|_| "the rules no longer pass the checks".to_owned())) {
        Ok(rules) => rules,
        Err(error) => {
            log::warn!("vpn: forward: the stored rules are ignored, nothing is forwarded: {error}");
            Vec::new()
        }
    }
}

/// The rules with their counters as `GET /vpn/forward`, `/vpn` and the `vpn` topic show them.
pub fn view(statuses: &[RuleStatus], active: bool, budget: Option<(u32, u32)>) -> Value {
    let rules: Vec<Value> = statuses
        .iter()
        .map(|status| {
            let mut rule = rule_json(&status.rule);
            rule["counters"] = counters_json(&status.counters);
            rule["lan"] = status.lan.iter().map(|lan| json!({ "interface": lan.interface, "state": lan.state, "detail": lan.detail })).collect();
            rule
        })
        .collect();
    let presets: Vec<Value> = forward::presets()
        .iter()
        .map(|preset| json!({ "id": preset.id, "title": preset.title, "description": preset.description, "rules": preset.rules.iter().map(rule_json).collect::<Vec<_>>() }))
        .collect();
    json!({
        "active": active,
        "rules": rules,
        "presets": presets,
        "limits": {
            "max_rules": forward::MAX_RULES,
            "max_ports": u16::MAX,
            "max_interfaces": forward::MAX_INTERFACES,
            "max_bytes": forward::MAX_BYTES,
            "max_rate": forward::MAX_RATE,
            "max_burst": forward::MAX_BURST,
            "max_dedup_secs": forward::MAX_DEDUP_SECS,
            "max_ttl": forward::MAX_TTL,
        },
        // All of the node's rules together (and each of the node's own senders besides).
        "node_budget": budget.map(|(rate, burst)| json!({ "rate": rate, "burst": burst })),
    })
}

/// The running VPN's rules, or the stored ones while it is not running.
pub async fn state(app: &App) -> Value {
    let budget = app.vpn_config.as_ref().map(|config| (config.limits.flood_rate, config.limits.flood_burst));
    match app.vpn.get() {
        Some(vpn) => view(&vpn.forward_status(), true, budget),
        None => {
            let statuses: Vec<RuleStatus> = stored(app).await.into_iter().map(|rule| RuleStatus { rule, counters: Counters::default(), lan: Vec::new() }).collect();
            view(&statuses, false, budget)
        }
    }
}

/// `GET /vpn/forward`
pub async fn get(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(state(&app).await)))
}

/// `PUT /vpn/forward`: replaces the rules. Stored, and applied at once when the VPN runs.
pub async fn put(State(app): State<App>, _: Admin, Json(body): Json<Value>) -> ApiResult<Response> {
    let rules = rules_of(body)?;
    let text = stored_json(&rules).to_string();
    app.store.call(move |c| kaonic_store::settings::set(c, FORWARD_KEY, &text)).await?;
    let detail = rules.iter().map(|rule| format!("{} {}:{}{}", rule.name, rule.address, rule.ports.0, if rule.enabled { "" } else { " (off)" })).collect::<Vec<_>>().join(", ");
    let now = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", "vpn.forward", &detail)).await;
    if let Some(vpn) = app.vpn.get() {
        vpn.set_forward(rules);
    }
    Ok(no_store(axum::Json(state(&app).await)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_round_trip_and_only_the_traffic_is_required() {
        let rules = rules_of(json!({ "rules": [{ "name": "atak-sa", "address": "239.2.3.1", "port": 6969 }] })).ok().unwrap();
        assert_eq!(rules, vec![Rule::new("atak-sa", Ipv4Addr::new(239, 2, 3, 1), 6969)]);
        let full = Rule { enabled: false, ports: (7000, 7003), direction: Direction::FromMesh, interfaces: vec!["usb0".into()], rate: 9, burst: 12, max_bytes: 600, dedup_secs: 2, ttl: 3, keep_source: false, ..Rule::new("lan games", Ipv4Addr::BROADCAST, 7000) };
        let block = Rule { direction: Direction::Block, ..Rule::range("no video", "239.9.0.0/16".parse().unwrap()) };
        let presets: Vec<Rule> = forward::presets().into_iter().flat_map(|preset| preset.rules).collect();
        for rules in [vec![full, block], presets, forward::defaults(), Vec::new()] {
            assert_eq!(rules_of(stored_json(&rules)).ok().unwrap(), rules);
        }
        // Without a port: every port; a range of groups as a prefix.
        let wide = rules_of(json!({ "rules": [{ "name": "multicast", "address": "224.0.0.0/4", "rate": 2 }, { "name": "broadcast", "address": "255.255.255.255", "rate": 2 }] })).ok().unwrap();
        assert_eq!(wide, forward::defaults());
        assert_eq!((&stored_json(&wide)["rules"][0]["address"], &stored_json(&wide)["rules"][0]["port"], &stored_json(&wide)["rules"][0]["port_end"], &stored_json(&wide)["rules"][1]["address"]), (&json!("224.0.0.0/4"), &json!(1), &json!(65535), &json!("255.255.255.255")));
    }

    #[test]
    fn bad_rules_name_the_rule_and_the_field() {
        let fields = |value: Value| rules_of(value).err().expect("refused").fields;
        let error = fields(json!({ "rules": [{ "name": "ok", "address": "239.2.3.1", "port": 6969 }, { "name": "wide", "address": "192.168.10.255", "port": 1 }] }));
        assert!(error["address"].starts_with("Rule 2 (wide): "), "{error:?}");
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "nope", "port": 1 }] })).contains_key("address"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "10.0.0.0/8" }] })).contains_key("address"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "239.1.1.1", "port_end": 9 }] })).contains_key("port"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "239.1.1.1", "port": 1, "direction": "sideways" }] })).contains_key("direction"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "239.1.1.1", "port": 1, "rate": 1000 }] })).contains_key("rate"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "239.1.1.1", "port": 1, "group": "y" }] })).contains_key("rules"));
        assert!(fields(json!({ "rules": [{ "name": "x", "address": "239.1.1.1", "port": 70000 }] })).contains_key("rules"));
        assert!(fields(json!({})).contains_key("rules"));
    }

    #[test]
    fn the_view_offers_the_default_and_atak_as_presets() {
        let empty = view(&[], false, Some((10, 20)));
        assert_eq!(empty["rules"], json!([]));
        assert_eq!((&empty["presets"][0]["id"], &empty["presets"][0]["rules"][0]["address"], &empty["presets"][0]["rules"][1]["address"]), (&json!("default"), &json!("224.0.0.0/4"), &json!("255.255.255.255")));
        assert_eq!(empty["presets"][1]["id"], "atak");
        assert_eq!(empty["presets"][1]["rules"][0]["address"], "239.2.3.1");
        assert_eq!(empty["presets"][1]["rules"][1]["port"], 17012);
        assert_eq!(empty["node_budget"], json!({ "rate": 10, "burst": 20 }));
        let status = RuleStatus { rule: Rule::new("r", Ipv4Addr::new(239, 2, 3, 1), 6969), counters: Counters { to_mesh_packets: 3, duplicates: 2, last_to_mesh_ms: Some(5_500), ..Counters::default() }, lan: Vec::new() };
        let shown = view(&[status], true, None);
        assert_eq!((&shown["rules"][0]["counters"]["to_mesh_packets"], &shown["rules"][0]["counters"]["dropped"]["duplicate"], &shown["rules"][0]["counters"]["last_to_mesh_ts"]), (&json!(3), &json!(2), &json!(5)));
    }
}
