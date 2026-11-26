use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct Dc {
    wire: i16,
    number: u16,
    media: bool,
    test: bool,
}

impl Dc {
    pub fn decode(wire: i16) -> Self {
        let number = wire.unsigned_abs();
        Self {
            wire,
            number: if number >= 10_000 {
                number - 10_000
            } else {
                number
            },
            media: wire < 0,
            test: number >= 10_000,
        }
    }

    pub fn relay_id(self) -> i16 {
        if self.media {
            -(self.number as i16)
        } else {
            self.number as i16
        }
    }

    pub fn label(self) -> String {
        format!(
            "DC{}{}{}",
            self.number,
            if self.media { " media" } else { "" },
            if self.test { " test" } else { "" }
        )
    }
}

#[derive(Deserialize)]
pub struct Socks {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub automatic: bool,
    pub routes: HashMap<i16, Vec<Vec<Stage>>>,
    pub mobile_routes: HashMap<i16, Vec<Vec<Stage>>>,
    pub socks: Option<Socks>,
}

impl Config {
    pub fn groups(&self, dc: Dc, cellular: bool) -> &[Vec<Stage>] {
        let routes = if cellular {
            &self.mobile_routes
        } else {
            &self.routes
        };
        routes.get(&dc.wire).map(Vec::as_slice).unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Family {
    System,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub address: String,
    pub path: Option<String>,
    pub sni: Option<String>,
    pub label: String,
    pub socks: bool,
    pub port: u16,
    pub family: Family,
}

impl Target {
    pub fn description(&self) -> String {
        if self.socks || self.label.starts_with("Cloudflare") {
            return self.label.clone();
        }
        match &self.sni {
            Some(sni) => format!("{} · {} · TLS {}", self.label, self.host, sni),
            None => format!("{} · {}", self.label, self.host),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub targets: Vec<Target>,
    pub limit: usize,
    pub public_relay: bool,
}

#[derive(Default)]
pub struct Health(Mutex<History>);

#[derive(Default)]
struct History {
    preferred: HashMap<Dc, (Target, Instant)>,
    failed: HashMap<(Dc, Target), (u32, Instant)>,
    last_no_route: HashMap<Dc, Instant>,
    ranking: HashMap<(Dc, usize), (Vec<Target>, Instant)>,
    measurements: HashMap<(Dc, usize), Arc<tokio::sync::Mutex<()>>>,
    rotation: usize,
}

impl Health {
    pub fn preferred(&self, dc: Dc) -> Option<Target> {
        self.0
            .lock()
            .unwrap()
            .preferred
            .get(&dc)
            .filter(|(_, when)| when.elapsed() < Duration::from_secs(300))
            .map(|(target, _)| target.clone())
    }

    pub fn ready(&self, dc: Dc, target: &Target) -> bool {
        self.0
            .lock()
            .unwrap()
            .failed
            .get(&(dc, target.clone()))
            .is_none_or(|(_, retry)| Instant::now() >= *retry)
    }

    pub fn succeeded(&self, dc: Dc, target: &Target) {
        let mut history = self.0.lock().unwrap();
        history.failed.remove(&(dc, target.clone()));
        history
            .preferred
            .insert(dc, (target.clone(), Instant::now()));
    }

    pub fn failed(&self, dc: Dc, target: &Target, started: Instant, automatic: bool) {
        let mut history = self.0.lock().unwrap();
        if let Some((preferred, observed)) = history.preferred.get(&dc) {
            if preferred == target {
                if *observed > started {
                    return;
                }
                history.preferred.remove(&dc);
            }
        }
        let now = Instant::now();
        let key = (dc, target.clone());
        let count = match history.failed.get(&key) {
            Some(&(count, retry))
                if now.saturating_duration_since(retry) <= Duration::from_secs(120) =>
            {
                (count + 1).min(4)
            }
            _ => 1,
        };
        let secs = if count == 1 {
            if automatic {
                4
            } else {
                0
            }
        } else {
            4 << (count - 2)
        };
        history
            .failed
            .insert(key, (count, now + Duration::from_secs(secs)));
    }

    pub fn report_no_route(&self, dc: Dc) -> bool {
        let mut history = self.0.lock().unwrap();
        if history
            .last_no_route
            .get(&dc)
            .is_some_and(|last| last.elapsed() < Duration::from_secs(5))
        {
            return false;
        }
        history.last_no_route.insert(dc, Instant::now());
        true
    }

    pub fn rotate(&self, targets: &mut [Target], limit: usize) {
        if !targets.is_empty() && targets.len() > limit {
            let mut history = self.0.lock().unwrap();
            targets.rotate_left(history.rotation % targets.len());
            history.rotation = history.rotation.wrapping_add(limit);
        }
    }

    pub fn cached(&self, dc: Dc, group: usize) -> Option<Vec<Target>> {
        self.0
            .lock()
            .unwrap()
            .ranking
            .get(&(dc, group))
            .filter(|(_, expiry)| Instant::now() < *expiry)
            .map(|(targets, _)| targets.clone())
    }

    pub fn remember(&self, dc: Dc, group: usize, targets: Vec<Target>) {
        let ttl = Duration::from_secs(if targets.is_empty() { 30 } else { 300 });
        self.0
            .lock()
            .unwrap()
            .ranking
            .insert((dc, group), (targets, Instant::now() + ttl));
    }

    pub fn measurement_lock(&self, dc: Dc, group: usize) -> Arc<tokio::sync::Mutex<()>> {
        self.0
            .lock()
            .unwrap()
            .measurements
            .entry((dc, group))
            .or_default()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_separate_wire_dc_and_cellular_plan() {
        let config: Config = serde_json::from_str(r#"{"automatic":true,"routes":{"-203":[]},"mobileRoutes":{"-203":[[{"targets":[],"limit":4,"publicRelay":true}]]}}"#).unwrap();
        let dc = Dc::decode(-203);
        assert_eq!(dc.relay_id(), -203);
        assert!(config.groups(dc, false).is_empty());
        assert!(config.groups(dc, true)[0][0].public_relay);
        assert!(config.groups(Dc::decode(203), true).is_empty());
        assert_eq!(Dc::decode(-10002).relay_id(), -2);
    }
}
