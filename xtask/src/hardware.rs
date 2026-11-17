//! `cargo xtask hardware [--check]`: README.md's "Supported hardware" table,
//! built from what the repository knows about each card.
//!
//! It reads three things:
//!
//! - `hardware/cards.toml`: the cards the table lists, their PCI or USB IDs,
//!   and each card's status and the machines it was tested on.
//! - `hardware/reports/*.json`: `owly test-card` reports, each matched to its
//!   card by the device ID it names.
//! - `crates/owly-radio/drivers.toml`: each card's quirk entry, by device ID
//!   and then by driver, for its status, mode and known issues.
//!
//! and writes the table between the `<!-- hardware-table:start -->` and
//! `<!-- hardware-table:end -->` lines of README.md. With `--check` it
//! writes nothing, and fails if the table there isn't the one it would
//! write.
//!
//! The rules:
//!
//! - A report **passes** when both transfers ("phone -> computer" and
//!   "computer -> phone") pass and no step fails, so Wi-Fi came back after
//!   teardown. It's **partial** when something passed but not all of that,
//!   and **fails** when no transfer passed and a step failed.
//! - A card with no report keeps the status cards.toml records for it,
//!   word for word. A card with reports takes its status from the latest
//!   report for each of its device IDs, the best of them: ✅ if one passes,
//!   ⚠️ if one is partial, ❌ if they all fail. A card whose quirk entry
//!   says `broken` is ❌ whatever its reports say, until the entry changes.
//! - The mode is the passing reports' mode, else the quirk entry's, marked
//!   "(opt-in)" when the entry isn't `tested`. A ⚠️ or ❌ links the issues
//!   its quirk entry cites.
//! - "Tested on" lists one machine per device ID, mode and result
//!   (the latest such report), so a second machine only appears when it
//!   tells readers something new, failures included, after the machines
//!   cards.toml lists for the card.
//! - Rows are grouped ✅, ⚠️, ❌, ❓, and within a group MediaTek, Realtek
//!   and Qualcomm cards come before others, and Intel last, since `iwlwifi`
//!   only supports exclusive mode. Otherwise they keep cards.toml's order.
//!
//! Every reported device ID must be on a card in cards.toml, with the
//! driver the report names: a report for a card the table doesn't know
//! fails the run instead of being left out.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

const START: &str = "<!-- hardware-table:start -->";
const END: &str = "<!-- hardware-table:end -->";

pub fn run(root: &Path, check: bool) -> Result<(), String> {
    let cards = parse_cards(&read(&root.join("hardware/cards.toml"))?)
        .map_err(|e| format!("hardware/cards.toml: {e}"))?;
    let drivers = parse_drivers(&read(&root.join("crates/owly-radio/drivers.toml"))?)
        .map_err(|e| format!("crates/owly-radio/drivers.toml: {e}"))?;
    let mut reports = Vec::new();
    let dir = root.join("hardware/reports");
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let name = format!(
            "hardware/reports/{}",
            path.file_name().unwrap().to_string_lossy()
        );
        let report: Report =
            serde_json::from_str(&read(&path)?).map_err(|e| format!("{name}: {e}"))?;
        reports.push((name, report));
    }

    let table = table(&cards, &drivers, &reports)?;
    let readme_path = root.join("README.md");
    let readme = read(&readme_path)?;
    let updated = splice(&readme, &table)?;
    if check {
        if updated != readme {
            return Err(
                "README.md's hardware table isn't what hardware/ and drivers.toml say: run `cargo xtask hardware`"
                    .into(),
            );
        }
        println!("README.md's hardware table is up to date");
    } else if updated != readme {
        fs::write(&readme_path, updated).map_err(|e| format!("README.md: {e}"))?;
        println!("wrote README.md's hardware table");
    } else {
        println!("README.md's hardware table is up to date");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CardsFile {
    #[serde(default)]
    card: Vec<Card>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Card {
    name: String,
    driver: String,
    #[serde(default)]
    ids: Vec<String>,
    status: Option<String>,
    #[serde(default)]
    tested_on: Vec<String>,
}

/// The parts of a drivers.toml entry the table uses.
#[derive(Debug, Deserialize)]
struct Quirk {
    status: String,
    mode: String,
    #[serde(default)]
    issues: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Drivers {
    #[serde(default)]
    drivers: BTreeMap<String, Quirk>,
    #[serde(default)]
    devices: BTreeMap<String, Quirk>,
}

/// The parts of an `owly test-card` report the table uses. Others, and
/// fields later versions add, are ignored.
#[derive(Debug, Default, Deserialize)]
struct Report {
    #[serde(default)]
    time: u64,
    #[serde(default)]
    kernel: String,
    #[serde(default)]
    os: String,
    /// The machine's vendor and model, from reports that have it.
    machine: Option<String>,
    driver: Option<String>,
    device: Option<String>,
    mode: Option<String>,
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct Step {
    step: String,
    result: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Fail,
    Partial,
    Pass,
}

impl Report {
    fn verdict(&self) -> Verdict {
        let passed = |name: &str| {
            self.steps
                .iter()
                .any(|s| s.step == name && s.result == "pass")
        };
        let transfers = [passed("phone -> computer"), passed("computer -> phone")];
        let failed = self.steps.iter().any(|s| s.result == "fail");
        if transfers.iter().all(|&t| t) && !failed {
            Verdict::Pass
        } else if transfers.iter().any(|&t| t) || !failed {
            Verdict::Partial
        } else {
            Verdict::Fail
        }
    }

    fn first_failure(&self) -> Option<&str> {
        self.steps
            .iter()
            .find(|s| s.result == "fail")
            .map(|s| s.step.as_str())
    }
}

fn parse_cards(text: &str) -> Result<Vec<Card>, String> {
    let file: CardsFile = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for card in &file.card {
        if !names.insert(card.name.as_str()) {
            return Err(format!("{} is listed twice", card.name));
        }
        for id in &card.ids {
            if !is_device_id(id) {
                return Err(format!(
                    "{}: {id:?} isn't a PCI or USB ID such as \"8086:51f1\"",
                    card.name
                ));
            }
            if !ids.insert(id.as_str()) {
                return Err(format!("{id} is on two cards"));
            }
        }
    }
    Ok(file.card)
}

fn parse_drivers(text: &str) -> Result<Drivers, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

/// `8086:51f1`: two groups of four lowercase hex digits.
fn is_device_id(s: &str) -> bool {
    let hex = |p: &str| {
        p.len() == 4
            && p.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    s.split_once(':').is_some_and(|(a, b)| hex(a) && hex(b))
}

struct Row {
    group: usize,
    vendor: usize,
    order: usize,
    cells: [String; 4],
}

fn table(
    cards: &[Card],
    drivers: &Drivers,
    reports: &[(String, Report)],
) -> Result<String, String> {
    // Every report belongs to a card.
    let mut by_card: Vec<Vec<&Report>> = cards.iter().map(|_| Vec::new()).collect();
    for (name, report) in reports {
        let device = report
            .device
            .as_deref()
            .ok_or_else(|| format!("{name}: the report names no device ID"))?;
        let Some(i) = cards
            .iter()
            .position(|c| c.ids.iter().any(|id| id == device))
        else {
            return Err(format!(
                "{name}: device {device} isn't on any card in hardware/cards.toml: add it to its card's ids, or add the card"
            ));
        };
        let driver = report.driver.as_deref().unwrap_or_default();
        if driver != cards[i].driver {
            return Err(format!(
                "{name}: the report's driver is {driver:?}, but hardware/cards.toml has {} on {}",
                cards[i].name, cards[i].driver
            ));
        }
        by_card[i].push(report);
    }

    let mut rows = Vec::new();
    for (order, (card, reports)) in cards.iter().zip(by_card).enumerate() {
        let quirk = quirk(card, drivers)
            .ok_or_else(|| format!("drivers.toml has no entry for {} and no \"*\"", card.name))?;
        let (group, status) = status(card, quirk, &reports);
        rows.push(Row {
            group,
            vendor: vendor(&card.name),
            order,
            cells: [
                card.name.clone(),
                format!("`{}`", card.driver),
                status,
                tested_on(card, &reports),
            ],
        });
    }
    rows.sort_by_key(|r| (r.group, r.vendor, r.order));

    let mut out = String::from("| Card | Driver | Status | Tested on |\n|---|---|---|---|\n");
    for row in rows {
        let cells: Vec<_> = row.cells.iter().map(|c| c.replace('|', "\\|")).collect();
        out.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    Ok(out)
}

/// A device's own entry, else its driver's, else `*`.
fn quirk<'a>(card: &Card, drivers: &'a Drivers) -> Option<&'a Quirk> {
    card.ids
        .iter()
        .find_map(|id| drivers.devices.get(id))
        .or_else(|| drivers.drivers.get(&card.driver))
        .or_else(|| drivers.drivers.get("*"))
}

/// The row's group (0 for ✅ to 3 for ❓) and its status cell.
fn status(card: &Card, quirk: &Quirk, reports: &[&Report]) -> (usize, String) {
    let opt_in = if quirk.status == "tested" {
        ""
    } else {
        " (opt-in)"
    };
    let links = issue_links(&quirk.issues);

    if quirk.status == "broken" {
        if reports.is_empty()
            && let Some(status) = card.status.as_deref().filter(|s| s.starts_with('❌'))
        {
            return (2, status.to_string());
        }
        return (2, format!("❌ {}{links}", mode_name(&quirk.mode)));
    }
    if reports.is_empty() {
        return match card.status.as_deref() {
            Some(status) => (group(status), status.to_string()),
            None => (
                3,
                format!("❓ {}{opt_in}, untested", mode_name(&quirk.mode)),
            ),
        };
    }

    // The latest report for each device ID.
    let mut latest: BTreeMap<&str, &Report> = BTreeMap::new();
    for r in reports {
        let id = r.device.as_deref().unwrap_or_default();
        if latest.get(id).is_none_or(|l| l.time <= r.time) {
            latest.insert(id, r);
        }
    }
    let best = latest.values().map(|r| r.verdict()).max().unwrap();
    let counted: Vec<_> = latest.values().filter(|r| r.verdict() == best).collect();
    let modes: BTreeSet<_> = counted
        .iter()
        .map(|r| r.mode.as_deref().unwrap_or(&quirk.mode))
        .map(mode_name)
        .collect();
    let mode = modes.into_iter().collect::<Vec<_>>().join(" and ");
    match best {
        Verdict::Pass => (0, format!("✅ {mode}{opt_in}")),
        Verdict::Partial => (1, format!("⚠️ {mode}{opt_in}{links}")),
        Verdict::Fail => (2, format!("❌ {mode}{links}")),
    }
}

/// A status cell's group, from its emoji: 0 for ✅ to 3 for ❓.
fn group(status: &str) -> usize {
    ["✅", "⚠️", "❌"]
        .iter()
        .position(|e| status.starts_with(e))
        .unwrap_or(3)
}

fn tested_on(card: &Card, reports: &[&Report]) -> String {
    let mut lines = card.tested_on.clone();
    if !reports.is_empty() {
        // The latest report for each device ID, mode and result.
        let mut seen = BTreeMap::new();
        for r in reports {
            let key = (r.device.clone(), r.mode.clone(), r.verdict());
            if seen.get(&key).is_none_or(|l: &&Report| l.time <= r.time) {
                seen.insert(key, *r);
            }
        }
        let mut chosen: Vec<_> = seen.into_values().collect();
        chosen.sort_by_key(|r| r.time);
        // Name the mode only where the reports differ in it.
        let modes: BTreeSet<_> = chosen.iter().map(|r| r.mode.as_deref()).collect();
        let with_mode = modes.len() > 1;
        lines.extend(chosen.into_iter().map(|r| machine_line(r, with_mode)));
    }
    match lines.len() {
        0 => "—".into(),
        1 => lines.into_iter().next().unwrap(),
        _ => lines
            .iter()
            .map(|l| format!("• {l}"))
            .collect::<Vec<_>>()
            .join("<br>"),
    }
}

/// `XPS 13, `8086:51f0`, Arch Linux (kernel 7.2.5)`, with the mode if
/// `with_mode` and what didn't work.
fn machine_line(r: &Report, with_mode: bool) -> String {
    let mut parts = Vec::new();
    if let Some(m) = r
        .machine
        .as_deref()
        .map(machine_name)
        .filter(|m| !m.is_empty())
    {
        parts.push(m);
    }
    if let Some(d) = &r.device {
        parts.push(format!("`{d}`"));
    }
    let kernel = kernel_version(&r.kernel);
    let os = os_name(&r.os);
    match (os.is_empty(), kernel.is_empty()) {
        (false, false) => parts.push(format!("{os} (kernel {kernel})")),
        (false, true) => parts.push(os.to_string()),
        (true, false) => parts.push(format!("kernel {kernel}")),
        (true, true) => {}
    }
    if let Some(mode) = r.mode.as_deref().filter(|_| with_mode) {
        parts.push(mode_name(mode).to_lowercase());
    }
    let mut line = parts.join(", ");
    match r.verdict() {
        Verdict::Pass => {}
        Verdict::Partial => line.push_str(": partly"),
        Verdict::Fail => {
            line.push_str(": fails");
            if let Some(step) = r.first_failure() {
                line.push_str(&format!(" at \"{step}\""));
            }
        }
    }
    line
}

/// `Intel(R) Client Systems NUC10i7FNK` is `Intel Client Systems
/// NUC10i7FNK`: DMI's trademark marks are noise in a table.
fn machine_name(dmi: &str) -> String {
    dmi.replace("(R)", "")
        .replace("(TM)", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `NixOS 26.05 (Yarara)` is `NixOS 26.05`: os-release's PRETTY_NAME
/// often ends in a codename or edition.
fn os_name(pretty: &str) -> &str {
    let os = pretty.trim();
    match os.rfind(" (") {
        Some(i) if os.ends_with(')') => os[..i].trim_end(),
        _ => os,
    }
}

/// `7.2.5-arch1-1` is `7.2.5`.
fn kernel_version(release: &str) -> &str {
    let end = release
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(release.len());
    release[..end].trim_end_matches('.')
}

fn mode_name(mode: &str) -> &str {
    match mode {
        "shared" => "Shared",
        "exclusive" => "Exclusive",
        "active-monitor" => "Active monitor",
        "concurrent" => "Concurrent",
        other => other,
    }
}

/// ` ([#44](…))` for each issue URL the entry's issues cite.
fn issue_links(issues: &[String]) -> String {
    const PREFIX: &str = "https://github.com/t4t5/owly/issues/";
    let mut links = Vec::new();
    for issue in issues {
        let mut rest = issue.as_str();
        while let Some(at) = rest.find(PREFIX) {
            let number: String = rest[at + PREFIX.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !number.is_empty() {
                let link = format!("[#{number}]({PREFIX}{number})");
                if !links.contains(&link) {
                    links.push(link);
                }
            }
            rest = &rest[at + PREFIX.len()..];
        }
    }
    if links.is_empty() {
        String::new()
    } else {
        format!(" ({})", links.join(", "))
    }
}

/// MediaTek, Realtek and Qualcomm first, then others, then Intel.
fn vendor(name: &str) -> usize {
    match name.split_whitespace().next() {
        Some("MediaTek") => 0,
        Some("Realtek") => 1,
        Some("Qualcomm") => 2,
        Some("Intel") => 4,
        _ => 3,
    }
}

/// README with the lines between the markers replaced by `table`.
fn splice(readme: &str, table: &str) -> Result<String, String> {
    let lines: Vec<&str> = readme.split_inclusive('\n').collect();
    let find = |marker: &str| {
        let at: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.trim_end() == marker)
            .map(|(i, _)| i)
            .collect();
        match at[..] {
            [i] => Ok(i),
            [] => Err(format!(
                "README.md has no {marker} line: put the hardware table between {START} and {END}"
            )),
            _ => Err(format!("README.md has more than one {marker} line")),
        }
    };
    let (start, end) = (find(START)?, find(END)?);
    if end < start {
        return Err(format!("README.md has {END} before {START}"));
    }
    let mut out: String = lines[..=start].concat();
    out.push_str(
        "<!-- Generated by `cargo xtask hardware` from hardware/ and crates/owly-radio/drivers.toml: edit those, not this table. -->\n\n",
    );
    out.push_str(table);
    out.push('\n');
    out.push_str(&lines[end..].concat());
    Ok(out)
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRIVERS: &str = r#"
[drivers.iwlwifi]
status = "tested"
mode = "exclusive"

[drivers.mt7921e]
status = "untested"
mode = "active-monitor"
issues = ["Slow (https://github.com/t4t5/owly/issues/14)."]

[devices."8086:095a"]
status = "broken"
mode = "exclusive"
issues = ["Asserts (https://github.com/t4t5/owly/issues/16)."]

[drivers."*"]
status = "untested"
mode = "shared"
"#;

    const CARDS: &str = r#"
[[card]]
name = "Intel AX211"
driver = "iwlwifi"
ids = ["8086:51f1", "8086:51f0"]
status = "✅ Exclusive"
tested_on = ["XPS 9320, `8086:51f0`, Arch (kernel 7.2.3)"]

[[card]]
name = "MediaTek MT7921"
driver = "mt7921e"
ids = ["14c3:7961"]
status = "⚠️ Exclusive, opt-in"

[[card]]
name = "Intel Dual Band Wireless-AC 7265"
driver = "iwlwifi"
ids = ["8086:095a"]
status = "❌ Exclusive: asserts ([#16](https://github.com/t4t5/owly/issues/16))"
tested_on = ["Zenbook, `8086:095a`, Omarchy (kernel 7.2.5)"]

[[card]]
name = "Intel AX210"
driver = "iwlwifi"
status = "❓ Exclusive untested"

[[card]]
name = "Qualcomm WCN6855"
driver = "ath11k_pci"
ids = ["17cb:1103"]
"#;

    fn report(device: &str, driver: &str, time: u64, steps: &[(&str, &str)]) -> Report {
        Report {
            time,
            kernel: "7.2.5-arch1-1".into(),
            os: "Arch Linux".into(),
            machine: Some("Dell XPS 13".into()),
            driver: Some(driver.into()),
            device: Some(device.into()),
            mode: Some("exclusive".into()),
            steps: steps
                .iter()
                .map(|(s, r)| Step {
                    step: s.to_string(),
                    result: r.to_string(),
                })
                .collect(),
        }
    }

    const PASS: &[(&str, &str)] = &[
        ("probe", "pass"),
        ("phone -> computer", "pass"),
        ("computer -> phone", "pass"),
        ("Wi-Fi after teardown", "pass"),
    ];
    const FAIL: &[(&str, &str)] = &[
        ("probe", "pass"),
        ("phone heard", "fail"),
        ("phone -> computer", "fail"),
        ("computer -> phone", "skipped"),
    ];

    fn render(reports: Vec<Report>) -> Result<String, String> {
        let cards = parse_cards(CARDS).unwrap();
        let drivers = parse_drivers(DRIVERS).unwrap();
        let reports: Vec<_> = reports
            .into_iter()
            .enumerate()
            .map(|(i, r)| (format!("r{i}.json"), r))
            .collect();
        table(&cards, &drivers, &reports)
    }

    fn rows(table: &str) -> Vec<&str> {
        table.lines().skip(2).collect()
    }

    #[test]
    fn verdicts() {
        assert_eq!(report("a", "b", 0, PASS).verdict(), Verdict::Pass);
        assert_eq!(report("a", "b", 0, FAIL).verdict(), Verdict::Fail);
        let teardown = [
            ("phone -> computer", "pass"),
            ("computer -> phone", "pass"),
            ("Wi-Fi after teardown", "fail"),
        ];
        assert_eq!(report("a", "b", 0, &teardown).verdict(), Verdict::Partial);
        let one_way = [
            ("phone -> computer", "pass"),
            ("computer -> phone", "skipped"),
        ];
        assert_eq!(report("a", "b", 0, &one_way).verdict(), Verdict::Partial);
    }

    #[test]
    fn without_reports_earlier_results_stand_and_are_grouped() {
        let t = render(vec![]).unwrap();
        assert_eq!(
            rows(&t),
            [
                "| Intel AX211 | `iwlwifi` | ✅ Exclusive | XPS 9320, `8086:51f0`, Arch (kernel 7.2.3) |",
                "| MediaTek MT7921 | `mt7921e` | ⚠️ Exclusive, opt-in | — |",
                "| Intel Dual Band Wireless-AC 7265 | `iwlwifi` | ❌ Exclusive: asserts ([#16](https://github.com/t4t5/owly/issues/16)) | Zenbook, `8086:095a`, Omarchy (kernel 7.2.5) |",
                "| Qualcomm WCN6855 | `ath11k_pci` | ❓ Shared (opt-in), untested | — |",
                "| Intel AX210 | `iwlwifi` | ❓ Exclusive untested | — |",
            ]
        );
    }

    #[test]
    fn machine_and_os_names_are_tidied() {
        assert_eq!(
            machine_name("Intel(R) Client Systems  NUC10i7FNK"),
            "Intel Client Systems NUC10i7FNK"
        );
        assert_eq!(machine_name("Dell XPS 13"), "Dell XPS 13");
        assert_eq!(os_name("NixOS 26.05 (Yarara)"), "NixOS 26.05");
        assert_eq!(
            os_name("Debian GNU/Linux 12 (bookworm)"),
            "Debian GNU/Linux 12"
        );
        assert_eq!(os_name("Ubuntu 24.04.1 LTS"), "Ubuntu 24.04.1 LTS");
        assert_eq!(os_name(" Arch Linux "), "Arch Linux");
    }

    #[test]
    fn a_passing_report_makes_a_card_green_and_lists_a_failure_beside_it() {
        let t = render(vec![
            report("8086:51f1", "iwlwifi", 10, PASS),
            report("8086:51f1", "iwlwifi", 5, PASS),
            report("8086:51f0", "iwlwifi", 20, FAIL),
        ])
        .unwrap();
        assert_eq!(
            rows(&t)[0],
            "| Intel AX211 | `iwlwifi` | ✅ Exclusive | • XPS 9320, `8086:51f0`, Arch (kernel 7.2.3)<br>• Dell XPS 13, `8086:51f1`, Arch Linux (kernel 7.2.5)<br>• Dell XPS 13, `8086:51f0`, Arch Linux (kernel 7.2.5): fails at \"phone heard\" |"
        );
    }

    #[test]
    fn reports_in_different_modes_say_which() {
        let mut shared = report("8086:51f1", "iwlwifi", 2, FAIL);
        shared.mode = Some("shared".into());
        let t = render(vec![report("8086:51f1", "iwlwifi", 1, PASS), shared]).unwrap();
        assert!(t.contains("<br>• Dell XPS 13, `8086:51f1`, Arch Linux (kernel 7.2.5), exclusive<br>• Dell XPS 13, `8086:51f1`, Arch Linux (kernel 7.2.5), shared: fails at \"phone heard\" |"), "{t}");
    }

    #[test]
    fn opt_in_and_partial_link_issues() {
        let mut r = report("14c3:7961", "mt7921e", 1, &[("phone -> computer", "pass")]);
        r.mode = Some("active-monitor".into());
        let t = render(vec![r]).unwrap();
        assert!(t.contains("| MediaTek MT7921 | `mt7921e` | ⚠️ Active monitor (opt-in) ([#14](https://github.com/t4t5/owly/issues/14)) |"), "{t}");
    }

    #[test]
    fn broken_stays_red_with_a_report() {
        let t = render(vec![report("8086:095a", "iwlwifi", 1, PASS)]).unwrap();
        assert!(t.contains("| ❌ Exclusive ([#16](https://github.com/t4t5/owly/issues/16)) | • Zenbook, `8086:095a`, Omarchy (kernel 7.2.5)<br>• Dell XPS 13, `8086:095a`"), "{t}");
    }

    #[test]
    fn unknown_device_or_driver_fails() {
        let e = render(vec![report("8086:9999", "iwlwifi", 1, PASS)]).unwrap_err();
        assert!(e.contains("8086:9999 isn't on any card"), "{e}");
        let e = render(vec![report("8086:51f1", "mt7921e", 1, PASS)]).unwrap_err();
        assert!(e.contains("the report's driver"), "{e}");
    }

    #[test]
    fn cards_are_checked() {
        let twice = "[[card]]\nname = \"A\"\ndriver = \"x\"\nids = [\"8086:0001\"]\n[[card]]\nname = \"B\"\ndriver = \"x\"\nids = [\"8086:0001\"]\n";
        assert!(parse_cards(twice).unwrap_err().contains("on two cards"));
        let bad = "[[card]]\nname = \"A\"\ndriver = \"x\"\nids = [\"8086:51F1\"]\n";
        assert!(parse_cards(bad).is_err());
    }

    #[test]
    fn reports_tolerate_unknown_and_missing_fields() {
        let r: Report = serde_json::from_str(
            r#"{"owly":"0.1.0","time":3,"kernel":"7.0.0","os":"Ubuntu","device":"8086:51f1","driver":"iwlwifi","steps":[],"wifi":{},"new":1}"#,
        )
        .unwrap();
        assert!(r.machine.is_none());
        assert_eq!(kernel_version("6.19.8-1-cachyos"), "6.19.8");
        assert_eq!(kernel_version("7.0"), "7.0");
    }

    #[test]
    fn splice_replaces_between_markers() {
        let readme = format!("# A\n\n{START}\nold\n{END}\n\nafter\n");
        let out = splice(&readme, "| t |\n").unwrap();
        assert!(out.starts_with(&format!("# A\n\n{START}\n<!-- Generated")));
        assert!(out.ends_with(&format!("\n\n| t |\n\n{END}\n\nafter\n")));
        assert_eq!(splice(&out, "| t |\n").unwrap(), out);
        assert!(
            splice("# A\n", "x")
                .unwrap_err()
                .contains("no <!-- hardware-table:start -->")
        );
    }

    #[test]
    fn the_repository_s_data_renders() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cards = parse_cards(&read(&root.join("hardware/cards.toml")).unwrap()).unwrap();
        let drivers =
            parse_drivers(&read(&root.join("crates/owly-radio/drivers.toml")).unwrap()).unwrap();
        let t = table(&cards, &drivers, &[]).unwrap();
        assert_eq!(rows(&t).len(), cards.len());
    }
}
