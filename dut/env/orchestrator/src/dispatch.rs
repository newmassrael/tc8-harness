//! Per-case dispatch: build `--expect`, spawn harness + DUT in start order,
//! poll to a verdict, classify it. Mirrors smoke-test.sh run_case
//! (lines 1457-1630) for the single-worker positive path.

use anyhow::Result;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use crate::config::Config;
use crate::topology::{Topology, WorkerCtx};

pub enum Verdict {
    Pass,
    Fail(String),
    Skip(String),
}

pub fn run_case(
    cfg: &Config,
    topo: &dyn Topology,
    w: u32,
    ctx: &WorkerCtx,
    case_id: &str,
    dut_first: bool,
) -> Result<Verdict> {
    let hlog = cfg.work_root.join(format!("{w}/{case_id}.harness.log"));
    let dlog = cfg.work_root.join(format!("{w}/{case_id}.dut.log"));
    let iface = topo.tester_iface(w);

    let mut args = vec![
        "test".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "-i".to_string(),
        iface,
        "-t".to_string(),
        cfg.backstop_sec.to_string(),
    ];
    args.extend(expect_args(cfg, case_id, &ctx.dut_mac));

    // Order: harness first so its pcap is open before the DUT's first
    // OfferService (FORMAT_02 session_id==0x0001); --dut-first inverts it.
    let mut harness;
    if dut_first {
        let _dut = topo.start_dut(w, &dlog, &cfg.vsomeip_cfg)?;
        sleep(Duration::from_millis(1500));
        harness = topo.run_harness(w, &hlog, &args)?;
    } else {
        harness = topo.run_harness(w, &hlog, &args)?;
        sleep(Duration::from_millis(500));
        let _dut = topo.start_dut(w, &dlog, &cfg.vsomeip_cfg)?;
    }

    // Poll the harness to its verdict: (backstop+3)*5 ticks @ 0.2s, capped at
    // 1100 (220s wall) — the harness exits the instant its SCXML reaches a
    // final state, so a fast case finishes well before the ceiling.
    let budget = (u64::from(cfg.backstop_sec + 3) * 5).min(1100);
    for _ in 0..budget {
        if harness.try_wait()?.is_some() {
            break;
        }
        sleep(Duration::from_millis(200));
    }
    let _ = harness.kill();
    let _ = harness.wait();
    topo.stop_dut(w)?;

    Ok(classify(&hlog))
}

/// First `^verdict  :` line → class (smoke-test.sh 1592-1625): pass → Pass;
/// skip/inconclusive/error → Skip (non-conclusion, not a gate fail); else Fail.
fn classify(hlog: &Path) -> Verdict {
    let text = std::fs::read_to_string(hlog).unwrap_or_default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("verdict  : ") {
            let v = v.trim();
            if v.starts_with("pass") {
                return Verdict::Pass;
            }
            if v.starts_with("skip") || v.starts_with("inconclusive") || v.starts_with("error") {
                return Verdict::Skip(v.to_string());
            }
            return Verdict::Fail(v.to_string());
        }
    }
    Verdict::Fail("no verdict line in harness log".to_string())
}

fn ex(e: &mut Vec<String>, key: &str, value: &str) {
    e.push("--expect".to_string());
    e.push(format!("{key}={value}"));
}

/// base TC8_DUT_EXPECT + the case's category static group
/// (smoke-test.sh init_expectation_defaults). Stage 1 covers ARP / ICMPv4 /
/// IPv4 statics; the full per-case override map lands in a later stage.
fn expect_args(cfg: &Config, case_id: &str, dut_mac: &str) -> Vec<String> {
    let mut e = Vec::new();
    // base
    ex(&mut e, "service_id", "0xF4E7");
    ex(&mut e, "instance_id", "0x0001");
    ex(&mut e, "major_version", "1");
    ex(&mut e, "ttl", "3");
    ex(&mut e, "minor_version", "0");
    ex(&mut e, "eventgroup_id", "0x0001");
    ex(&mut e, "dut_iface_ip", &cfg.dut_ip4);
    ex(&mut e, "udp_port", "30502");
    ex(&mut e, "tcp_port", "30501");
    ex(&mut e, "sd_multicast_ip", "224.244.224.245");
    ex(&mut e, "mcast_ipv4", "224.244.224.246");
    ex(&mut e, "mcast_port", "30495");

    let cat = case_id.to_uppercase();
    if cat.starts_with("ARP_") {
        ex(&mut e, "arp.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "arp.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "arp.dut_iface_mac", dut_mac);
        ex(&mut e, "dut.ip", &cfg.dut_ip4);
        ex(&mut e, "arp.tester_mac", "02:00:00:00:00:A1");
        ex(&mut e, "arp.tester_mac2", "02:00:00:00:00:A2");
        ex(&mut e, "arp.tester_mac3", "02:00:00:00:00:A3");
    } else if cat.starts_with("ICMPV4_") {
        ex(&mut e, "icmpv4.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "icmpv4.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "icmpv4.echo_id", "0x1234");
        ex(&mut e, "icmpv4.echo_seq", "0x5678");
    } else if cat.starts_with("IPV4_") {
        ex(&mut e, "ipv4.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "ipv4.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "ipv4.dut_alias_ip", "172.16.0.5");
        ex(&mut e, "ipv4.tester_alias_ip", "172.16.0.4");
    }
    e
}
