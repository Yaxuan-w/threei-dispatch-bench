//! Small measurement harness: warm up, auto-size the inner loop, take several
//! trials, report the median and the minimum. Minimum is the more stable figure
//! for microbenchmarks; the median is reported alongside so that a large gap
//! flags a noisy machine.

use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Stat {
    pub name: String,
    pub group: String,
    pub ns_min: f64,
    pub ns_median: f64,
    pub iters: u64,
    pub trials: usize,
}

pub fn bench<F>(group: &str, name: &str, min_trials: usize, mut f: F) -> Stat
where
    F: FnMut(u64) -> u64,
{
    // auto-size so that one trial takes ~20ms
    let mut iters: u64 = 64;
    loop {
        let t0 = Instant::now();
        std::hint::black_box(f(iters));
        let dt = t0.elapsed();
        if dt >= Duration::from_millis(20) || iters >= 1 << 28 {
            break;
        }
        let scale = (Duration::from_millis(20).as_secs_f64() / dt.as_secs_f64()).max(2.0);
        iters = ((iters as f64) * scale.min(64.0)) as u64;
    }

    // warmup
    std::hint::black_box(f(iters));

    let mut samples = Vec::with_capacity(min_trials);
    for _ in 0..min_trials {
        let t0 = Instant::now();
        std::hint::black_box(f(iters));
        let dt = t0.elapsed();
        samples.push(dt.as_secs_f64() * 1e9 / iters as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());

    Stat {
        name: name.to_string(),
        group: group.to_string(),
        ns_min: samples[0],
        ns_median: samples[samples.len() / 2],
        iters,
        trials: min_trials,
    }
}

pub fn render_table(stats: &[Stat], baseline: Option<f64>) -> String {
    let mut out = String::new();
    out.push_str("| group | scenario | ns/op (min) | ns/op (median) | vs baseline |\n");
    out.push_str("|---|---|---:|---:|---:|\n");
    let mut last_group = String::new();
    for s in stats {
        let g = if s.group == last_group { String::new() } else { s.group.clone() };
        last_group = s.group.clone();
        let rel = match baseline {
            Some(b) if b > 0.0 => format!("{:.2}x", s.ns_min / b),
            _ => "-".to_string(),
        };
        out.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {} |\n",
            g, s.name, s.ns_min, s.ns_median, rel
        ));
    }
    out
}

pub fn render_csv(stats: &[Stat]) -> String {
    let mut out = String::from("group,scenario,ns_min,ns_median,iters,trials\n");
    for s in stats {
        out.push_str(&format!(
            "{},{},{:.3},{:.3},{},{}\n",
            s.group, s.name, s.ns_min, s.ns_median, s.iters, s.trials
        ));
    }
    out
}
