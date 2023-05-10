use serde::{Deserialize, Serialize};
use slog::{info, warn};
use std::time::Duration;
use thiserror::Error;

use super::VmmHdl;

pub(crate) const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VmTimeData {
    /// guest TSC frequency (hz)
    pub guest_freq: u64,

    /// current guest TSC
    pub guest_tsc: u64,

    /// monotonic host clock (ns)
    pub hrtime: u64,

    /// wall clock host clock (sec)
    pub hres_sec: u64,

    /// wall clock host clock (ns)
    pub hres_ns: u64,

    /// guest boot_hrtime (can be negative)
    pub boot_hrtime: i64,
}

impl VmTimeData {
    pub fn wall_clock(&self) -> Duration {
        Duration::new(self.hres_sec, self.hres_ns as u32)
    }
}

impl From<bhyve_api::vdi_time_info_v1> for VmTimeData {
    fn from(raw: bhyve_api::vdi_time_info_v1) -> Self {
        Self {
            guest_freq: raw.vt_guest_freq,
            guest_tsc: raw.vt_guest_tsc,
            hrtime: raw.vt_hrtime as u64,
            hres_sec: raw.vt_hres_sec,
            hres_ns: raw.vt_hres_ns,
            boot_hrtime: raw.vt_boot_hrtime,
        }
    }
}
impl From<VmTimeData> for bhyve_api::vdi_time_info_v1 {
    fn from(info: VmTimeData) -> Self {
        bhyve_api::vdi_time_info_v1 {
            vt_guest_freq: info.guest_freq,
            vt_guest_tsc: info.guest_tsc,
            vt_hrtime: info.hrtime as i64,
            vt_hres_sec: info.hres_sec,
            vt_hres_ns: info.hres_ns,
            vt_boot_hrtime: info.boot_hrtime,
        }
    }
}

pub fn import_time_data(
    hdl: &VmmHdl,
    time_info: VmTimeData,
) -> std::io::Result<()> {
    let raw = bhyve_api::vdi_time_info_v1::from(time_info);
    crate::vmm::data::write(hdl, -1, bhyve_api::VDC_VMM_TIME, 1, raw)?;

    Ok(())
}

pub fn export_time_data(hdl: &VmmHdl) -> std::io::Result<VmTimeData> {
    let time_info: bhyve_api::vdi_time_info_v1 =
        crate::vmm::data::read(hdl, -1, bhyve_api::VDC_VMM_TIME, 1)?;

    Ok(VmTimeData::from(time_info))
}

/// Returns the current host hrtime and wall clock time
//
// The hrtime and wall clock time are exposed via the VMM time data interface.
// These values are available on the system by doing a read of the VMM time
// data.
//
// The kernel side of the interface disables interrupts while it takes the clock
// readings; in the absence of a function to translate between the two clock
// values, this is a best effort way to read the hrtime and wall clock times as
// close to as possible at the same point in time. Thus fishing this data out of
// the VMM time data read payload is strictly better than calling
// clock_gettime(3c) twice from userspace.
pub fn host_time_snapshot(hdl: &VmmHdl) -> std::io::Result<(i64, Duration)> {
    let ti = export_time_data(hdl)?;
    let wc = Duration::new(ti.hres_sec, ti.hres_ns as u32);
    let hrt = ti.hrtime as i64;

    Ok((hrt, wc))
}

#[usdt::provider(provider = "propolis")]
mod probes {
    fn adj_time_begin(guest_freq: u64, guest_tsc: u64, boot_hrtime: i64) {}
    fn adj_time_end(
        guest_freq: u64,
        guest_tsc: u64,
        boot_hrtime: i64,
        vm_uptime: u64,
        migrate_delta: u64,
    ) {
    }
}

/// Given an input representation of guest time data on a source host, and a
/// current host hrtime and wallclock time on the target host, output an
/// "adjusted" view of the guest time data. This data can be imported to bhyve
/// to allow guest time (namely, the guest TSC and its device timers) to allow
/// the guest's sense of time to function properly on the target.
//  See comments inline for more details about how we calculate a new guest TSC
//  and boot_hrtime.
pub fn adjust_time_data(
    src: VmTimeData,
    dst_hrt: i64,
    dst_wc: Duration,
    log: &slog::Logger,
) -> Result<VmTimeData, TimeAdjustError> {
    info!(log, "Adjusting time data for guest: {:#?}", src);
    probes::adj_time_begin!(|| (
        src.guest_freq,
        src.guest_tsc,
        src.boot_hrtime,
    ));

    // Find delta between export on source and import on target using wall clock
    // time. This delta is used for adjusting the TSC and boot_hrtime.
    //
    // We expect to be operating on machines with well-synchronized wall
    // clocks, so using wall clock time is a useful shorthand for observing how
    // much time has passed. If for some reason we see a negative delta (see
    // also: #357), clamp the delta to 0.
    //
    // migrate_delta = target wall clock - source wall clock
    let migrate_delta = match dst_wc.checked_sub(src.wall_clock()) {
        Some(d) => d,
        None => {
            warn!(
                log,
                "Found negative wall clock delta between target import \
                and source export:\n\
                - source wall clock: {:?}\n\
                - target wall clock: {:?}\n",
                src.wall_clock(),
                dst_wc
            );
            Duration::from_secs(0)
        }
    };

    // Find a new boot_hrtime for the guest
    //
    // Device timers are scheduled based on hrtime of the host: For example, a
    // timer that should fire after 1 second is scheduled as: host hrtime + 1s.
    //
    // When devices are exported for migration, time values are normalized
    // against the guest's boot_hrtime on export, and de-normalized against
    // boot_hrtime on import. The boot_hrtime of the guest is set to the hrtime
    // of when the guest booted. Because this value is used on import to fix up
    // timer values, it is critical to set this value prior to importing device
    // state such that existing timers are normalized correctly. As with booting
    // a guest, on the target, it should be set to the hrtime of the host when
    // the guest would have booted, had it booted on that target.
    //
    // An example may be helpful. Consider a guest that has 5 days of uptime,
    // booted on a host with 30 days of uptime. Suppose that guest is migrated
    // with a device timer that should fire 1 second in the future.
    //
    // +=================================================================+
    // | hrtime (source) | guest hrtime | boot_hrtime  | timer value     |
    // +-----------------------------------------------------------------+
    // | 30 days         | 5 days       |(30 - 5) days | src hrtime + 1s |
    // |                 |              | 25 days      | 30 days + 1s    |
    // +=================================================================+
    //
    // Suppose the guest is then migrated to a host with 100 days of uptime.
    // On migration, the existing timer is normalized before export by
    // subtracting out boot_hrtime:
    //       normalized = timer - boot_hrtime
    //                  = (30 days + 1 sec) - 25 days
    //                  = 5 days + 1 sec
    //
    // When the timer is imported, it is denormalized by adding back in
    // the new boot_hrtime. The timer should still fire 1 second from the
    // current hrtime of the host. The target hrtime is 100 days, so the timer
    // should fire at 100 days + 1 sec.
    //
    // Working backwards to get the new boot_hrtime, we have:
    //
    //       denormalized = normalized + boot_hrtime
    //       boot_hrtime  = denormalized - normalized
    //       boot_hrtime  = (100 days + 1 sec) - (5 days + 1 sec)
    //       boot_hrtime  = 95 days
    //
    // And on the target, the timer should still fire 1 second into the future
    // as expected:
    //
    // +=====================================================================+
    // | hrtime (target) | guest hrtime | boot_hrtime   | timer value        |
    // +---------------------------------------------------------------------+
    // | 100 days        | 5 days       |(100 - 5) days |     5 days + 1 sec |
    // |                 |              | 95 days       |   + 95 days        |
    // |                 |              |               | = 100 days + 1 sec |
    // +=====================================================================+
    //
    // NB: It is possible for boot_hrtime to be negative; this occurs if a
    // guest has a longer uptime than its host (an expected common case for
    // migration). This is okay: hrtime is a signed value, and the normalization
    // maths still work with negative values.
    //

    // vm_uptime   = source hrtime - boot_hrtime
    let vm_uptime = (src.hrtime as i64)
        .checked_sub(src.boot_hrtime)
        .ok_or_else(|| TimeAdjustError::GuestUptimeOverflow {
            src_hrt: src.hrtime as i64,
            boot_hrtime: src.boot_hrtime,
        })?;

    // boot_hrtime_delta = vm_uptime + migrate_delta
    let boot_hrtime_delta = vm_uptime
        .checked_add(migrate_delta.as_nanos() as i64)
        .ok_or_else(|| TimeAdjustError::TimeDeltaOverflow {
            uptime_ns: vm_uptime,
            migrate_delta,
        })?;

    // boot_hrtime = target hrtime - boot_hrtime_delta
    let new_boot_hrtime =
        dst_hrt.checked_sub(boot_hrtime_delta).ok_or_else(|| {
            TimeAdjustError::BootHrtimeOverflow {
                total_delta: boot_hrtime_delta,
                dst_hrtime: dst_hrt,
            }
        })?;

    // Get the guest TSC adjustment and add it to the old guest TSC
    //
    // We move the guest TSC forward based on the migrate delta, such that the
    // guest TSC reflects the time passed in migration (which will have paused
    // the guest for some period of time).
    //
    // NB: It is okay to overflow the TSC here: It is possible for the guest to
    // write to the TSC, and if it did so it might expect it to overflow.
    let tsc_delta = calc_tsc_delta(migrate_delta, src.guest_freq)?;
    let new_guest_tsc = src.guest_tsc.wrapping_add(tsc_delta);

    info!(
        log,
        "Timing data adjustments completed.\n\
            - guest TSC freq: {} Hz = {} GHz\n\
            - guest uptime: {:?}\n\
            - migration time delta: {:?}\n\
            - guest_tsc adjustment = {} + {} = {}\n\
            - boot_hrtime adjustment = {} ---> {} - {} = {}\n\
            - dest highres clock time: {}\n\
            - dest wall clock time: {:?}",
        src.guest_freq,
        src.guest_freq as f64 / 1_000_000_000f64,
        vm_uptime,
        migrate_delta,
        src.guest_tsc,
        tsc_delta,
        new_guest_tsc,
        src.boot_hrtime,
        dst_hrt,
        boot_hrtime_delta,
        new_boot_hrtime,
        dst_hrt,
        dst_wc,
    );

    let res = VmTimeData {
        guest_freq: src.guest_freq,
        guest_tsc: new_guest_tsc,
        hrtime: dst_hrt as u64,
        hres_sec: dst_wc.as_secs(),
        hres_ns: dst_wc.subsec_nanos() as u64,
        boot_hrtime: new_boot_hrtime,
    };

    probes::adj_time_end!(|| (
        res.guest_freq,
        res.guest_tsc,
        res.boot_hrtime,
        vm_uptime as u64,
        migrate_delta.as_nanos() as u64,
    ));

    Ok(res)
}

/// Errors related to making timing adjustment calcultions
#[derive(Clone, Debug, Error)]
pub enum TimeAdjustError {
    /// Error calculatip g migration time delta
    #[error("invalid migration delta: src={src_wc:?},dst={dst_wc:?}")]
    InvalidMigrateDelta {
        /// source host wall clock time
        src_wc: Duration,

        /// destination host wall clock time
        dst_wc: Duration,
    },

    /// Error calculating guest uptime
    #[error(
        "guest uptime cannot be represented: \
        src_hrtime={src_hrt:?}, boot_hrtime={boot_hrtime}"
    )]
    GuestUptimeOverflow {
        /// source host hrtime
        src_hrt: i64,

        /// input guest boot_hrtime
        boot_hrtime: i64,
    },

    /// Invalid total delta for boot_hrtime calculations
    #[error(
        "could not calculate time delta: \
            guest uptime {uptime_ns} ns, migrate_delta={migrate_delta:?}"
    )]
    TimeDeltaOverflow {
        /// guest uptime
        uptime_ns: i64,

        /// migration time delta
        migrate_delta: Duration,
    },

    /// Invalid calculated boot_hrtime
    #[error(
        "guest boot_hrtime cannot be represented: \
            total_delta={total_delta:?}, dst_hrtime={dst_hrtime:?}"
    )]
    BootHrtimeOverflow {
        /// calculated total delta (uptime + migration delta)
        total_delta: i64,

        /// destination host hrtime
        dst_hrtime: i64,
    },

    /// Invalid guest TSC adjustment
    #[error(
        "could not calculate TSC adjustment: \
            desc=\"{desc:?}\", migrate_delta={migrate_delta:?},
            guest_hz={guest_hz}, tsc_adjust={tsc_adjust}"
    )]
    TscAdjustOverflow {
        /// error description
        desc: &'static str,

        /// migration time delta
        migrate_delta: Duration,

        /// guest TSC frequency (hz)
        guest_hz: u64,

        /// calculated TSC adjustment
        tsc_adjust: u128,
    },
}

/// Calculate the adjustment needed for the guest TSC.
///
/// ticks = (migrate_delta ns * guest_hz hz) / `NS_PER_SEC`
fn calc_tsc_delta(
    migrate_delta: Duration,
    guest_hz: u64,
) -> Result<u64, TimeAdjustError> {
    assert_ne!(guest_hz, 0);

    let delta_ns: u128 = migrate_delta.as_nanos();
    let mut tsc_adjust: u128 = 0;

    let upper: u128 =
        delta_ns.checked_mul(guest_hz as u128).ok_or_else(|| {
            TimeAdjustError::TscAdjustOverflow {
                desc: "migrate_delta * guest_hz",
                migrate_delta,
                guest_hz,
                tsc_adjust,
            }
        })?;

    tsc_adjust = upper.checked_div(NS_PER_SEC).ok_or_else(|| {
        TimeAdjustError::TscAdjustOverflow {
            desc: "upper / NS_PER_SEC",
            migrate_delta,
            guest_hz,
            tsc_adjust,
        }
    })?;
    if tsc_adjust > u64::MAX as u128 {
        return Err(TimeAdjustError::TscAdjustOverflow {
            desc: "tsc_adjust > 64-bits",
            migrate_delta,
            guest_hz,
            tsc_adjust,
        });
    }

    Ok(tsc_adjust as u64)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::{
        calc_boot_hrtime, calc_boot_hrtime_delta, calc_guest_tsc,
        calc_guest_uptime, calc_migrate_delta, calc_tsc_delta, Hrtime,
        TimeAdjustError, NS_PER_SEC,
    };

    #[test]
    fn test_calc_migrate_delta() {
        // valid input
        let res = calc_migrate_delta(
            Duration::from_nanos(0),
            Duration::from_nanos(1),
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Duration::from_nanos(1));
        let res = calc_migrate_delta(
            Duration::from_nanos(0),
            Duration::from_nanos(0),
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Duration::from_nanos(0));

        // error case: dst_wc < src_wc
        let res = calc_migrate_delta(
            Duration::from_nanos(1),
            Duration::from_nanos(0),
        );
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(TimeAdjustError::InvalidMigrateDelta { .. })
        ));
    }

    struct Gutv {
        hrt: u64,
        bhrt: Hrtime,
        res: Duration,
    }
    const GUEST_UPTIME_TESTS_VALID: &'static [Gutv] = &[
        // boot_hrtime > 0
        // guest was booted on this host, or was migrated to a host with higher
        // uptime than itself
        Gutv { hrt: 1, bhrt: 0, res: Duration::from_nanos(1) },
        Gutv {
            hrt: 300_000_000_000,
            bhrt: 200_000_000_000,
            res: Duration::from_nanos(100_000_000_000),
        },
        Gutv {
            hrt: i64::MAX as u64,
            bhrt: i64::MAX - 1,
            res: Duration::from_nanos(1),
        },
        // src_hrt == boot_hrtime
        Gutv { hrt: 0, bhrt: 0, res: Duration::from_nanos(0) },
        Gutv {
            hrt: 300_000_000_000,
            bhrt: 300_000_000_000,
            res: Duration::from_nanos(0),
        },
        Gutv {
            hrt: i64::MAX as u64,
            bhrt: i64::MAX,
            res: Duration::from_nanos(0),
        },
        // src_hrt < boot_hrtime
        // guest came from a host with less uptime than itself
        Gutv { hrt: 1000, bhrt: -100, res: Duration::from_nanos(1100) },
        Gutv {
            hrt: i64::MAX as u64,
            bhrt: 0,
            res: Duration::from_nanos(i64::MAX as u64),
        },
        Gutv {
            hrt: 0,
            bhrt: i64::MIN + 1,
            res: Duration::from_nanos((-(i64::MIN + 1)) as u64),
        },
    ];
    struct Guti {
        hrt: u64,
        bhrt: Hrtime,
    }
    const GUEST_UPTIME_TESTS_INVALID: &'static [Guti] = &[
        // src_hrt - boot_hrtime underflows i64
        Guti { hrt: 0, bhrt: i64::MAX },
        // (src_hrt - boot_hrtime) overflows u64
        Guti { hrt: u64::MAX, bhrt: -1 },
    ];

    #[test]
    fn test_calc_guest_uptime() {
        // valid cases
        for i in 0..GUEST_UPTIME_TESTS_VALID.len() {
            let t = &GUEST_UPTIME_TESTS_VALID[i];

            let msg = format!(
                "src_hrtime={}, boot_hrtime={}, expected={:?}",
                t.hrt, t.bhrt, t.res
            );
            let res = calc_guest_uptime(t.hrt, t.bhrt);
            match res {
                Ok(v) => {
                    assert_eq!(v, t.res, "got incorrect value: {}", msg);
                }
                Err(e) => {
                    assert!(false, "got error {}: {}", e, msg);
                }
            }
        }

        // error cases
        for i in 0..GUEST_UPTIME_TESTS_INVALID.len() {
            let t = &GUEST_UPTIME_TESTS_INVALID[i];
            let msg = format!("src_hrtime={}, boot_hrtime={}", t.hrt, t.bhrt,);
            let res = calc_guest_uptime(t.hrt, t.bhrt);
            match res {
                Ok(v) => {
                    assert!(
                        false,
                        "expected error but got value {:?}: {}",
                        v, msg
                    );
                }
                Err(TimeAdjustError::GuestUptimeOverflow { .. }) => {
                    // test passes
                }
                Err(e) => {
                    assert!(false, "got incorrect error type {:?}: {}", e, msg);
                }
            }
        }
    }

    #[test]
    fn test_calc_boot_hrtime_delta() {
        // valid input
        let res = calc_boot_hrtime_delta(
            Duration::from_nanos(1),
            Duration::from_nanos(1),
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Duration::from_nanos(2));

        let res = calc_boot_hrtime_delta(
            Duration::from_secs(u64::MAX),
            Duration::from_nanos(NS_PER_SEC as u64 - 1),
        );
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Duration::new(u64::MAX, (NS_PER_SEC as u32) - 1)
        );

        // error case: uptime + migrate_delta overflows Duration
        let res = calc_boot_hrtime_delta(
            Duration::from_secs(u64::MAX),
            Duration::from_nanos(NS_PER_SEC as u64),
        );
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::TimeDeltaOverflow { .. })));
    }

    #[test]
    fn test_calc_boot_hrtime() {
        // valid input

        // positive boot_hrtime result
        // 4 days, 1 min, 500 ns
        let dst_hrtime = Duration::new(4 * 24 * 60 * 60 + 60, 500);
        // 3 days, 300 ns
        let total_delta = Duration::new(3 * 24 * 60 * 60, 300);
        // 1 day, 1 min, 200 ns
        let expect: Hrtime = (1 * 24 * 60 * 60 + 60) * NS_PER_SEC as i64 + 200;
        let res = calc_boot_hrtime(total_delta, dst_hrtime);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // negative boot_hrtime result
        // 3 days, 300 ns
        let dst_hrtime = Duration::new(3 * 24 * 60 * 60, 300);
        // 4 days, 1 min, 500 ns
        let total_delta = Duration::new(4 * 24 * 60 * 60 + 60, 500);
        // - (1 day, 1 min, 200 ns)
        let expect: Hrtime =
            -((1 * 24 * 60 * 60 + 60) * NS_PER_SEC as i64 + 200);
        let res = calc_boot_hrtime(total_delta, dst_hrtime);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // error cases

        // dst_hrtime - total_delta underflows i128
        let dst_hrtime = Duration::from_nanos(0);
        let total_delta = Duration::from_secs(u64::MAX);
        let res = calc_boot_hrtime(total_delta, dst_hrtime);
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::BootHrtimeOverflow { .. })));

        // dst_hrtime - total_delta overflows/underflows i64
        let dst_hrtime = Duration::from_nanos(u64::MAX);
        let total_delta = Duration::from_nanos(0);
        let res = calc_boot_hrtime(total_delta, dst_hrtime);
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::BootHrtimeOverflow { .. })));

        let dst_hrtime = Duration::from_nanos(0);
        let total_delta = Duration::from_nanos(i64::MAX as u64 + 2);
        let res = calc_boot_hrtime(total_delta, dst_hrtime);
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::BootHrtimeOverflow { .. })));
    }

    #[test]
    fn test_calc_tsc_delta() {
        // valid input

        // 1 GHz, 1 second
        let migrate_delta = Duration::from_nanos(NS_PER_SEC as u64);
        let guest_hz = 1_000_000_000;
        let expect = NS_PER_SEC as u64;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // 1 GHz, 20 seconds
        let migrate_delta = Duration::from_nanos(NS_PER_SEC as u64 * 20);
        let guest_hz = 1_000_000_000;
        let expect = NS_PER_SEC as u64 * 20;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // 2.5 GHz, 1 second
        let migrate_delta = Duration::from_nanos(NS_PER_SEC as u64);
        let guest_hz = 2_500_000_000;
        let expect = 2_500_000_000;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // 2.5 GHz, 20 seconds
        let migrate_delta = Duration::from_nanos(NS_PER_SEC as u64 * 20);
        let guest_hz = 2_500_000_000;
        let expect = 50_000_000_000;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expect);

        // error cases

        // delta * guest_hz overflows u128
        let migrate_delta = Duration::from_secs(u64::MAX);
        let guest_hz = u64::MAX;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::TscAdjustOverflow { .. })));

        // (delta * guest_hz) / NS_PER_SEC overflows u64
        let migrate_delta = Duration::from_secs(u64::MAX);
        let guest_hz = 1_000_000_000;
        let res = calc_tsc_delta(migrate_delta, guest_hz);
        assert!(res.is_err());
        assert!(matches!(res, Err(TimeAdjustError::TscAdjustOverflow { .. })));
    }

    #[test]
    fn test_calc_guest_tsc() {
        // valid input
        let res = calc_guest_tsc(1_000_000_000, 1_000_000_000);
        assert_eq!(res, 2_000_000_000);

        // valid input: tsc + adjust overflows u64
        let res = calc_guest_tsc(u64::MAX, 1);
        assert_eq!(res, 0);
    }
}
