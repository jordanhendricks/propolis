use erased_serde::Deserializer;
use thiserror::Error;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use slog::info;

use super::VmmHdl;

const NS_PER_SEC: u128 = 1_000_000_000;

/// Convenience type for hrtime_t
pub type Hrtime = i64;

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
    deserializer: &mut dyn Deserializer,
    log: &slog::Logger,
) -> std::io::Result<()> {
    // TODO: MigrateStateError?
    let mut imported: VmTimeData = erased_serde::deserialize(deserializer).unwrap();
    let raw = bhyve_api::vdi_time_info_v1::from(imported);
    crate::vmm::data::write(hdl, -1, bhyve_api::VDC_VMM_TIME, 1, raw)?;

    Ok(())
}

pub fn export_time_data(hdl: &VmmHdl) -> std::io::Result<VmTimeData> {
    let time_info: bhyve_api::vdi_time_info_v1 =
        crate::vmm::data::read(hdl, -1, bhyve_api::VDC_VMM_TIME, 1)?;

    Ok(VmTimeData::from(time_info))
}

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

    // Get the VM uptime.
    let vm_uptime = calc_guest_uptime(src.hrtime, src.boot_hrtime)?;

    // Compute the delta for how long migration took, using wall clock time.
    let migrate_delta = calc_migrate_delta(src.wall_clock(), dst_wc)?;

    // Find the total time delta we need to adjust for `boot_hrtime`.
    let boot_hrtime_delta = calc_boot_hrtime_delta(vm_uptime, migrate_delta)?;

    // Get the new boot_hrtime.
    let adj_boot_hrtime = calc_boot_hrtime(boot_hrtime_delta, Duration::from_nanos(dst_hrt as u64))?;

    // Get the guest TSC adjustment.
    let tsc_delta = calc_tsc_delta(migrate_delta, src.guest_freq)?;
    let adj_guest_tsc = calc_guest_tsc(src.guest_tsc, tsc_delta);

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
        adj_guest_tsc,
        src.boot_hrtime,
        dst_hrt,
        boot_hrtime_delta.as_nanos(),
        adj_boot_hrtime,
        dst_hrt,
        dst_wc,
    );

    // Update the time data with the adjustments and current host times.
    let res = VmTimeData {
        guest_freq: src.guest_freq,
        guest_tsc: adj_guest_tsc,
        hrtime: dst_hrt as u64,
        hres_sec: dst_wc.as_secs(),
        hres_ns: dst_wc.subsec_nanos() as u64,
        boot_hrtime: adj_boot_hrtime,
    };

    probes::adj_time_end!(|| (
        res.guest_freq,
        res.guest_tsc,
        res.boot_hrtime,
        vm_uptime.as_nanos() as u64,
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
        src_hrt: i128,

        /// input guest boot_hrtime
        boot_hrtime: i128,
    },

    /// Invalid total delta for boot_hrtime calculations
    #[error(
        "could not calculate time delta:\
            guest uptime {uptime:?}, migrate_delta={migrate_delta:?}"
    )]
    TimeDeltaOverflow {
        /// guest uptime
        uptime: Duration,

        /// migration time delta
        migrate_delta: Duration,
    },

    /// Invalid calculated boot_hrtime
    #[error(
        "guest boot_hrtime cannot be represented:\
            desc=\"{desc}\", total_delta={total_delta:?},\
            dst_hrtime={dst_hrtime:?}"
    )]
    BootHrtimeOverflow {
        /// error description
        desc: String,

        /// calculated total delta (uptime + migration delta)
        total_delta: Duration,

        /// destination host hrtime
        dst_hrtime: Duration,
    },

    /// Invalid guest TSC adjustment
    #[error(
        "could not calculate TSC adjustment:\
            desc=\"{desc:?}\", migrate_delta={migrate_delta:?},
            guest_hz={guest_hz}, tsc_adjust={tsc_adjust}"
    )]
    TscAdjustOverflow {
        /// error description
        desc: String,

        /// migration time delta
        migrate_delta: Duration,

        /// guest TSC frequency (hz)
        guest_hz: u64,

        /// calculated TSC adjustment
        tsc_adjust: u128,
    },
}

/// Find the perceived wall clock time difference between when timing data
/// was read on the source versus the current time on the destination.
// TODO(#357): Right now we throw up our hands if the delta is negative.
// On extremely short intervals between timing data read and write, I
// sometimes saw a negative delta (~2 ms) on the lab systems I was testing on
// before we switched them to use a local ntp server. We may want to consider
// guard rails here (both positive and negative).
fn calc_migrate_delta(
    src_wc: Duration,
    dst_wc: Duration,
) -> Result<Duration, TimeAdjustError> {
    match dst_wc.checked_sub(src_wc) {
        Some(d) => Ok(d),
        None => Err(TimeAdjustError::InvalidMigrateDelta { src_wc, dst_wc }),
    }
}

/// Calculate guest uptime for a particular point in time, using its
/// boot_hrtime and the hrtime of the host.
///
/// uptime = hrtime - boot_hrtime
fn calc_guest_uptime(
    src_hrt: u64,
    boot_hrtime: Hrtime,
) -> Result<Duration, TimeAdjustError> {
    // convert input to 128-bits so we can check for overflow
    let src_hrt_ns: i128 = src_hrt as i128;
    let boot_hrt_ns: i128 = boot_hrtime as i128;
    let uptime: u128;

    match src_hrt_ns.checked_sub(boot_hrt_ns) {
        Some(v) if v >= 0 => {
            uptime = v as u128;
        }
        _ => {
            return Err(TimeAdjustError::GuestUptimeOverflow {
                src_hrt: src_hrt_ns,
                boot_hrtime: boot_hrt_ns,
            });
        }
    }

    // Note: TryFrom<u128> for u64 is currently unstable
    if uptime > u64::MAX as u128 {
        return Err(TimeAdjustError::GuestUptimeOverflow {
            src_hrt: src_hrt_ns,
            boot_hrtime: boot_hrt_ns,
        });
    }

    Ok(Duration::from_nanos(uptime as u64))
}

/// Calculate the total delta we need to use for updating the boot_hrtime:
///
/// boot_hrtime_delta = uptime + migrate_delta
fn calc_boot_hrtime_delta(
    uptime: Duration,
    migrate_delta: Duration,
) -> Result<Duration, TimeAdjustError> {
    uptime.checked_add(migrate_delta).ok_or_else(|| {
        TimeAdjustError::TimeDeltaOverflow { uptime, migrate_delta }
    })
}

/// Calculate the new boot_hrtime for the guest.
///
/// The boot_hrtime is the hrtime of when a VM booted on the current host. In
/// the case of live migration, this VM did not boot on this host, so we need
/// to adjust to the boot_hrtime to be the "effective boot_hrtime": that is,
/// what the hrtime of this host would have been when this VM booted.
///
/// To do so, we need several pieces of information:
/// - the current hrtime of this host
/// - the uptime of the VM
/// - the migration time delta
///
/// And we can fix up the boot_hrtime as follows:
///     boot_hrtime = cur_hrtime - (vm_uptime_ns + wallclock_delta)
///
/// The `vm_uptime_ns + wallclock_delta` term is `total_delta` here.
///
/// Note: It is possible for the boot_hrtime to be negative, in the case that
/// the target host has a smaller uptime than the guest. This is okay: hrtime_t
/// is signed, and the boot_hrtime is used by bhyve as a normalization value for
/// device timers.
///
fn calc_boot_hrtime(
    total_delta: Duration,
    dst_hrtime: Duration,
) -> Result<Hrtime, TimeAdjustError> {
    let dst_hrt_ns: i128 = dst_hrtime.as_nanos() as i128;
    let adjusted_bhrt: i128;
    match dst_hrt_ns.checked_sub_unsigned(total_delta.as_nanos()) {
        Some(v) => {
            adjusted_bhrt = v;
        }
        None => {
            return Err(TimeAdjustError::BootHrtimeOverflow {
                desc: "dst_hrtime - total_delta".to_string(),
                total_delta,
                dst_hrtime,
            });
        }
    }

    if (adjusted_bhrt < i64::MIN as i128) || (adjusted_bhrt > i64::MAX as i128)
    {
        return Err(TimeAdjustError::BootHrtimeOverflow {
            desc: "boot_hrtime to i64".to_string(),
            total_delta,
            dst_hrtime,
        });
    }

    Ok(adjusted_bhrt as Hrtime)
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

    let upper: u128;
    if let Some(v) = delta_ns.checked_mul(guest_hz as u128) {
        upper = v;
    } else {
        return Err(TimeAdjustError::TscAdjustOverflow {
            desc: "migrate_delta * guest_hz".to_string(),
            migrate_delta,
            guest_hz,
            tsc_adjust,
        });
    }

    tsc_adjust = upper / NS_PER_SEC;
    if tsc_adjust > u64::MAX as u128 {
        return Err(TimeAdjustError::TscAdjustOverflow {
            desc: "tsc_adjust > 64-bits".to_string(),
            migrate_delta,
            guest_hz,
            tsc_adjust,
        });
    }

    Ok(tsc_adjust as u64)
}

/// Calculate the new guest TSC, given an adjustment.
fn calc_guest_tsc(tsc: u64, adjust: u64) -> u64 {
    tsc.wrapping_add(adjust)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::vmm::time_adjust::{
        calc_boot_hrtime_delta, calc_guest_uptime, calc_tsc_delta, NS_PER_SEC,
    };

    use super::{
        calc_boot_hrtime, calc_guest_tsc, calc_migrate_delta, Hrtime,
        TimeAdjustError,
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
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 2_000_000_000);

        // valid input: tsc + adjust overflows u64
        let res = calc_guest_tsc(u64::MAX, 1);
        assert!(res.is_err());
        // TODO
        assert!(matches!(res, Err(TimeAdjustError::GuestTscOverflow { .. })));
    }
}
