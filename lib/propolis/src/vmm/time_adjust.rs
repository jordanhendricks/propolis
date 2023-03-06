//! Utility functions for adjusting guest timing data post-migration

use std::time::Duration;

use thiserror::Error;

use time;

const NS_PER_SEC: u128 = 1_000_000_000;

/// Convenience type for an hrtime_t
pub type Hrtime = i64;

/// "Snapshot" (read: not atomic) of the host's wall clock and high res clock
pub struct HostTime {
    pub hrtime: Duration,
    pub wall_clock: Duration,
}

/// Errors related to making timing adjustment calculations
#[derive(Clone, Debug, Error)]
pub enum TimeAdjustError {
    /// Error reading system clock
    #[error("could not read system wall clock: {0}")]
    RealTimeClock(String),

    /// Error reading high res clock
    #[error("could not read system monotonic clock: {0}")]
    HighResClock(String),

    /// Error calculating migration delta
    #[error("invalid migration delta: src={src_wc:?},dst={dst_wc:?}")]
    InvalidMigrateDelta { src_wc: Duration, dst_wc: Duration },

    /// Invalid calculated guest uptime
    #[error(
        "guest uptime cannot be represented: \
        src_hrtime={src_hrt:?}, boot_hrtime={boot_hrtime}"
    )]
    GuestUptimeOverflow {
        /// source host hrtime
        src_hrt: i128,

        /// input boot_hrtime
        boot_hrtime: i128,
    },

    /// Invalid total boot_hrtime delta
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

    /// Calculated boot_hrtime overflow
    #[error(
        "guest boot_hrtime cannot be represented:\
            desc=\"{desc}\", total_delta={total_delta:?},\
            boot_hrtime={boot_hrtime}, dst_hrtime={dst_hrtime:?}"
    )]
    BootHrtimeOverflow {
        /// error description
        desc: String,

        /// total delta to add to boot_hrtime
        total_delta: Duration,

        /// input boot_hrtime
        boot_hrtime: Hrtime,

        /// destination host hrtime
        dst_hrtime: Duration,
    },

    /// Guest TSC adjustment overflow
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

    /// Guest TSC overflow
    #[error("guest TSC overflow: old tsc = {tsc}, adjustment = {adjust}")]
    GuestTscOverflow {
        /// input guest TSC value
        tsc: u64,

        /// calculated TSC adjustment
        adjust: u64,
    },
}

/// Returns the current hrtime and wall clock time.
///
/// TODO: We may want to put a bound in here to make sure the two
/// values are close enough, and we may want that to be tunable. What's the
/// best tuning mechanism here? And what should the bound be?
/// We could also punt on this for now.
pub fn host_time_snapshot() -> Result<HostTime, TimeAdjustError> {
    let hrtime;
    let wall_clock;

    match time::get_highres_time() {
        Ok(hrt) => {
            hrtime = hrt;
        }
        Err(e) => {
            return Err(TimeAdjustError::HighResClock(e.to_string()));
        }
    };

    match time::get_real_time() {
        Ok(wc) => {
            wall_clock = wc;
        }
        Err(e) => {
            return Err(TimeAdjustError::RealTimeClock(e.to_string()));
        }
    }

    Ok(HostTime { hrtime, wall_clock })
}

/// Find the perceived wall clock time difference between when timing data
/// was read on the source versus the current time on the destination.
///
/// TODO(#357): Right now we throw up our hands if the delta is negative. On
/// the lab systems I'm testing on, we sometimes see a small negative delta
/// (< 2 ms). We might want to consider guard rails here (positive and
/// negative) as well.
pub fn calc_migrate_delta(
    src_wc: Duration,
    dst_wc: Duration,
) -> Result<Duration, TimeAdjustError> {
    match dst_wc.checked_sub(src_wc) {
        Some(d) => Ok(d),
        None => Err(TimeAdjustError::InvalidMigrateDelta { src_wc, dst_wc }),
    }
}

/// Calculate guest uptime for a particular point in time, using its
/// boot_hrtime and the hrtime of the host
///
/// uptime = hrtime - boot_hrtime
pub fn calc_guest_uptime(
    src_hrt: u64,
    boot_hrtime: Hrtime,
) -> Result<Duration, TimeAdjustError> {
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

/// Calculate the total delta we need to use for updating the boot_hrtime
///
/// boot_hrtime_delta = uptime + migrate_delta
pub fn calc_boot_hrtime_delta(
    uptime: Duration,
    migrate_delta: Duration,
) -> Result<Duration, TimeAdjustError> {
    match uptime.checked_add(migrate_delta) {
        Some(v) => Ok(v),
        None => {
            Err(TimeAdjustError::TimeDeltaOverflow { uptime, migrate_delta })
        }
    }
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
/// the target host has a smaller uptime than the guest. This is okay:
/// hrtime_t is signed, and the boot_hrtime is used by bhyve as a normalization
/// value for device timers.
///
pub fn calc_boot_hrtime(
    total_delta: Duration,
    boot_hrtime: Hrtime,
    dst_hrtime: Duration,
) -> Result<Hrtime, TimeAdjustError> {
    // Find the new boot_hrtime: cur_hrtime - total_delta
    if dst_hrtime.as_nanos() > i128::MAX as u128 {
        return Err(TimeAdjustError::BootHrtimeOverflow {
            desc: "dst_hrtime > 64 bits".to_string(),
            total_delta,
            boot_hrtime,
            dst_hrtime,
        });
    }

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
                boot_hrtime,
                dst_hrtime,
            });
        }
    }

    if (adjusted_bhrt < i64::MIN as i128) || (adjusted_bhrt > i64::MAX as i128)
    {
        return Err(TimeAdjustError::BootHrtimeOverflow {
            desc: "boot_hrtime to i64".to_string(),
            total_delta,
            boot_hrtime,
            dst_hrtime,
        });
    }

    Ok(adjusted_bhrt as Hrtime)
}

/// Calculate the adjustment needed for guest TSC
///
/// ticks = (migrate_delta ns * guest_hz hz) / `NS_PER_SEC`
pub fn calc_tsc_delta(
    migrate_delta: Duration,
    guest_hz: u64,
) -> Result<u64, TimeAdjustError> {
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

    if let Some(v) = upper.checked_div(NS_PER_SEC) {
        tsc_adjust = v;
    } else {
        return Err(TimeAdjustError::TscAdjustOverflow {
            desc: "(migrate_delta * guest_hz) / NS_PER_SEC".to_string(),
            migrate_delta,
            guest_hz,
            tsc_adjust,
        });
    }

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

/// Calculate the new guest TSC, given an adjustment
pub fn calc_guest_tsc(tsc: u64, adjust: u64) -> Result<u64, TimeAdjustError> {
    match tsc.checked_add(adjust) {
        Some(new_tsc) => Ok(new_tsc),
        None => Err(TimeAdjustError::GuestTscOverflow { tsc, adjust }),
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::vmm::time_adjust::calc_tsc_delta;

    // TODO: write more tests here
    #[test]
    fn test_calc_tsc_delta() {
        // basic tests
        assert!(matches!(
            calc_tsc_delta(Duration::from_nanos(1_000_000_000), 1_000_000_000),
            Ok(1_000_000_000)
        ));
    }
}
