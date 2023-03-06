use std::io::{Error, Result};

/// Real time clock, aka wall clock time (not monotonic)
pub(crate) const CLOCK_REALTIME: i32 = 0;

/// High resolution monotonic clock
/// CLOCK_HIGHRES is an alias for CLOCK_MONOTONIC
pub(crate) const CLOCK_HIGHRES: i32 = 4;

/// clock_gettime(3c)
#[cfg(target_os = "illumos")]
pub(crate) fn clock_gettime(
    clockid: libc::clockid_t,
) -> Result<libc::timespec> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };

    let res;
    unsafe {
        res = libc::clock_gettime(clockid, &mut ts);
    };

    if res == -1 {
        return Err(Error::last_os_error());
    }
    assert_eq!(res, 0);

    Ok(ts)
}

#[cfg(not(target_os = "illumos"))]
pub(crate) fn clock_gettime(
    _clockid: libc::clockid_t,
) -> Result<libc::timespec> {
    Err(Error::new(std::io::ErrorKind::Other, "illumos required"))
}
