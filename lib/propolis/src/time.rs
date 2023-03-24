use std::{
    io::{Error, ErrorKind, Result},
    time::Duration,
};

pub const CLOCK_REALTIME: i32 = 0;
// CLOCK_HIGHRES is defined as CLOCK_MONOTONIC
pub const CLOCK_HIGHRES: i32 = 4;

/// TODO: doc
pub fn get_highres_time() -> Result<u64> {
    match clock_gettime(CLOCK_HIGHRES) {
        // TODO: check cast here?
        Ok(ts) => Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
            .as_nanos() as u64),
        Err(e) => Err(e),
    }
}

/// TODO: doc
pub fn get_wallclock_time() -> Result<Duration> {
    match clock_gettime(CLOCK_REALTIME) {
        Ok(ts) => {
            // TODO cast here
            Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
        }
        Err(e) => Err(e),
    }
}

/// clock_gettime(3c)
#[cfg(target_os = "illumos")]
fn clock_gettime(clockid: libc::clockid_t) -> Result<libc::timespec> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };

    let res = unsafe {
        libc::clock_gettime(clockid, &mut ts);
    };

    match res {
        -1 => Err(Error::last_os_error()),
        Ok(ts) => ts,
    }
}

#[cfg(not(target_os = "illumos"))]
fn clock_gettime(clockid: libc::clockid_t) -> Result<libc::timespec> {
    Err(Error::new(ErrorKind::Other, "illumos required"))
}
