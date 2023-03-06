use std::io::Result;
use std::time::Duration;

mod sys;

// TODO: this is a (terribly generically named) crate for now, but it could be
// moved (perhaps into lib/propolis)

/// Get the system high resolution time (monotonic time)
pub fn get_highres_time() -> Result<Duration> {
    match sys::clock_gettime(sys::CLOCK_HIGHRES) {
        Ok(ts) => Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)),
        Err(e) => Err(e),
    }
}

/// Get the system wall clock time (not monotonic)
pub fn get_real_time() -> Result<Duration> {
    match sys::clock_gettime(sys::CLOCK_REALTIME) {
        Ok(ts) => Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)),
        Err(e) => Err(e),
    }
}
