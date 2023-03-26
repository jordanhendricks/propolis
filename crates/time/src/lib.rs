use std::io::Result;
use std::time::Duration;

mod tsc_math;
mod sys;

/// Get the system high resolution time (monotonic time)
pub fn get_highres_time() -> Result<u64> {
    match sys::clock_gettime(sys::CLOCK_HIGHRES) {
        // TODO: check cast here?
        Ok(ts) => Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
            .as_nanos() as u64),
        Err(e) => Err(e),
    }
}

/// Get the system wall clock time (not monotonic)
pub fn get_wallclock_time() -> Result<Duration> {
    match sys::clock_gettime(sys::CLOCK_REALTIME) {
        Ok(ts) => {
            // TODO cast here
            Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
        }
        Err(e) => Err(e),
    }
}
