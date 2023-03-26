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

#[derive(Debug, Copy, Clone)]
pub struct FreqRatio {
    pub int_size: u8,
    pub frac_size: u8,
    pub mult: u64,
}

/// 
pub fn calc_tsc_freqratio(guest_hz: u64, host_hz: u64, int_size: u8, frac_size: u8) -> Result<FreqRatio> {
    todo!()
}

pub fn scale_tsc(tsc: u64, fr: FreqRatio) -> Result<u64> {
    todo!()
}

pub fn highres_to_tsc(hrt: u64, freq_hz: u64) -> Result<u64> {
    todo!()
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
