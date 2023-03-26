//! Module responsible for communicating with the kernel's VMM.
//!
//! Responsible for both issuing commands to the bhyve
//! kernel controller to create and destroy VMs.
//!
//! Additionally, contains a wrapper struct ([`VmmHdl`])
//! for encapsulating commands to the underlying kernel
//! object which represents a single VM.

use erased_serde::{Deserializer, Serialize};
use slog::{info, Logger};

use std::fs::File;
use std::io::{Error, ErrorKind, Result, Write};
use std::os::raw::c_void;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::common::PAGE_SIZE;
use crate::migrate::MigrateStateError;
use time::{get_highres_time, get_wallclock_time};
use crate::vmm::mem::Prot;

use self::migrate::{BhyveVmV1, TimingInfoV1, TscFreqInfoV1};

#[derive(Default, Copy, Clone)]
/// Configurable options for VMM instance creation
///
/// # Options:
/// - `force`: If a VM with the name `name` already exists, attempt
///   to destroy the VM before creating it.
/// - `use_reservoir`: Allocate guest memory (only) from the VMM reservoir.  If
/// this is enabled, and memory in excess of what is available from the
/// reservoir is requested, creation of that guest memory resource will fail.
pub struct CreateOpts {
    pub force: bool,
    pub use_reservoir: bool,
    pub track_dirty: bool,
}

/// Creates a new virtual machine with the provided `name`.
///
/// Operates on the bhyve controller object at `/dev/vmmctl`,
/// which acts as an interface to the kernel module, and opens
/// an object at `/dev/vmm/{name}`.
///
/// # Arguments
/// - `name`: The name of the VM to create.
/// - `opts`: Creation options (detailed in `CreateOpts`)
pub(crate) fn create_vm(
    name: &str,
    log: Logger,
    opts: CreateOpts,
) -> Result<VmmHdl> {
    let ctl = bhyve_api::VmmCtlFd::open()?;

    let mut req = bhyve_api::vm_create_req::new(name);
    if opts.use_reservoir {
        req.flags |= bhyve_api::VCF_RESERVOIR_MEM;
    }
    if opts.track_dirty {
        req.flags |= bhyve_api::VCF_TRACK_DIRTY;
    }
    let res = unsafe { ctl.ioctl(bhyve_api::VMM_CREATE_VM, &mut req) };
    if let Err(e) = res {
        if e.kind() != ErrorKind::AlreadyExists || !opts.force {
            return Err(e);
        }

        // try to nuke(!) the existing vm
        let mut dreq = bhyve_api::vm_destroy_req::new(name);
        let _ = unsafe { ctl.ioctl(bhyve_api::VMM_DESTROY_VM, &mut dreq) }
            .or_else(|e| match e.kind() {
                ErrorKind::NotFound => Ok(0),
                _ => Err(e),
            })?;

        // now attempt to create in its presumed absence
        let _ = unsafe { ctl.ioctl(bhyve_api::VMM_CREATE_VM, &mut req) }?;
    }

    // Safety: Files opened within VMM_PATH_PREFIX are VMMs, which may not be
    // truncated.
    let inner = bhyve_api::VmmFd::open(name)?;

    Ok(VmmHdl {
        inner,
        destroyed: AtomicBool::new(false),
        name: name.to_string(),
        log,
        #[cfg(test)]
        is_test_hdl: false,
    })
}

/// Destroys the virtual machine matching the provided `name`.
fn destroy_vm_impl(name: &str) -> Result<()> {
    let ctl = bhyve_api::VmmCtlFd::open()?;
    let mut dreq = bhyve_api::vm_destroy_req::new(name);
    let _ = unsafe { ctl.ioctl(bhyve_api::VMM_DESTROY_VM, &mut dreq) }
        .or_else(|e| match e.kind() {
            ErrorKind::NotFound => Ok(0),
            _ => Err(e),
        })?;
    Ok(())
}

/// A wrapper around a file which must uphold the guarantee that the underlying
/// structure may not be truncated.
pub struct VmmFile(File);

impl VmmFile {
    /// Constructs a new `VmmFile`.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the provided file cannot be truncated.
    pub unsafe fn new(f: File) -> Self {
        VmmFile(f)
    }

    /// Accesses the VMM as a raw fd.
    pub fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// A handle to an existing virtual machine monitor.
pub struct VmmHdl {
    pub(super) inner: bhyve_api::VmmFd,
    destroyed: AtomicBool,
    name: String,
    log: Logger,

    #[cfg(test)]
    /// Track if this VmmHdl belongs to a wholly fictitious Instance/Machine.
    is_test_hdl: bool,
}
impl VmmHdl {
    /// Accesses the raw file descriptor behind the VMM.
    pub fn fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
    /// Sends an ioctl to the underlying VMM.
    pub unsafe fn ioctl<T>(&self, cmd: i32, data: *mut T) -> Result<()> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(Error::new(ErrorKind::NotFound, "instance destroyed"));
        }

        #[cfg(test)]
        if self.is_test_hdl {
            // Lie about all ioctl results, since there is no real vmm resource
            // underlying this handle.
            return Ok(());
        }

        self.inner.ioctl(cmd, data)?;
        Ok(())
    }

    /// Sends an ioctl (with usize param) to the underlying VMM.
    pub fn ioctl_usize(&self, cmd: i32, data: usize) -> Result<()> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(Error::new(ErrorKind::NotFound, "instance destroyed"));
        }

        #[cfg(test)]
        if self.is_test_hdl {
            // Lie about all ioctl results, since there is no real vmm resource
            // underlying this handle.
            return Ok(());
        }

        self.inner.ioctl_usize(cmd, data)?;
        Ok(())
    }

    /// Allocate a memory segment within the VM.
    ///
    /// # Arguments
    /// - `segid`: The segment ID of the requested memory.
    /// - `size`: The size of the memory region, in bytes.
    /// - `segname`: The (optional) name of the memory segment.
    pub fn create_memseg(
        &self,
        segid: i32,
        size: usize,
        segname: Option<&str>,
    ) -> Result<()> {
        let mut seg = bhyve_api::vm_memseg {
            segid,
            len: size,
            name: [0u8; bhyve_api::VM_MAX_SEG_NAMELEN],
        };
        if let Some(name) = segname {
            let name_raw = name.as_bytes();

            assert!(name_raw.len() < bhyve_api::VM_MAX_SEG_NAMELEN);
            (&mut seg.name[..]).write_all(name_raw)?;
        }
        unsafe { self.ioctl(bhyve_api::VM_ALLOC_MEMSEG, &mut seg) }
    }

    /// Maps a memory segment within the guest address space.
    ///
    /// # Arguments
    /// - `segid`: The segment ID to be mapped.
    /// - `gpa`: The "Guest Physical Address" to be mapped.
    /// - `len`: The length of the mapping, in bytes. Must be page aligned.
    /// - `segoff`: Offset within the `gpa` where the mapping should occur.
    /// Must be page aligned.
    /// - `prot`: Memory protections to apply to the guest mapping.
    pub fn map_memseg(
        &self,
        segid: i32,
        gpa: usize,
        len: usize,
        segoff: usize,
        prot: Prot,
    ) -> Result<()> {
        assert!(segoff <= i64::MAX as usize);

        let mut map = bhyve_api::vm_memmap {
            gpa: gpa as u64,
            segid,
            segoff: segoff as i64,
            len,
            prot: prot.bits() as i32,
            flags: 0,
        };
        unsafe { self.ioctl(bhyve_api::VM_MMAP_MEMSEG, &mut map) }
    }

    /// Looks up a segment by `segid` and returns the offset
    /// within the guest's address virtual address space where
    /// it is mapped.
    pub fn devmem_offset(&self, segid: i32) -> Result<usize> {
        let mut devoff = bhyve_api::vm_devmem_offset { segid, offset: 0 };
        unsafe {
            self.ioctl(bhyve_api::VM_DEVMEM_GETOFFSET, &mut devoff)?;
        }

        assert!(devoff.offset >= 0);
        Ok(devoff.offset as usize)
    }

    /// Tracks dirty pages in the guest's physical address space.
    ///
    /// # Arguments:
    /// - `start_gpa`: The start of the guest physical address range to track.
    /// Must be page aligned.
    /// - `bitmap`: A mutable bitmap of dirty pages, one bit per guest PFN
    /// relative to `start_gpa`.
    pub fn track_dirty_pages(
        &self,
        start_gpa: u64,
        bitmap: &mut [u8],
    ) -> Result<()> {
        let mut tracker = bhyve_api::vmm_dirty_tracker {
            vdt_start_gpa: start_gpa,
            vdt_len: bitmap.len() * 8 * PAGE_SIZE,
            vdt_pfns: bitmap.as_mut_ptr() as *mut c_void,
        };
        unsafe { self.ioctl(bhyve_api::VM_TRACK_DIRTY_PAGES, &mut tracker) }
    }

    /// Issues a request to update the virtual RTC time.
    pub fn rtc_settime(&self, unix_time: u64) -> Result<()> {
        let mut time: u64 = unix_time;
        unsafe { self.ioctl(bhyve_api::VM_RTC_SETTIME, &mut time) }
    }
    /// Writes to the registers within the RTC device.
    pub fn rtc_write(&self, offset: u8, value: u8) -> Result<()> {
        let mut data = bhyve_api::vm_rtc_data { offset: offset as i32, value };
        unsafe { self.ioctl(bhyve_api::VM_RTC_WRITE, &mut data) }
    }
    /// Reads from the registers within the RTC device.
    pub fn rtc_read(&self, offset: u8) -> Result<u8> {
        let mut data =
            bhyve_api::vm_rtc_data { offset: offset as i32, value: 0 };
        unsafe {
            self.ioctl(bhyve_api::VM_RTC_READ, &mut data)?;
        }
        Ok(data.value)
    }

    /// Asserts the requested IRQ for the virtual interrupt controller.
    ///
    /// `pic_irq` sends a request to the legacy 8259 PIC.
    /// `ioapic_irq` (if supplied) sends a request to the IOAPIC.
    pub fn isa_assert_irq(
        &self,
        pic_irq: u8,
        ioapic_irq: Option<u8>,
    ) -> Result<()> {
        let mut data = bhyve_api::vm_isa_irq {
            atpic_irq: pic_irq as i32,
            ioapic_irq: ioapic_irq.map(|x| x as i32).unwrap_or(-1),
        };
        unsafe { self.ioctl(bhyve_api::VM_ISA_ASSERT_IRQ, &mut data) }
    }
    /// Deasserts the requested IRQ.
    pub fn isa_deassert_irq(
        &self,
        pic_irq: u8,
        ioapic_irq: Option<u8>,
    ) -> Result<()> {
        let mut data = bhyve_api::vm_isa_irq {
            atpic_irq: pic_irq as i32,
            ioapic_irq: ioapic_irq.map(|x| x as i32).unwrap_or(-1),
        };
        unsafe { self.ioctl(bhyve_api::VM_ISA_DEASSERT_IRQ, &mut data) }
    }
    /// Pulses the requested IRQ, turning it on then off.
    pub fn isa_pulse_irq(
        &self,
        pic_irq: u8,
        ioapic_irq: Option<u8>,
    ) -> Result<()> {
        let mut data = bhyve_api::vm_isa_irq {
            atpic_irq: pic_irq as i32,
            ioapic_irq: ioapic_irq.map(|x| x as i32).unwrap_or(-1),
        };
        unsafe { self.ioctl(bhyve_api::VM_ISA_PULSE_IRQ, &mut data) }
    }
    #[allow(unused)]
    pub fn isa_set_trigger_mode(
        &self,
        vec: u8,
        level_mode: bool,
    ) -> Result<()> {
        let mut data = bhyve_api::vm_isa_irq_trigger {
            atpic_irq: vec as i32,
            trigger: if level_mode { 1 } else { 0 },
        };
        unsafe { self.ioctl(bhyve_api::VM_ISA_SET_IRQ_TRIGGER, &mut data) }
    }

    #[allow(unused)]
    pub fn ioapic_assert_irq(&self, irq: u8) -> Result<()> {
        let mut data = bhyve_api::vm_ioapic_irq { irq: irq as i32 };
        unsafe { self.ioctl(bhyve_api::VM_IOAPIC_ASSERT_IRQ, &mut data) }
    }
    #[allow(unused)]
    pub fn ioapic_deassert_irq(&self, irq: u8) -> Result<()> {
        let mut data = bhyve_api::vm_ioapic_irq { irq: irq as i32 };
        unsafe { self.ioctl(bhyve_api::VM_IOAPIC_DEASSERT_IRQ, &mut data) }
    }
    #[allow(unused)]
    pub fn ioapic_pulse_irq(&self, irq: u8) -> Result<()> {
        let mut data = bhyve_api::vm_ioapic_irq { irq: irq as i32 };
        unsafe { self.ioctl(bhyve_api::VM_IOAPIC_PULSE_IRQ, &mut data) }
    }
    #[allow(unused)]
    pub fn ioapic_pin_count(&self) -> Result<u8> {
        let mut data = 0u32;
        unsafe {
            self.ioctl(bhyve_api::VM_IOAPIC_PINCOUNT, &mut data)?;
        }
        Ok(data as u8)
    }

    pub fn lapic_msi(&self, addr: u64, msg: u64) -> Result<()> {
        let mut data = bhyve_api::vm_lapic_msi { msg, addr };
        unsafe { self.ioctl(bhyve_api::VM_LAPIC_MSI, &mut data) }
    }

    pub fn pmtmr_locate(&self, port: u16) -> Result<()> {
        unsafe { self.ioctl(bhyve_api::VM_PMTMR_LOCATE, port as *mut usize) }
    }

    pub fn suspend(&self, how: bhyve_api::vm_suspend_how) -> Result<()> {
        let mut data = bhyve_api::vm_suspend { how: how as u32 };
        unsafe { self.ioctl(bhyve_api::VM_SUSPEND, &mut data) }
    }

    pub fn reinit(&self, force_suspend: bool) -> Result<()> {
        let mut data = bhyve_api::vm_reinit { flags: 0 };
        if force_suspend {
            data.flags |= bhyve_api::VM_REINIT_F_FORCE_SUSPEND;
        }
        unsafe { self.ioctl(bhyve_api::VM_REINIT, &mut data) }
    }

    /// Pause device emulation logic for the instance (such as timers, etc).
    /// This allows a consistent snapshot to be taken or loaded.
    pub fn pause(&self) -> Result<()> {
        self.ioctl_usize(bhyve_api::VM_PAUSE, 0)
    }

    /// Resume device emulation logic from a prior [VmmHdl::pause] call.
    pub fn resume(&self) -> Result<()> {
        self.ioctl_usize(bhyve_api::VM_RESUME, 0)
    }

    /// Destroys the VMM.
    // TODO: Should this take "mut self", to consume the object?
    pub fn destroy(&self) -> Result<()> {
        if self.destroyed.swap(true, Ordering::SeqCst) {
            return Err(Error::new(ErrorKind::NotFound, "already destroyed"));
        }

        // Attempt destruction via the handle (rather than going through vmmctl)
        // This is done through the [ioctl_usize] helper rather than
        // [Self::ioctl_usize], since the latter rejects attempted operations
        // after `destroyed` is set.
        if let Ok(_) = self.inner.ioctl_usize(bhyve_api::VM_DESTROY_SELF, 0) {
            return Ok(());
        }

        // If that failed (which may occur on older platforms without
        // self-destruction), then fall back to performing the destroy through
        // the vmmctl device.
        destroy_vm_impl(&self.name)
    }

    /// Export the global VMM state.
    pub fn export(
        &self,
    ) -> std::result::Result<Box<dyn Serialize>, MigrateStateError> {
        Ok(Box::new(BhyveVmV1::read(self)?))
    }

    /// Restore previously exported global VMM state.
    pub fn import(
        &self,
        deserializer: &mut dyn Deserializer,
    ) -> std::result::Result<(), MigrateStateError> {
        let mut imported: BhyveVmV1 =
            erased_serde::deserialize(deserializer)?;

        // Get the host TSC frequency
        let tsc_freq_info = BhyveVmV1::read_tsc_freq_info(self)?;
        imported.tsc_freq_info = tsc_freq_info;

        // Update guest timing-related data to adjust for migration time and
        // movement across hosts before sending it to the VMM.
        self.adjust_timing_data(&mut imported.timing_info, &imported.tsc_freq_info)?;

        imported.write(self)?;
        Ok(())
    }

    // Take a snapshot of the hrtime and the wall clock time of this host.
    fn host_time_snapshot(
    ) -> std::result::Result<(u64, Duration), MigrateStateError> {
        let hrtime;
        let real_time;

        match get_highres_time() {
            Ok(hrt) => {
                hrtime = hrt;
            }
            Err(e) => {
                return Err(MigrateStateError::ImportFailed(format!(
                    "could not get high res time: {:?}",
                    e
                )))
            }
        }
        match get_wallclock_time() {
            Ok(rt) => {
                real_time = rt;
            }
            Err(e) => {
                return Err(MigrateStateError::ImportFailed(format!(
                    "could not get wall clock time: {:?}",
                    e
                )))
            }
        }

        Ok((hrtime, real_time))
    }

    // TODO
    fn compute_migration_delta(
        src_wallclock: Duration,
        dest_wallclock: Duration,
    ) -> std::result::Result<u64, MigrateStateError> {
        match Duration::checked_sub(dest_wallclock, src_wallclock) {
            Some(d) => {
                let ns = d.as_nanos();
                // TODO: limit on the delta we support
                // TryFrom<128> to u64 is unstable

                Ok(ns as u64)
            },
            None => {
                Err(MigrateStateError::ImportFailed(format!(
                    "perceived wall clock delta found negative: source read time: {:?}, target write time: {:?}",
                    src_wallclock,
                    dest_wallclock,
                )))
            }
        }
    }

    // TODO: comment about negative
    // TODO: handle overflow?
    fn compute_vm_uptime(src_hrtime: u64, boot_hrtime: i64) -> u64 {
        src_hrtime - boot_hrtime as u64
    }

    // Compute new VM boot_hrtime
    //
    // The boot_hrtime is the hrtime of when a VM booted on the current host. In
    // the case of live migrations, this VM did not boot on this host, so we
    // need to adjust to the boot_hrtime to be the "effective boot_hrtime" --
    // that is, what the hrtime of this host would've been when this VM booted.
    //
    // To do so, we need several pieces of information:
    // - the current hrtime of this host
    // - the uptime of the VM
    // - the migration time delta
    //
    // And we can fix up the boot_hrtime as follows:
    //  boot_hrtime = cur_hrtime - (vm_uptime_ns + wallclock_delta)
    // 
    // A couple additional things to note:
    // - It is possible for the boot_hrtime to be negative, in the case that the
    // target host has a smaller uptime than the guest. This is okay: hrtime_t
    // is signed, and the boot_hrtime is used by bhyve as a normalization value
    // for device timers.
    // - This calculation still won't quite capture the entire time difference
    // -- we are only fixing up this value for this specific point in time. The
    // kernel side of the timing data write will make additional adjustments to
    // account for the small delta between our timing adjustments and the actual
    // time of write.
    //
    fn compute_boot_hrtime(
        vm_uptime_ns: u64,
        wallclock_delta_ns: u64,
        boot_hrtime: i64,
        cur_hrtime: i64,
    ) -> std::result::Result<i64, MigrateStateError> {

        // Find total time difference:
        //      migration delta + VM uptime
        //
        // And convert it to ns
        let boot_hrt_adjust;
        match vm_uptime_ns.checked_add(wallclock_delta_ns) {
            Some(v) => {
                boot_hrt_adjust = v;
            }
            None => {
                return Err(MigrateStateError::ImportFailed(format!(
                    "boot_hrtime adjustment could not be represented: VM uptime = {} ns, migration delta = {}, boot_hrtime = {}",
                    vm_uptime_ns,
                    wallclock_delta_ns,
                    boot_hrtime,
                )));
            }
        }

        // TODO: handle cast
        // Find the new boot_hrtime:
        //      cur_hrtime - adjustment
        let bhrt_res = cur_hrtime.checked_sub(boot_hrt_adjust as i64);
        match bhrt_res {
            Some(v) => {
                Ok(v)
            },
            None => {
                Err(MigrateStateError::ImportFailed(format!(
                    "boot_hrtime adjustment could not be applied (underflow): VM uptime = {} ns, migration delta = {:?}, boot_hrtime = {}",
                    vm_uptime_ns,
                    wallclock_delta_ns,
                    boot_hrtime,
                )))
            }
        }
    }

    fn adjust_timing_data(
        &self,
        timing_data: &mut TimingInfoV1,
        tsc_freq_data: &TscFreqInfoV1,
    ) -> std::result::Result<(), MigrateStateError> {
        // Take a snapshot of time on this host.
        let (host_hrt, host_hrest) = Self::host_time_snapshot()?;

        // Get the VM uptime.
        let vm_uptime_ns = Self::compute_vm_uptime(
            timing_data.hrtime,
            timing_data.boot_hrtime,
        );

        // Compute the delta for how long the migration took, using wall clock time.
        let migrate_delta_ns =
            Self::compute_migration_delta(timing_data.hrestime, host_hrest)?;

        info!(self.log, "Importing VM with uptime {} ns, migration time = {} ns", vm_uptime_ns, migrate_delta_ns);

        // Adjust the boot_hrtime.
        timing_data.boot_hrtime = Self::compute_boot_hrtime(
            vm_uptime_ns,
            migrate_delta_ns,
            timing_data.boot_hrtime,
            host_hrt as i64,
        )?;

        // Next steps:
        // - finish this up
        // - add scaling needed function for freqratio?
        // Adjust the guest TSC.
        let ratio = time::calc_tsc_freqratio(tsc_freq_data.guest_freq, tsc_freq_data.host_freq, tsc_freq_data.int_size, tsc_freq_data.frac_size)?;

        let guest_ticks = time::highres_to_tsc(migrate_delta_ns, tsc_freq_data.guest_freq)?;

        info!(
            self.log,
            "Adjusting guest timing data: vm_uptime={:?}, delta={:?}",
            vm_uptime_ns,
            migration_delta
        );

        todo!()
    }

    /// Set whether instance should auto-destruct when closed
    pub fn set_autodestruct(&self, enable_autodestruct: bool) -> Result<()> {
        self.ioctl_usize(
            bhyve_api::VM_SET_AUTODESTRUCT,
            enable_autodestruct as usize,
        )
    }
}

#[cfg(test)]
impl VmmHdl {
    /// Build a VmmHdl instance suitable for unit tests, but nothing else, since
    /// it will not be backed by any real vmm reousrces.
    pub(crate) fn new_test(mem_size: usize) -> Result<Self> {
        use tempfile::tempfile;
        let fp = tempfile()?;
        fp.set_len(mem_size as u64).unwrap();
        let inner = unsafe { bhyve_api::VmmFd::new_raw(fp) };
        Ok(Self {
            inner,
            destroyed: AtomicBool::new(false),
            name: "TEST-ONLY VMM INSTANCE".to_string(),
            is_test_hdl: true,
        })
    }
}

pub fn query_reservoir() -> Result<bhyve_api::vmm_resv_query> {
    let ctl = bhyve_api::VmmCtlFd::open()?;
    let mut data = bhyve_api::vmm_resv_query::default();
    let _ = unsafe { ctl.ioctl(bhyve_api::VMM_RESV_QUERY, &mut data) }?;
    Ok(data)
}

pub mod migrate {
    use std::{io, time::Duration};

    use bhyve_api::{vdi_field_entry_v1, vdi_timing_info_v1, vdi_tsc_freq_v1};
    use serde::{Deserialize, Serialize};

    use crate::vmm;

    use super::VmmHdl;

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    pub struct BhyveVmV1 {
        pub arch_entries: Vec<ArchEntryV1>,
        pub timing_info: TimingInfoV1,
        pub tsc_freq_info: TscFreqInfoV1,
    }

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
    pub struct ArchEntryV1 {
        pub ident: u32,
        pub value: u64,
    }

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
    pub struct TimingInfoV1 {
        // guest TSC
        pub guest_tsc: u64,

        // monotonic host clock (ns)
        pub hrtime: u64,

        // wall clock host clock
        pub hrestime: Duration,

        // guest boot_hrtime (can be negative)
        pub boot_hrtime: i64,
    }

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
    pub struct TscFreqInfoV1 {
        // guest TSC frequency (hz)
        pub guest_freq: u64,

        // host TSC frequency (hz)
        pub host_freq: u64,

        // Multiplier format
        pub int_size: u8,
        pub frac_size: u8,
    }

    impl From<vdi_field_entry_v1> for ArchEntryV1 {
        fn from(raw: vdi_field_entry_v1) -> Self {
            Self { ident: raw.vfe_ident, value: raw.vfe_value }
        }
    }
    impl From<ArchEntryV1> for vdi_field_entry_v1 {
        fn from(entry: ArchEntryV1) -> Self {
            vdi_field_entry_v1 {
                vfe_ident: entry.ident,
                vfe_value: entry.value,
                ..Default::default()
            }
        }
    }

    impl From<vdi_timing_info_v1> for TimingInfoV1 {
        fn from(raw: vdi_timing_info_v1) -> Self {
            Self {
                guest_tsc: raw.vt_guest_tsc,
                hrtime: raw.vt_hrtime as u64,
                // TODO: u64 to u32 cast
                hrestime: Duration::new(raw.vt_hres_sec, raw.vt_hres_ns as u32),
                boot_hrtime: raw.vt_boot_hrtime,
            }
        }
    }
    impl From<TimingInfoV1> for vdi_timing_info_v1 {
        fn from(info: TimingInfoV1) -> Self {
            vdi_timing_info_v1 {
                vt_guest_tsc: info.guest_tsc,
                vt_hrtime: info.hrtime as i64,
                vt_hres_sec: info.hrestime.as_secs(),
                vt_hres_ns: info.hrestime.subsec_nanos() as u64,
                vt_boot_hrtime: info.boot_hrtime,
            }
        }
    }

    impl From<vdi_tsc_freq_v1> for TscFreqInfoV1 {
        fn from(raw: vdi_tsc_freq_v1) -> Self {
            Self {
                guest_freq: raw.vt_guest_freq,
                host_freq: raw.vt_host_freq,
                int_size: raw.vt_int_size as u8,
                frac_size: raw.vt_frac_size as u8,
            }
        }
    }
    impl From<TscFreqInfoV1> for vdi_tsc_freq_v1 {
        fn from(info: TscFreqInfoV1) -> Self {
             Self {
                vt_guest_freq: info.guest_freq,
                vt_host_freq: info.guest_freq,
                vt_int_size: info.int_size as u32,
                vt_frac_size: info.frac_size as u32,
            }
        }
    }

    impl BhyveVmV1 {
        pub(super) fn read(hdl: &VmmHdl) -> io::Result<Self> {
            // TODO: fix this up when illumos 15143 lands
            let arch_entries: Vec<bhyve_api::vdi_field_entry_v1> =
                vmm::data::read_many(hdl, -1, bhyve_api::VDC_VMM_ARCH, 1)?;

            let tsc_freq_info = Self::read_tsc_freq_info(hdl)?;

            let timing_info: bhyve_api::vdi_timing_info_v1 =
                vmm::data::read(hdl, -1, bhyve_api::VDC_VMM_TIMING, 1)?;

            Ok(Self {
                arch_entries: arch_entries
                    .into_iter()
                    .map(From::from)
                    .collect(),
                tsc_freq_info,
                timing_info: TimingInfoV1::from(timing_info),
            })
        }
    
        pub(super) fn read_tsc_freq_info(hdl: &VmmHdl) -> io::Result<TscFreqInfoV1> {
            let tsc_freq_info: bhyve_api::vdi_tsc_freq_v1 = vmm::data::read(hdl, -1, bhyve_api::VDC_VMM_SCALING, 1)?;

            Ok(TscFreqInfoV1::from(tsc_freq_info))
        }

        pub(super) fn write(self, hdl: &VmmHdl) -> io::Result<()> {
            // TODO: fix this up when illumos 15143 lands
            /*let mut arch_entries: Vec<bhyve_api::vdi_field_entry_v1> = self
                .arch_entries
                .into_iter()
                // TODO: Guest TSC frequency is not currently adjustable
                .filter(|e| e.ident != bhyve_api::VAI_TSC_FREQ)
                .map(From::from)
                .collect();
            vmm::data::write_many(
                hdl,
                -1,
                bhyve_api::VDC_VMM_TIMING,
                1,
                &mut arch_entries,
            )?; */

            let tsc_freq_info = vdi_tsc_freq_v1::from(self.tsc_freq_info);
            vmm::data::write(
                hdl,
                -1,
                bhyve_api::VDC_VMM_SCALING,
                1,
                tsc_freq_info,
            )?;

            let timing_info = vdi_timing_info_v1::from(self.timing_info);
            vmm::data::write(
                hdl,
                -1,
                bhyve_api::VDC_VMM_TIMING,
                1,
                timing_info,
            )?;

            Ok(())
        }
    }
}
