// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Generates a TPM2 ACPI table, and the matching DSDT device, for an instance.
//!
//! The [`Tpm2`] struct implements the `Aml` trait of the `acpi_tables` crate
//! and can write the AML bytecode to any AmlSink, like a `Vec<u8>`.
//!
//! Between them, the two items here describe a TPM 2.0 using the Command
//! Response Buffer (CRB) interface to the guest:
//!
//! - The TPM2 table tells the guest that a TPM 2.0 is present, which interface
//!   it speaks, and where its control area lives.
//! - The [`TpmDevice`] node in the DSDT reserves the CRB register window in the
//!   ACPI namespace and gives the guest a device with the `MSFT0101` ID for a
//!   driver to bind to.
//!
//! Guests want both: Linux's `tpm_crb` driver, for example, matches on the
//! `MSFT0101` device but reads the control area address out of the TPM2 table.
//!
//! TCG ACPI Specification, version 1.4, section 3.2 "TPM2 Table"
//!
//! <https://trustedcomputinggroup.org/resource/tcg-acpi-specification/>
//!
//! # Note
//!
//! These tables only *advertise* a TPM, they do not emulate one. Nothing in
//! Propolis currently services the CRB register window described here, so they
//! should only be generated for instances that actually have a TPM device,
//! lest the guest find the device and then fail to talk to it.

use super::aml::names;
use super::{AcpiVariant, OEM_ID, OEM_REVISION, OEM_TABLE_ID};
use acpi_tables::{
    aml,
    tpm2::{PlatformClass, StartMethod, Tpm2 as Tpm2Table},
    Aml, AmlSink,
};

/// Base address of the TPM's CRB register window.
///
/// This is the fixed address the TCG specification assigns to the TPM, and is
/// the same address QEMU uses for its CRB device.
///
/// TCG PC Client Platform TPM Profile Specification for TPM 2.0, section 6.5.2
/// "Command Response Buffer Interface"
pub const CRB_MMIO_BASE: u32 = 0xfed4_0000;

/// Length of the TPM's CRB register window.
pub const CRB_MMIO_LEN: u32 = 0x1000;

/// Offset of the control area within the CRB register window.
///
/// The window opens with the per-locality registers (`TPM_LOC_STATE_x`,
/// `TPM_LOC_CTRL_x`, `TPM_LOC_STS_x`, `TPM_INTERFACE_ID_x`, and
/// `TPM_CRB_CTRL_EXT_x`), which occupy the first 0x40 bytes. The control area
/// proper begins after them, at `TPM_CRB_CTRL_REQ_x`.
const CRB_CONTROL_AREA_OFFSET: u32 = 0x40;

/// Address of the CRB control area.
///
/// This, rather than [`CRB_MMIO_BASE`], is what the TPM2 table advertises when
/// the start method is [`StartMethod::Crb`].
pub const CRB_CONTROL_AREA_ADDR: u64 =
    (CRB_MMIO_BASE + CRB_CONTROL_AREA_OFFSET) as u64;

/// Plug and Play ID for a TPM 2.0 device.
///
/// Unlike the `PNP`-prefixed IDs in [`super::aml::devids`], this is a vendor ID
/// assigned to Microsoft rather than one from the PNP registry. It is what both
/// Windows and Linux look for to find a TPM 2.0.
///
/// TCG ACPI Specification, version 1.4, section 3.1 "Device Object"
const TPM_HID: &str = "MSFT0101";

/// Value returned by the TPM device's `_STA`: present, enabled, shown in the
/// UI, and functioning.
///
/// ACPI rev. 6.6 section 6.3.7 "_STA (Device Status)"
const TPM_STA: u64 = 0x0f;

/// Configuration for generating a TPM2 table.
pub struct Tpm2Config {
    /// The ACPI table variant to use.
    pub acpi_variant: AcpiVariant,
}

/// The TPM2 table describes the TPM 2.0 presented to the guest.
///
/// TCG ACPI Specification, version 1.4, section 3.2 "TPM2 Table"
pub struct Tpm2 {
    config: Tpm2Config,
}

impl Tpm2 {
    pub fn new(config: Tpm2Config) -> Self {
        Self { config }
    }
}

impl Aml for Tpm2 {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        match self.config.acpi_variant {
            AcpiVariant::V0 => {
                // Propolis presents a "client" platform TPM, matching the
                // physical machines guests expect to be running on.
                //
                // The event log fields are left out entirely: populating them
                // means reserving guest memory for the log and handing the
                // firmware a pointer to it, which Propolis does not do yet. A
                // TPM2 table without a log is the short, 52-byte revision 1
                // form, which EDK2 and guests both accept.
                Tpm2Table::new(
                    *OEM_ID,
                    *OEM_TABLE_ID,
                    OEM_REVISION,
                    PlatformClass::Client,
                    CRB_CONTROL_AREA_ADDR,
                    StartMethod::Crb,
                )
                .to_aml_bytes(sink);
            }
        }
    }
}

/// The TPM device in the DSDT's system bus scope (`\_SB.TPM`).
///
/// The CRB register window is behind neither the PCI root bridge nor the LPC
/// bridge, so the device is declared directly under `\_SB`.
///
/// TCG ACPI Specification, version 1.4, section 3.1 "Device Object"
pub struct TpmDevice {}

impl Aml for TpmDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        aml::Device::new(
            // ACPI name segments are four characters, padded with underscores.
            "TPM_".into(),
            vec![
                &names::hid(&TPM_HID),
                &names::crs(&aml::ResourceTemplate::new(vec![
                    &aml::Memory32Fixed::new(
                        true, // The CRB window is read/write.
                        CRB_MMIO_BASE,
                        CRB_MMIO_LEN,
                    ),
                ])),
                &names::sta(&TPM_STA),
            ],
        )
        .to_aml_bytes(sink);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn tpm2_bytes() -> Vec<u8> {
        let tpm2 = Tpm2::new(Tpm2Config { acpi_variant: AcpiVariant::V0 });
        let mut sink = Vec::new();
        tpm2.to_aml_bytes(&mut sink);
        sink
    }

    /// The TPM2 table is the short revision 1 form, and is self-consistent.
    #[test]
    fn tpm2_table() {
        let sink = tpm2_bytes();

        assert_eq!(&sink[0..4], b"TPM2");

        // Without an event log, the table is the short revision 1 form.
        assert_eq!(sink.len(), 52);
        assert_eq!(
            u32::from_le_bytes(sink[4..8].try_into().unwrap()),
            sink.len() as u32,
        );

        // A valid ACPI table's bytes sum to zero.
        assert_eq!(sink.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)), 0);
    }

    /// The table advertises the CRB interface at the control area address,
    /// rather than at the base of the register window.
    #[test]
    fn tpm2_table_crb_fields() {
        let sink = tpm2_bytes();

        // Platform class, at offset 36, follows the 36-byte table header.
        assert_eq!(
            u16::from_le_bytes(sink[36..38].try_into().unwrap()),
            PlatformClass::Client as u16,
        );

        // Control area address, at offset 40, after two reserved bytes.
        assert_eq!(
            u64::from_le_bytes(sink[40..48].try_into().unwrap()),
            CRB_CONTROL_AREA_ADDR,
        );
        assert_eq!(CRB_CONTROL_AREA_ADDR, 0xfed4_0040);

        // Start method, at offset 48.
        assert_eq!(
            u32::from_le_bytes(sink[48..52].try_into().unwrap()),
            StartMethod::Crb as u32,
        );
    }

    /// The DSDT device carries the ID guests match on, and reserves the window
    /// that the TPM2 table's control area address points into.
    #[test]
    fn tpm_device_aml() {
        let mut sink = Vec::new();
        TpmDevice {}.to_aml_bytes(&mut sink);

        assert!(sink.windows(4).any(|w| w == b"TPM_"));
        assert!(sink.windows(4).any(|w| w == b"_HID"));
        assert!(sink.windows(8).any(|w| w == TPM_HID.as_bytes()));
        assert!(sink.windows(4).any(|w| w == b"_CRS"));
        assert!(sink.windows(4).any(|w| w == b"_STA"));

        let mut crs = Vec::new();
        aml::Memory32Fixed::new(true, CRB_MMIO_BASE, CRB_MMIO_LEN)
            .to_aml_bytes(&mut crs);
        assert!(sink.windows(crs.len()).any(|w| w == crs));

        let window =
            CRB_MMIO_BASE as u64..(CRB_MMIO_BASE as u64 + CRB_MMIO_LEN as u64);
        assert!(window.contains(&CRB_CONTROL_AREA_ADDR));
    }
}
