// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use propolis_types::PciPath;
use thiserror::Error;

use super::{Board, Chipset, InstanceSpec, SerialPort, SerialPortNumber};
#[cfg(feature = "falcon")]
use super::{P9fs, SoftNpuP9, SoftNpuPciPort, SoftNpuPort};

/// Errors that can arise while building an instance spec from component parts.
#[derive(Debug, Error)]
pub enum SpecBuilderError {
    #[error("A device with name {0} already exists")]
    DeviceNameInUse(String),

    #[error("A backend with name {0} already exists")]
    BackendNameInUse(String),

    #[error("A PCI device is already attached at {0:?}")]
    PciPathInUse(PciPath),

    #[error("Serial port {0:?} is already specified")]
    SerialPortInUse(SerialPortNumber),

    #[error("SoftNpu port {0:?} is already specified")]
    SoftNpuPortInUse(String),
}

/// A builder that constructs instance specs incrementally and catches basic
/// errors, such as specifying duplicate device or backend names or specifying
/// multiple devices with the same PCI path.
pub struct SpecBuilder {
    spec: InstanceSpec,
    pci_paths: BTreeSet<PciPath>,
}

impl SpecBuilder {
    /// Creates a new instance spec with the supplied board configuration.
    pub fn new(cpus: u8, memory_mb: u64, enable_pcie: bool) -> Self {
        let board =
            Board { cpus, memory_mb, chipset: Chipset::I440Fx { enable_pcie } };

        Self {
            spec: InstanceSpec {
                devices: super::DeviceSpec { board, ..Default::default() },
                ..Default::default()
            },
            pci_paths: Default::default(),
        }
    }

    /// Adds a PCI path to this builder's record of PCI locations with an
    /// attached device. If the path is already in use, returns an error.
    fn register_pci_device(
        &mut self,
        pci_path: PciPath,
    ) -> Result<(), SpecBuilderError> {
        if self.pci_paths.contains(&pci_path) {
            Err(SpecBuilderError::PciPathInUse(pci_path))
        } else {
            self.pci_paths.insert(pci_path);
            Ok(())
        }
    }

    /// Adds a storage device with an associated backend.
    pub fn add_storage_device(
        &mut self,
        device_name: String,
        device_spec: super::devices::StorageDevice,
        backend_name: String,
        backend_spec: super::backends::StorageBackend,
    ) -> Result<&Self, SpecBuilderError> {
        if self.spec.devices.storage_devices.contains_key(&device_name) {
            return Err(SpecBuilderError::DeviceNameInUse(device_name));
        }

        if self.spec.backends.storage_backends.contains_key(&backend_name) {
            return Err(SpecBuilderError::BackendNameInUse(backend_name));
        }

        self.register_pci_device(device_spec.pci_path)?;
        let _old =
            self.spec.devices.storage_devices.insert(device_name, device_spec);

        assert!(_old.is_none());
        let _old = self
            .spec
            .backends
            .storage_backends
            .insert(backend_name, backend_spec);

        assert!(_old.is_none());
        Ok(self)
    }

    /// Adds a network device with an associated backend.
    pub fn add_network_device(
        &mut self,
        device_name: String,
        device_spec: super::devices::NetworkDevice,
        backend_name: String,
        backend_spec: super::backends::NetworkBackend,
    ) -> Result<&Self, SpecBuilderError> {
        if self.spec.devices.network_devices.contains_key(&device_name) {
            return Err(SpecBuilderError::DeviceNameInUse(device_name));
        }

        if self.spec.backends.network_backends.contains_key(&backend_name) {
            return Err(SpecBuilderError::BackendNameInUse(backend_name));
        }

        self.register_pci_device(device_spec.pci_path)?;
        let _old =
            self.spec.devices.network_devices.insert(device_name, device_spec);

        assert!(_old.is_none());
        let _old = self
            .spec
            .backends
            .network_backends
            .insert(backend_name, backend_spec);

        assert!(_old.is_none());
        Ok(self)
    }

    /// Adds a PCI-PCI bridge.
    pub fn add_pci_bridge(
        &mut self,
        bridge_name: String,
        bridge_spec: super::devices::PciPciBridge,
    ) -> Result<&Self, SpecBuilderError> {
        if self.spec.devices.pci_pci_bridges.contains_key(&bridge_name) {
            return Err(SpecBuilderError::DeviceNameInUse(bridge_name));
        }

        self.register_pci_device(bridge_spec.pci_path)?;
        let _old =
            self.spec.devices.pci_pci_bridges.insert(bridge_name, bridge_spec);

        assert!(_old.is_none());
        Ok(self)
    }

    /// Adds a serial port.
    pub fn add_serial_port(
        &mut self,
        port: SerialPortNumber,
    ) -> Result<&Self, SpecBuilderError> {
        if self
            .spec
            .devices
            .serial_ports
            .insert(
                match port {
                    SerialPortNumber::Com1 => "com1",
                    SerialPortNumber::Com2 => "com2",
                    SerialPortNumber::Com3 => "com3",
                    SerialPortNumber::Com4 => "com4",
                }
                .to_string(),
                SerialPort { num: port },
            )
            .is_some()
        {
            Err(SpecBuilderError::SerialPortInUse(port))
        } else {
            Ok(self)
        }
    }

    #[cfg(feature = "falcon")]
    /// Sets softnpu pci port
    pub fn set_softnpu_pci_port(
        &mut self,
        pci_port: SoftNpuPciPort,
    ) -> Result<&Self, SpecBuilderError> {
        self.register_pci_device(pci_port.pci_path)?;
        self.spec.devices.softnpu_pci_port = Some(pci_port);
        Ok(self)
    }

    #[cfg(feature = "falcon")]
    pub fn add_softnpu_port(
        &mut self,
        key: String,
        port: SoftNpuPort,
    ) -> Result<&Self, SpecBuilderError> {
        let _old = self.spec.backends.network_backends.insert(
            port.backend_name.clone(),
            super::backends::NetworkBackend {
                kind: super::backends::NetworkBackendKind::Dlpi {
                    vnic_name: port.backend_name.clone(),
                },
            },
        );
        assert!(_old.is_none());
        if self.spec.devices.softnpu_ports.insert(key, port.clone()).is_some() {
            Err(SpecBuilderError::SoftNpuPortInUse(port.name))
        } else {
            Ok(self)
        }
    }

    #[cfg(feature = "falcon")]
    pub fn set_softnpu_p9(
        &mut self,
        p9: SoftNpuP9,
    ) -> Result<&Self, SpecBuilderError> {
        self.register_pci_device(p9.pci_path)?;
        self.spec.devices.softnpu_p9 = Some(p9);
        Ok(self)
    }

    #[cfg(feature = "falcon")]
    pub fn set_p9fs(&mut self, p9fs: P9fs) -> Result<&Self, SpecBuilderError> {
        self.register_pci_device(p9fs.pci_path)?;
        self.spec.devices.p9fs = Some(p9fs);
        Ok(self)
    }

    /// Yields the completed spec, consuming the builder.
    pub fn finish(self) -> InstanceSpec {
        self.spec
    }
}
