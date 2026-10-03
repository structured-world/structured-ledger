//! The NVM regions of [`Storage`] as statics in the application's `.nvm_data`, each record an SDK
//! [`AtomicStorage`]: two copies with validity flags, so after a power loss a record holds the
//! value before a write or the value written. An update writes the other copy and only
//! invalidates the current one, whose bytes stay; records that hold secrets are therefore
//! written twice, so both copies hold the new value and no retired key or PIN verifier is left.

use ledger_device_sdk::NVMData;
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use structured_passkeys_ctap::storage::{CONFIG_LEN, INDEX_ENTRY_LEN, KEY_SLOT_LEN, Storage};

/// Discoverable index slots: at least 64 on every device.
pub const INDEX_SLOTS: usize = 64;
/// Device-only key slots: one per index slot, so every discoverable credential can be
/// device-only, plus the spare a replacement writes its new key into before the old one goes.
pub const KEY_SLOTS: usize = INDEX_SLOTS + 1;

type Record<const N: usize> = AtomicStorage<[u8; N]>;

// A fresh install holds all-zero records, which the store formats on open.
#[unsafe(link_section = ".nvm_data")]
static mut CONFIG: NVMData<Record<CONFIG_LEN>> = NVMData::new(AtomicStorage::new(&[0; CONFIG_LEN]));
#[unsafe(link_section = ".nvm_data")]
static mut INDEX: NVMData<[Record<INDEX_ENTRY_LEN>; INDEX_SLOTS]> =
    NVMData::new([const { AtomicStorage::new(&[0; INDEX_ENTRY_LEN]) }; INDEX_SLOTS]);
#[unsafe(link_section = ".nvm_data")]
static mut KEYS: NVMData<[Record<KEY_SLOT_LEN>; KEY_SLOTS]> =
    NVMData::new([const { AtomicStorage::new(&[0; KEY_SLOT_LEN]) }; KEY_SLOTS]);

/// The application's NVM regions.
pub struct NvmStorage {
    config: &'static mut Record<CONFIG_LEN>,
    index: &'static mut [Record<INDEX_ENTRY_LEN>; INDEX_SLOTS],
    keys: &'static mut [Record<KEY_SLOT_LEN>; KEY_SLOTS],
}

impl NvmStorage {
    /// The regions, through the PIC-translated addresses of the statics. A record that was
    /// never written (Speculos loads `.nvm_data` zeroed, validity flags included) is written
    /// as zeros, the free record, so every later read finds a valid copy.
    ///
    /// # Safety
    ///
    /// Called at most once: the returned value holds the only references to the statics.
    pub unsafe fn take() -> Self {
        let config = &raw mut CONFIG;
        let index = &raw mut INDEX;
        let keys = &raw mut KEYS;
        // SAFETY: the caller takes the statics once, so these are their only references.
        let storage = unsafe {
            Self {
                config: (*config).get_mut(),
                index: (*index).get_mut(),
                keys: (*keys).get_mut(),
            }
        };
        storage.config.get_or_init(&[0; CONFIG_LEN]);
        for record in storage.index.iter_mut() {
            record.get_or_init(&[0; INDEX_ENTRY_LEN]);
        }
        for record in storage.keys.iter_mut() {
            record.get_or_init(&[0; KEY_SLOT_LEN]);
        }
        storage
    }
}

impl Storage for NvmStorage {
    fn config(&self) -> &[u8; CONFIG_LEN] {
        self.config.get_ref()
    }

    fn write_config(&mut self, record: &[u8; CONFIG_LEN]) {
        // The PIN verifier: the second update overwrites the copy the first one retired.
        self.config.update(record);
        self.config.update(record);
    }

    fn index_slots(&self) -> usize {
        INDEX_SLOTS
    }

    fn index_entry(&self, slot: usize) -> &[u8; INDEX_ENTRY_LEN] {
        self.index[slot].get_ref()
    }

    fn write_index_entry(&mut self, slot: usize, record: &[u8; INDEX_ENTRY_LEN]) {
        self.index[slot].update(record);
    }

    fn key_slots(&self) -> usize {
        KEY_SLOTS
    }

    fn key_slot(&self, slot: usize) -> &[u8; KEY_SLOT_LEN] {
        self.keys[slot].get_ref()
    }

    fn write_key_slot(&mut self, slot: usize, record: &[u8; KEY_SLOT_LEN]) {
        // Private key and CredRandom: the second update overwrites the copy the first retired.
        self.keys[slot].update(record);
        self.keys[slot].update(record);
    }
}
