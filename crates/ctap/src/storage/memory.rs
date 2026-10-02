//! [`Storage`] in RAM for host tests and fuzzing, with simulated power loss.

use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

use super::{CONFIG_LEN, INDEX_ENTRY_LEN, KEY_SLOT_LEN, Storage};

/// NVM regions held in RAM. Writes are atomic per record, as on the device; after
/// [`MemoryStorage::lose_power_after`] the given number of writes land and every later one is
/// lost, until [`MemoryStorage::power_on`]. Key slots are zeroized on drop.
#[derive(Clone, Debug)]
pub struct MemoryStorage {
    config: [u8; CONFIG_LEN],
    index: Vec<[u8; INDEX_ENTRY_LEN]>,
    keys: Vec<[u8; KEY_SLOT_LEN]>,
    writes: usize,
    power_until: Option<usize>,
}

impl MemoryStorage {
    /// Fresh NVM, all zeros, with `index_slots` discoverable slots and `key_slots` key slots.
    pub fn new(index_slots: usize, key_slots: usize) -> Self {
        Self {
            config: [0; CONFIG_LEN],
            index: vec![[0; INDEX_ENTRY_LEN]; index_slots],
            keys: vec![[0; KEY_SLOT_LEN]; key_slots],
            writes: 0,
            power_until: None,
        }
    }

    /// Lets `writes` more writes land and loses every one after them.
    pub fn lose_power_after(&mut self, writes: usize) {
        self.power_until = Some(self.writes + writes);
    }

    /// Restores power: later writes land again.
    pub fn power_on(&mut self) {
        self.power_until = None;
    }

    /// Writes that landed so far.
    pub const fn writes(&self) -> usize {
        self.writes
    }

    /// Whether the next write lands, counting it if it does.
    fn powered(&mut self) -> bool {
        if self.power_until.is_some_and(|until| self.writes >= until) {
            return false;
        }
        self.writes += 1;
        true
    }
}

impl Drop for MemoryStorage {
    fn drop(&mut self) {
        for slot in &mut self.keys {
            slot.zeroize();
        }
        self.config.zeroize();
    }
}

impl Storage for MemoryStorage {
    fn config(&self) -> &[u8; CONFIG_LEN] {
        &self.config
    }

    fn write_config(&mut self, record: &[u8; CONFIG_LEN]) {
        if self.powered() {
            self.config = *record;
        }
    }

    fn index_slots(&self) -> usize {
        self.index.len()
    }

    fn index_entry(&self, slot: usize) -> &[u8; INDEX_ENTRY_LEN] {
        &self.index[slot]
    }

    fn write_index_entry(&mut self, slot: usize, record: &[u8; INDEX_ENTRY_LEN]) {
        if self.powered() {
            self.index[slot] = *record;
        }
    }

    fn key_slots(&self) -> usize {
        self.keys.len()
    }

    fn key_slot(&self, slot: usize) -> &[u8; KEY_SLOT_LEN] {
        &self.keys[slot]
    }

    fn write_key_slot(&mut self, slot: usize, record: &[u8; KEY_SLOT_LEN]) {
        if self.powered() {
            self.keys[slot] = *record;
        }
    }
}
