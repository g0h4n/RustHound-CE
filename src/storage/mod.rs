pub mod buffer;
pub mod iter;
use std::error::Error;

pub use buffer::{BincodeObjectBuffer, Storage};

use crate::transport::ldap::LdapSearchEntry;
pub use iter::DiskStorageReader;

pub type DiskStorage = BincodeObjectBuffer<LdapSearchEntry>;

/// Used to iterate over LDAP search entries.
///
// trait is required because BincodeFileIterator will return a Result(LdapSearchEntry, Box<dyn Error>)
// without this trait the caller has to convert like `self.into_iter().map(Ok)`
pub trait EntrySource {
    type Iter: Iterator<Item = Result<LdapSearchEntry, Box<dyn Error>>>;
    fn into_entry_iter(self) -> Self::Iter;
}

// For reading from cache
impl EntrySource for DiskStorageReader<LdapSearchEntry> {
    type Iter = Self;

    fn into_entry_iter(self) -> Self::Iter {
        self
    }
}

// For reading from memory
impl EntrySource for Vec<LdapSearchEntry> {
    type Iter = std::iter::Map<
        std::vec::IntoIter<LdapSearchEntry>,
        fn(LdapSearchEntry) -> Result<LdapSearchEntry, Box<dyn Error>>,
    >;

    fn into_entry_iter(self) -> Self::Iter {
        self.into_iter().map(Ok)
    }
}
