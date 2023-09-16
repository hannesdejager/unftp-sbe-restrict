#![deny(clippy::all)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![doc(html_root_url = "https://docs.rs/unftp-sbe-restrict/0.1.1")]

//! A [libunftp](https://docs.rs/libunftp/latest/libunftp/) wrapper
//! storage back-end that restricts FTP operations and in so doing
//! provide some form of authorization.
//!
//! # Quick start
//!
//! Start by implementing the libunftp [`UserDetail`](libunftp::auth::UserDetail) trait
//! and then follow that by implementing [`UserWithPermissions`](crate::UserWithPermissions).
//!
//! Finally call the [RestrictingVfs::new()](crate::RestrictingVfs::new) method.
//!
//! ```rust
//! use libunftp::auth::UserDetail;
//! use unftp_sbe_restrict::{UserWithPermissions, VfsOperations};
//! use std::fmt::Formatter;
//!
//! #[derive(Debug, PartialEq, Eq)]
//! pub struct User {
//!     pub username: String,
//!     // e.g. this can be something like
//!     // `VfsOperations::all() - VfsOperations::PUT - VfsOperations::DEL`
//!     pub permissions: VfsOperations,
//! }
//!
//! impl UserDetail for User {
//!     fn account_enabled(&self) -> bool {
//!         true
//!     }
//! }
//!
//! impl std::fmt::Display for User {
//!     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//!         write!(f, "User(username: {:?}", self.username,)
//!     }
//! }
//!
//! impl UserWithPermissions for User {
//!     fn permissions(&self) -> VfsOperations {
//!         self.permissions
//!     }
//! }
//!
//! // Return type omited for brevity.
//! fn create_restricted_storage_backend() {
//!     use unftp_sbe_fs::{Filesystem, Meta};
//!     let _backend = Box::new(move || {
//!         unftp_sbe_restrict::RestrictingVfs::<Filesystem, User, Meta>::new(Filesystem::new("/srv/ftp"))
//!     });
//! }
//!
// ```

use async_trait::async_trait;
use bitflags::bitflags;
use libunftp::{
    auth::UserDetail,
    storage::{self, Fileinfo, Metadata, StorageBackend},
};
use std::fmt::Debug;
use std::io::{Cursor, Error, ErrorKind};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use tokio::io::AsyncRead;

bitflags! {
    /// The FTP operations that can be enabled/disabled for the virtual filesystem.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VfsOperations: u32 {
        /// If set allows FTP make directory
        const MK_DIR = 0b00000001;
        /// If set allows FTP remove directory
        const RM_DIR = 0b00000010;
        /// If set allows FTP GET i.e. clients can download files.
        const GET    = 0b00000100;
        /// If set allows FTP PUT i.e. clients can upload files.
        const PUT    = 0b00001000;
        /// If set allows FTP DELE i.e. clients can remove files.
        const DEL    = 0b00010000;
        /// If set allows FTP RENAME i.e. clients can rename directories and files
        const RENAME = 0b00100000;
        /// If set allows the extended SITE MD5 command to calculate checksums
        const MD5    = 0b01000000;
        /// If set allows clients to list the contents of a directory.
        const LIST   = 0b10000000;

        /// Convenience aggragation of all the write operation bits.
        const WRITE_OPS = Self::MK_DIR.bits() | Self::RM_DIR.bits() | Self::PUT.bits() | Self::DEL.bits() | Self::RENAME.bits();
    }
}

/// Used by [RestrictingVfs] to obtain permission info from a [UserDetail](libunftp::auth::UserDetail) implementation
pub trait UserWithPermissions: UserDetail {
    /// Returns the permissions given to the user
    fn permissions(&self) -> VfsOperations;
}

/// A virtual filesystem that checks if the user has permissions to do its operations before it
/// delegates to another storage back-end.
#[derive(Debug)]
pub struct RestrictingVfs<Delegate, User, Meta>
where
    Delegate: StorageBackend<User>,
    User: UserWithPermissions,
    Meta: Metadata + Debug + Sync + Send,
{
    delegate: Delegate,
    x: PhantomData<Meta>,
    y: PhantomData<User>,
}

impl<Delegate, User, Meta> RestrictingVfs<Delegate, User, Meta>
where
    Delegate: StorageBackend<User>,
    User: UserWithPermissions,
    Meta: Metadata + Debug + Sync + Send,
{
    /// Creates a new instance of [`RestrictingVfs`](crate::RestrictingVfs).
    pub fn new(delegate: Delegate) -> Self {
        RestrictingVfs {
            delegate,
            x: PhantomData,
            y: PhantomData,
        }
    }
}

#[async_trait]
impl<Delegate, User, Meta> StorageBackend<User> for RestrictingVfs<Delegate, User, Meta>
where
    Delegate: StorageBackend<User>,
    User: UserWithPermissions,
    Meta: Metadata + Debug + Sync + Send,
{
    type Metadata = Delegate::Metadata;

    fn name(&self) -> &str {
        self.delegate.name()
    }

    fn supported_features(&self) -> u32 {
        self.delegate.supported_features()
    }

    async fn metadata<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<Self::Metadata> {
        self.delegate.metadata(user, path).await
    }

    async fn md5<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<String>
    where
        P: AsRef<Path> + Send + Debug,
    {
        if user.permissions().contains(VfsOperations::MD5) {
            self.delegate.md5(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn list<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<Vec<Fileinfo<PathBuf, Self::Metadata>>>
    where
        <Self as StorageBackend<User>>::Metadata: Metadata,
    {
        if user.permissions().contains(VfsOperations::LIST) {
            self.delegate.list(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn list_fmt<P>(&self, user: &User, path: P) -> storage::Result<Cursor<Vec<u8>>>
    where
        P: AsRef<Path> + Send + Debug,
        Self::Metadata: Metadata + 'static,
    {
        if user.permissions().contains(VfsOperations::LIST) {
            self.delegate.list_fmt(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn nlst<P>(&self, user: &User, path: P) -> std::result::Result<Cursor<Vec<u8>>, Error>
    where
        P: AsRef<Path> + Send + Debug,
        Self::Metadata: Metadata + 'static,
    {
        if user.permissions().contains(VfsOperations::LIST) {
            self.delegate.nlst(user, path).await
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    }

    async fn get_into<'a, P, W: ?Sized>(
        &self,
        user: &User,
        path: P,
        start_pos: u64,
        output: &'a mut W,
    ) -> storage::Result<u64>
    where
        W: tokio::io::AsyncWrite + Unpin + Sync + Send,
        P: AsRef<Path> + Send + Debug,
    {
        if user.permissions().contains(VfsOperations::GET) {
            self.delegate.get_into(user, path, start_pos, output).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn get<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
        start_pos: u64,
    ) -> storage::Result<Box<dyn AsyncRead + Send + Sync + Unpin>> {
        if user.permissions().contains(VfsOperations::GET) {
            self.delegate.get(user, path, start_pos).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn put<
        P: AsRef<Path> + Send + Debug,
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    >(
        &self,
        user: &User,
        input: R,
        path: P,
        start_pos: u64,
    ) -> storage::Result<u64> {
        if user.permissions().contains(VfsOperations::PUT) {
            self.delegate.put(user, input, path, start_pos).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn del<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<()> {
        if user.permissions().contains(VfsOperations::DEL) {
            self.delegate.del(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn mkd<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<()> {
        if user.permissions().contains(VfsOperations::MK_DIR) {
            self.delegate.mkd(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn rename<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        from: P,
        to: P,
    ) -> storage::Result<()> {
        if user.permissions().contains(VfsOperations::RENAME) {
            self.delegate.rename(user, from, to).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn rmd<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<()> {
        if user.permissions().contains(VfsOperations::RM_DIR) {
            self.delegate.rmd(user, path).await
        } else {
            Err(libunftp::storage::ErrorKind::PermissionDenied.into())
        }
    }

    async fn cwd<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &User,
        path: P,
    ) -> storage::Result<()> {
        self.delegate.cwd(user, path).await
    }
}
