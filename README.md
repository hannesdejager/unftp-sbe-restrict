# unftp-sbe-restrict

[![Crate Version](https://img.shields.io/crates/v/unftp-sbe-restrict.svg)](https://crates.io/crates/unftp-sbe-restrict)
[![API Docs](https://docs.rs/unftp-sbe-restrict/badge.svg)](https://docs.rs/unftp-sbe-restrict)
[![Crate License](https://img.shields.io/crates/l/unftp-sbe-restrict.svg)](https://crates.io/crates/unftp-sbe-restrict)
[![Follow on Telegram](https://img.shields.io/badge/Follow%20on-Telegram-brightgreen.svg)](https://t.me/unftp)  


A storage backend wrapper for [libunftp](https://github.com/Cloudinvoke/libunftp) that checks
per-user permissions before selected FTP storage operations.

## Usage

Implement [`UserDetail`](https://docs.rs/unftp-core/latest/unftp_core/auth/trait.UserDetail.html)
and [`UserWithPermissions`](https://docs.rs/unftp-sbe-restrict/latest/unftp_sbe_restrict/trait.UserWithPermissions.html)
on your user type. Return a set of [`VfsOperations`](https://docs.rs/unftp-sbe-restrict/latest/unftp_sbe_restrict/struct.VfsOperations.html)
flags, then wrap your storage backend with [`RestrictingVfs::new`](https://docs.rs/unftp-sbe-restrict/latest/unftp_sbe_restrict/struct.RestrictingVfs.html#method.new).
For example, `VfsOperations::LIST | VfsOperations::GET` permits listing and downloading while
denying the operations guarded by the other flags.

See the [crate documentation](https://docs.rs/unftp-sbe-restrict/latest/unftp_sbe_restrict/)
for a user type and wrapper example.
