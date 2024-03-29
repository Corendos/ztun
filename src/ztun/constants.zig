// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

/// Magic cookie defined by the RFC to put in the message header.
pub const magic_cookie = 0x2112A442;

/// Magic value used to XOR the fingerprint CRC32.
pub const fingerprint_magic = 0x5354554e;

/// Size in bytes of the header of a STUN message.
pub const message_header_length = 20;

/// The start of the nonce cookie that is used to fill the NONCE attribute.
pub const nonce_cookie_start = "obMatJos2";

/// Current version of the library.
pub const version = @import("std").SemanticVersion{
    .major = 0,
    .minor = 1,
    .patch = 0,
};
