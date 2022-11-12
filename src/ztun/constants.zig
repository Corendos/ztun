// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

pub const magic_cookie = 0x2112A442;
pub const fingerprint_magic = 0x5354554e;
pub const message_header_length = 20;

pub const version = @import("std").SemanticVersion{
    .major = 0,
    .minor = 0,
    .patch = 1,
};
