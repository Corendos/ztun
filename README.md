<p align="center">
    <a href="https://github.com/Corendos/ztun/actions/workflows/main.yaml" alt="Actions">
        <img src="https://github.com/Corendos/ztun/actions/workflows/main.yaml/badge.svg" />
    </a>
</p>

`ztun` is an implementation of Session Traversal Utilities for NAT (STUN) (a.k.a [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html)) in Zig.

## What is STUN ?

Here is the abstract of the RFC 8489:

> Session Traversal Utilities for NAT (STUN) is a protocol that serves as a tool for other protocols in dealing with NAT traversal.  It can be used by an endpoint to determine the IP address and port allocated to it by a NAT.  It can also be used to check connectivity between two endpoints and as a keep-alive protocol to maintain NAT bindings. STUN works with many existing NATs and does not require any special behavior from them.
>
> STUN is not a NAT traversal solution by itself.  Rather, it is a tool to be used in the context of a NAT traversal solution.

For instance, STUN is used in the ICE protocol to gather Server Reflexive candidates and perform connectivity checks.

## Features

### Platform agnostic core

The core part of `ztun` is written without any platform-specific code. Thus, it's ready to use on any OS targeted by Zig.

### Implementation of a STUN server

`ztun` gives you access to a STUN server that is ready to use and supports the following features:
* Short-Term authentication
* Long-Term authentication
* Username Anonymity
* MD5 and Sha256 password algorithms

Data transport management is not handled by the server. This lets you integrate `ztun` in your codebase with ease.

## Usage

The simplest way you can use `ztun` is by using it's STUN message building capabilities. It exposes an easy to use `MessageBuilder` that can be used as such:

```zig
const ztun = @import("ztun");

var builder = ztun.MessageBuilder.init(allocator);
defer builder.deinit(allocator);

builder.setClass(ztun.Class.request);
builder.setMethod(ztun.Method.binding);
builder.randomTransactionId();
builder.addFingerprint();

const message = try builder.build();
defer message.deinit(allocator);
```

This snippet simply builds a STUN Binding request, using a random transaction ID and adds a fingerprint to the message. The message is allocated using the allocator given to the builder.

You can also add attributes to the message using the `builder.addAttribute()` method. For convenience, common attributes are defined in `ztun.attr.common` and can easily be converted to/from raw attributes.

For example, let's say you want to add a `SOFTWARE` attribute to a STUN message, here is how you would do it:
```zig
const ztun = @import("ztun");

var builder = ztun.MessageBuilder.init(allocator);
defer builder.deinit(allocator);

builder.setClass(ztun.Class.request);
builder.setMethod(ztun.Method.binding);
builder.randomTransactionId();

const software_attribute = ztun.attr.common.Software{ .value = "My software name" };
const raw_software_attribute = software_attribute.toAttribute(allocator);
errdefer allocator.free(raw_software_attribute.data);
builder.addAttribute(raw_software_attribute);

builder.addFingerprint();

const message = try builder.build();
defer message.deinit(allocator);
```

To get a list of all the supported common attributes, take a look at the [`src/ztun/attributes.zig`](src/ztun/attributes.zig) file.

Alternatively, you can also make use of the `Server` struct. It exposes a ready to use STUN Server:

```zig
const ztun = @import("ztun");

var server = ztun.Server.init(allocator, ztun.Server.Options{
        // The authentication type to use, valid enums are .none, .short_term and .long_term.
        .authentication_type = .none
        // (For Long-Term authentication only) The realm to use to authenticate users.
        .realm = "default"
        // (For Long-Term authentication only) The supported password algorithms
        .algorithms = &.{
            .{ .type = ztun.auth.AlgorithmType.md5, .parameters = &.{} },
            .{ .type = ztun.auth.AlgorithmType.sha256, .parameters = &.{} },
        },
    });
defer server.deinit();

try server.registerShortTermUser("user", "password");
try server.registerLongTermUser("user". "password");

const message_source: std.net.Address = ...; // The source IP that sent the message.
const raw_message = ...; // Read a message from the data transport.
const reader = std.io.fixedBufferStream(raw_message).reader();
const message = try ztun.Message.readAlloc(allocator, reader);
defer message.deinit(allocator);

const result = server.handleMessage(allocator, message, message_source);
switch (result) {
    .ok => {
        // Nothing to do.
    },
    .response => |response| {
        // Send the response back.
    }
    .discard => {
        // The message was discarded.
    },
}
```

Samples are available in the [`samples`](samples/) subfolder if you want to have a better overview.

## Supported zig version
`0.14.0`

## License

MIT
