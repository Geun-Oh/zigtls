const std = @import("std");

pub const Role = enum {
    client,
    server,
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

pub const HandshakeEvent = enum {
    client_hello,
    server_hello,
    hello_retry_request,
    new_session_ticket,
    encrypted_extensions,
    certificate,
    certificate_verify,
    finished,
    key_update,
    message_hash,
};

pub const ConnectionState = enum {
    start,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_server_certificate,
    wait_server_certificate_verify,
    wait_server_finished,
    wait_client_certificate_or_finished,
    wait_client_certificate_verify,
    wait_client_finished_after_cert,
    connected,
    closing,
    closed,
};

pub const TransitionError = error{
    IllegalTransition,
};

pub const Machine = struct {
    role: Role,
    state: ConnectionState,

    pub fn init(role: Role) Machine {
        return .{
            .role = role,
            .state = switch (role) {
                .client => .wait_server_hello,
                .server => .start,
            },
        };
    }

    pub fn onHandshake(self: *Machine, handshake_type: HandshakeType) TransitionError!void {
        try self.onEvent(fromHandshakeType(handshake_type));
    }

    pub fn onEvent(self: *Machine, event: HandshakeEvent) TransitionError!void {
        switch (self.role) {
            .client => try onClientHandshake(self, event),
            .server => try onServerHandshake(self, event),
        }
    }

    pub fn markClosing(self: *Machine) void {
        self.state = .closing;
    }

    pub fn markClosed(self: *Machine) void {
        self.state = .closed;
    }
};

pub fn fromHandshakeType(handshake_type: HandshakeType) HandshakeEvent {
    return switch (handshake_type) {
        .client_hello => .client_hello,
        .server_hello => .server_hello,
        .new_session_ticket => .new_session_ticket,
        .encrypted_extensions => .encrypted_extensions,
        .certificate => .certificate,
        .certificate_verify => .certificate_verify,
        .finished => .finished,
        .key_update => .key_update,
        .message_hash => .message_hash,
    };
}

fn onClientHandshake(self: *Machine, event: HandshakeEvent) TransitionError!void {
    switch (self.state) {
        .wait_server_hello => switch (event) {
            .server_hello => self.state = .wait_encrypted_extensions,
            .hello_retry_request => {},
            else => return error.IllegalTransition,
        },
        .wait_encrypted_extensions => if (event == .encrypted_extensions) {
            self.state = .wait_server_certificate;
        } else {
            return error.IllegalTransition;
        },
        .wait_server_certificate => switch (event) {
            .certificate => self.state = .wait_server_certificate_verify,
            .finished => self.state = .connected,
            else => return error.IllegalTransition,
        },
        .wait_server_certificate_verify => if (event == .certificate_verify) {
            self.state = .wait_server_finished;
        } else {
            return error.IllegalTransition;
        },
        .wait_server_finished => if (event == .finished) {
            self.state = .connected;
        } else {
            return error.IllegalTransition;
        },
        .connected => switch (event) {
            .new_session_ticket, .key_update => {},
            else => return error.IllegalTransition,
        },
        else => return error.IllegalTransition,
    }
}

fn onServerHandshake(self: *Machine, event: HandshakeEvent) TransitionError!void {
    switch (self.state) {
        .start => if (event == .client_hello) {
            self.state = .wait_client_certificate_or_finished;
        } else {
            return error.IllegalTransition;
        },
        .wait_client_certificate_or_finished => switch (event) {
            .certificate => self.state = .wait_client_certificate_verify,
            .finished => self.state = .connected,
            else => return error.IllegalTransition,
        },
        .wait_client_certificate_verify => if (event == .certificate_verify) {
            self.state = .wait_client_finished_after_cert;
        } else {
            return error.IllegalTransition;
        },
        .wait_client_finished_after_cert => if (event == .finished) {
            self.state = .connected;
        } else {
            return error.IllegalTransition;
        },
        .connected => switch (event) {
            .new_session_ticket, .key_update => {},
            else => return error.IllegalTransition,
        },
        else => return error.IllegalTransition,
    }
}

test "client handshake transition happy path" {
    var machine = Machine.init(.client);
    try machine.onHandshake(.server_hello);
    try machine.onHandshake(.encrypted_extensions);
    try machine.onHandshake(.certificate);
    try machine.onHandshake(.certificate_verify);
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}

test "server handshake transition happy path" {
    var machine = Machine.init(.server);
    try machine.onHandshake(.client_hello);
    try machine.onHandshake(.certificate);
    try machine.onHandshake(.certificate_verify);
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}

test "unexpected handshake is rejected" {
    var machine = Machine.init(.client);
    try std.testing.expectError(error.IllegalTransition, machine.onHandshake(.finished));
}

test "client accepts hello retry request and stays waiting server hello" {
    var machine = Machine.init(.client);
    try machine.onEvent(.hello_retry_request);
    try std.testing.expectEqual(ConnectionState.wait_server_hello, machine.state);
}

test "client also accepts psk-like path without certificate" {
    var machine = Machine.init(.client);
    try machine.onHandshake(.server_hello);
    try machine.onHandshake(.encrypted_extensions);
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}

test "server also accepts no-client-certificate path" {
    var machine = Machine.init(.server);
    try machine.onHandshake(.client_hello);
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}
