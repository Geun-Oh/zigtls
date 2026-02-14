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

pub const ConnectionState = enum {
    start,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_server_finished,
    wait_client_finished,
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
        switch (self.role) {
            .client => try onClientHandshake(self, handshake_type),
            .server => try onServerHandshake(self, handshake_type),
        }
    }

    pub fn markClosing(self: *Machine) void {
        self.state = .closing;
    }

    pub fn markClosed(self: *Machine) void {
        self.state = .closed;
    }
};

fn onClientHandshake(self: *Machine, handshake_type: HandshakeType) TransitionError!void {
    switch (self.state) {
        .wait_server_hello => if (handshake_type == .server_hello) {
            self.state = .wait_encrypted_extensions;
        } else {
            return error.IllegalTransition;
        },
        .wait_encrypted_extensions => if (handshake_type == .encrypted_extensions) {
            self.state = .wait_server_finished;
        } else {
            return error.IllegalTransition;
        },
        .wait_server_finished => if (handshake_type == .finished) {
            self.state = .connected;
        } else {
            return error.IllegalTransition;
        },
        .connected => switch (handshake_type) {
            .new_session_ticket, .key_update => {},
            else => return error.IllegalTransition,
        },
        else => return error.IllegalTransition,
    }
}

fn onServerHandshake(self: *Machine, handshake_type: HandshakeType) TransitionError!void {
    switch (self.state) {
        .start => if (handshake_type == .client_hello) {
            self.state = .wait_client_finished;
        } else {
            return error.IllegalTransition;
        },
        .wait_client_finished => if (handshake_type == .finished) {
            self.state = .connected;
        } else {
            return error.IllegalTransition;
        },
        .connected => switch (handshake_type) {
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
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}

test "server handshake transition happy path" {
    var machine = Machine.init(.server);
    try machine.onHandshake(.client_hello);
    try machine.onHandshake(.finished);
    try std.testing.expectEqual(ConnectionState.connected, machine.state);
}

test "unexpected handshake is rejected" {
    var machine = Machine.init(.client);
    try std.testing.expectError(error.IllegalTransition, machine.onHandshake(.finished));
}
