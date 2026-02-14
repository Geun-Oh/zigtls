const std = @import("std");
const zigtls = @import("zigtls");

pub fn main() !void {
    std.debug.print("zigtls {s}\n", .{zigtls.version()});
}
