const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const debug_ubsan = b.option(bool, "debug-ubsan", "Build with undefined behaviour sanitizer") orelse false;
    const debug_asan = b.option(bool, "debug-asan", "Build with address sanitizer") orelse false;

    const libmprompt_dep = b.dependency("libmprompt", .{
        .target = target,
        .optimize = optimize,
    });

    const mprompt_sources = [_][]const u8{
        "src/mprompt/main.c",
    };

    const mpeff_sources = [_][]const u8{
        "src/mpeff/main.c",
    };

    const test_mpe_main_sources = [_][]const u8{
        "test/common_util.c",
        "test/common_effects.c",
        "test/src/reader.c",
        "test/src/counter.c",
        "test/src/countern.c",
        "test/src/mstate.c",
        "test/src/amb.c",
        "test/src/amb_state.c",
        "test/src/nqueens.c",
        "test/src/rehandle.c",
        "test/src/triples.c",
        "test/test_mpe_main.c",
    };

    var test_mpe_main_sources_list = std.ArrayList([]const u8).init(b.allocator);
    defer test_mpe_main_sources_list.deinit();
    test_mpe_main_sources_list.appendSlice(&test_mpe_main_sources) catch return;

    //if (!use_c) {
    //    test_mpe_main_sources_list.append("test/src/exn.cpp") catch return;
    //    test_mpe_main_sources_list.append("test/src/multi_unwind.cpp") catch return;
    //    test_mpe_main_sources_list.append("test/src/throw.cpp") catch return;
    //}

    const test_mp_async_sources = [_][]const u8{
        "test/test_mp_async.c",
        "test/common_util.c",
    };

    const test_mp_example_generator_sources = [_][]const u8{
        "test/test_mp_example_generator.c",
    };

    const test_mp_example_async_sources = [_][]const u8{
        "test/test_mp_example_async.c",
    };

    var test_sources_list = std.ArrayList([]const u8).init(b.allocator);
    defer test_sources_list.deinit();

    test_sources_list.appendSlice(test_mpe_main_sources_list.items) catch return;
    test_sources_list.appendSlice(&test_mp_async_sources) catch return;
    test_sources_list.appendSlice(&test_mp_example_generator_sources) catch return;
    test_sources_list.appendSlice(&test_mp_example_async_sources) catch return;

    var cflags = std.ArrayList([]const u8).init(b.allocator);
    defer cflags.deinit();

    const mp_mprompt_name: [:0]const u8 = "mprompt";
    const mp_mpeff_name: [:0]const u8 = "mpeff";
    var mprompt_asm_source: []const u8 = undefined;

    if (builtin.cpu.arch == .x86_64) {
        if (builtin.os.tag == .windows) {
            mprompt_asm_source = "src/mprompt/asm/longjmp_amd64_win.asm";
        } else {
            mprompt_asm_source = "src/mprompt/asm/longjmp_amd64.S";
        }
    } else if (builtin.cpu.arch == .aarch64) {
        if (builtin.os.tag == .macos) {
            std.debug.print("arm64 support on Apple is untested\n", .{});
        }
        mprompt_asm_source = "src/mprompt/asm/longjmp_arm64.S";
    } else {
        std.debug.print("unsupported architecture: {s}\n", .{builtin.cpu.arch});
    }

    if (optimize == .Debug and (debug_ubsan or debug_asan) and builtin.os.tag != .windows and builtin.zig_backend != .stage2_llvm) { // != .freestanding) {
        var san_flags = std.ArrayList([]const u8).init(b.allocator);
        defer san_flags.deinit();

        if (debug_ubsan) {
            san_flags.append("undefined") catch return;
        }
        if (debug_asan) {
            san_flags.append("address") catch return;
        }

        const san_flags_joined = std.mem.join(b.allocator, ",", san_flags.items) catch unreachable;
        cflags.append(std.mem.concat(b.allocator, "-fsanitize=", san_flags_joined)) catch return;
    } else if ((debug_ubsan or debug_asan)) {
        std.debug.print("Can only use sanitizer with a clang++ debug build\n", .{});
    }

    if (optimize == .ReleaseFast or (optimize == .ReleaseSafe and builtin.os.tag != .macos)) {
        cflags.append("-flto") catch return;
    }

    if (builtin.os.tag != .windows and builtin.os.tag != .freestanding) {
        cflags.append("-Wall") catch return;
        cflags.append("-Wextra") catch return;
        cflags.append("-Wno-unknown-pragmas") catch return;
        cflags.append("-fvisibility=hidden") catch return;
    }

    if (builtin.os.tag == .macos) {}

    std.debug.print("\nLibraries : lib{s}, lib{s}\n", .{ mp_mprompt_name, mp_mpeff_name });
    std.debug.print("            {s}\n", .{std.mem.join(b.allocator, " ", cflags.items) catch unreachable});
    std.debug.print("Link with : pthread\n\n", .{});

    const install_step = b.step("installer", "Install the library");

    const mprompt_lib = b.addStaticLibrary(.{
        .name = mp_mprompt_name,
        .target = target,
        .optimize = optimize,
    });
    const mprompt_srcs = [_][]const u8{ mprompt_sources[0], mprompt_asm_source };
    //mprompt_lib.addCSourceFiles(.{ .files = &mprompt_srcs, .flags = cflags.items });
    mprompt_lib.addCSourceFiles(.{ .files = &mprompt_srcs, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    mprompt_lib.addIncludePath(libmprompt_dep.path("include"));
    if (builtin.os.tag != .windows and builtin.os.tag != .freestanding) {
        mprompt_lib.linkLibC();
        mprompt_lib.linkSystemLibrary("pthread");
    }

    const mpeff_lib = b.addStaticLibrary(.{
        .name = mp_mpeff_name,
        .target = target,
        .optimize = optimize,
    });
    mpeff_lib.addCSourceFiles(.{ .files = &mpeff_sources, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    //mpeff_lib.addDefine("MPE_STATIC_LIB", null);
    mpeff_lib.addIncludePath(libmprompt_dep.path("include"));
    if (builtin.os.tag != .windows and builtin.os.tag != .freestanding) {
        mpeff_lib.linkLibC();
        mpeff_lib.linkSystemLibrary("pthread");
    }

    install_step.dependOn(&mprompt_lib.step);
    install_step.dependOn(&mpeff_lib.step);

    const test_mpe_main_exe = b.addExecutable(.{
        .name = "test_mpe_main",
        .target = target,
        .optimize = optimize,
    });
    test_mpe_main_exe.addCSourceFiles(.{ .files = test_mpe_main_sources_list.items, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    test_mpe_main_exe.addIncludePath(libmprompt_dep.path("include"));
    test_mpe_main_exe.addIncludePath(libmprompt_dep.path("test"));
    test_mpe_main_exe.linkLibrary(mpeff_lib);
    test_mpe_main_exe.linkLibrary(mprompt_lib);
    b.installArtifact(test_mpe_main_exe);

    const test_mp_async_exe = b.addExecutable(.{
        .name = "test_mp_async",
        .target = target,
        .optimize = optimize,
    });
    test_mp_async_exe.addCSourceFiles(.{ .files = &test_mp_async_sources, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    test_mp_async_exe.addIncludePath(libmprompt_dep.path("include"));
    test_mp_async_exe.addIncludePath(libmprompt_dep.path("test"));
    test_mp_async_exe.linkLibrary(mpeff_lib);
    test_mp_async_exe.linkLibrary(mprompt_lib);
    b.installArtifact(test_mp_async_exe);

    const test_mp_example_generator_exe = b.addExecutable(.{
        .name = "test_mp_example_generator",
        .target = target,
        .optimize = optimize,
    });
    test_mp_example_generator_exe.addCSourceFiles(.{ .files = &test_mp_example_generator_sources, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    test_mp_example_generator_exe.addIncludePath(libmprompt_dep.path("include"));
    test_mp_example_generator_exe.addIncludePath(libmprompt_dep.path("test"));
    test_mp_example_generator_exe.linkLibrary(mpeff_lib);
    test_mp_example_generator_exe.linkLibrary(mprompt_lib);
    b.installArtifact(test_mp_example_generator_exe);

    const test_mp_example_async_exe = b.addExecutable(.{
        .name = "test_mp_example_async",
        .target = target,
        .optimize = optimize,
    });
    test_mp_example_async_exe.addCSourceFiles(.{ .files = &test_mp_example_async_sources, .flags = cflags.items, .root = libmprompt_dep.path(".") });
    test_mp_example_async_exe.addIncludePath(libmprompt_dep.path("include"));
    test_mp_example_async_exe.addIncludePath(libmprompt_dep.path("test"));
    test_mp_example_async_exe.linkLibrary(mpeff_lib);
    test_mp_example_async_exe.linkLibrary(mprompt_lib);
    b.installArtifact(test_mp_example_async_exe);

    const test_step = b.step("test", "Run tests");

    const test_mpe_main_run = b.addRunArtifact(test_mpe_main_exe);
    test_step.dependOn(&test_mpe_main_run.step);

    const test_mp_async_run = b.addRunArtifact(test_mp_async_exe);
    test_step.dependOn(&test_mp_async_run.step);

    const test_mp_example_generator_run = b.addRunArtifact(test_mp_example_generator_exe);
    test_step.dependOn(&test_mp_example_generator_run.step);

    const test_mp_example_async_run = b.addRunArtifact(test_mp_example_async_exe);
    test_step.dependOn(&test_mp_example_async_run.step);

    b.installArtifact(mprompt_lib);
    b.installArtifact(mpeff_lib);
}
