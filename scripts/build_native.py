import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

TARGETS = {
    "armeabi-v7a": ("armv7-linux-androideabi", "armv7a-linux-androideabi"),
    "arm64-v8a": ("aarch64-linux-android", "aarch64-linux-android"),
    "x86": ("i686-linux-android", "i686-linux-android"),
    "x86_64": ("x86_64-linux-android", "x86_64-linux-android"),
}


def write_notices(cargo, manifest, destination):
    platform_filters = [arg for target, _ in TARGETS.values() for arg in ("--filter-platform", target)]
    metadata = subprocess.check_output(
        [cargo, "metadata", "--locked", "--offline", "--format-version", "1",
         "--manifest-path", str(manifest), *platform_filters],
        encoding="utf-8",
    )
    packages = sorted(json.loads(metadata)["packages"], key=lambda p: (p["name"], p["version"]))
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "LICENSE-Flowseal"):
        shutil.copyfile(manifest.parent.parent / name, destination / name)

    with (destination / "rust-dependencies.txt").open("w", encoding="utf-8") as notices:
        for package in packages:
            if not package["source"]:
                continue
            root = Path(package["manifest_path"]).parent
            notices.write(f'{package["name"]} {package["version"]} | {package["license"]}\n\n')
            files = {
                file for file in root.iterdir() if file.is_file()
                and file.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE"))
            }
            if package["license_file"]:
                files.add(root / package["license_file"])
            for file in sorted(files):
                notices.write(f"{file.name}\n{file.read_text(encoding='utf-8').strip()}\n\n")


def main():
    parser = argparse.ArgumentParser(description="Build the Android Rust proxy libraries")
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--licenses", type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--api", required=True, type=int)
    parser.add_argument("--test-abi", choices=TARGETS)
    args = parser.parse_args()

    system = platform.system()
    host = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}[system]
    suffix = ".exe" if system == "Windows" else ""
    tools = args.ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    clang, ar = tools / f"clang{suffix}", tools / f"llvm-ar{suffix}"
    if not clang.is_file() or not ar.is_file():
        parser.error(f"Android NDK toolchain was not found: {tools}")

    cargo = os.environ.get("TGWS_CARGO", "cargo")
    manifest = args.native.resolve() / "Cargo.toml"
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo").resolve()
    remapped_paths = (
        (manifest.parent.parent, "/source"),
        (args.target_dir.resolve(), "/build"),
        (cargo_home, "/cargo"),
    )
    remap_flags = [
        f"--remap-path-prefix={source}={destination}"
        for path, destination in remapped_paths
        for source in dict.fromkeys((str(path), path.as_posix()))
    ]
    selected = [args.test_abi] if args.test_abi else TARGETS
    for abi in selected:
        target, llvm_name = TARGETS[abi]
        lower = target.replace("-", "_")
        upper = lower.upper()
        llvm_target = f"--target={llvm_name}{args.api}"
        env = os.environ.copy()
        env.update({
            "CARGO_TARGET_DIR": str(args.target_dir.resolve()),
            f"CARGO_TARGET_{upper}_LINKER": str(clang),
            # Cargo's encoded form preserves remapping arguments for paths with spaces.
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join([
                f"-Clink-arg={llvm_target}", "-Clink-arg=-Wl,-z,max-page-size=16384", *remap_flags,
            ]),
            f"CC_{lower}": str(clang),
            f"CFLAGS_{lower}": llvm_target,
            f"AR_{lower}": str(ar),
        })
        operation = ["test", "--no-run", "--message-format=json"] if args.test_abi else ["build"]
        subprocess.run(
            [cargo, *operation, "--locked", "--release", "--target", target,
             "--manifest-path", str(manifest)],
            env=env, check=True,
        )
        if not args.test_abi:
            destination = args.output / abi
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.target_dir / target / "release" / "libtelegramws_core.so",
                            destination / "libtelegramws_core.so")

    if args.licenses and not args.test_abi:
        write_notices(cargo, manifest, args.licenses)


if __name__ == "__main__":
    main()
