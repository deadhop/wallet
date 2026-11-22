//! The binary itself: arguments and environment reach the library.

use std::process::Command;

#[test]
fn the_binary_runs_and_reports_errors() {
    let dir = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_deadhop-wallet");
    let status = Command::new(bin)
        .arg("status")
        .env("DEADHOP_WALLET_STATE_DIR", dir.path())
        .env("DEADHOP_LOG", "off")
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(String::from_utf8_lossy(&status.stdout), "no sweeps yet\n");
    let bad = Command::new(bin)
        .arg("bogus")
        .env("DEADHOP_LOG", "off")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("usage: deadhop-wallet"));
}
