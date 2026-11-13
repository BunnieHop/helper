use bunniehop_helper::uploaders::bluesky::tid_for;
use serde_json::Value;

#[test]
fn bluesky_record_key_matches_the_browser_engine() {
  // Read at run time: the published Helper tree has the fixture under fixtures/sidecar-cross and
  // no monorepo around it, so a compile-time include would break its build.
  let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
  let mono = root.join("../../packages/sidecar/fixtures/cross");
  let dir = if mono.is_dir() {
    mono
  } else {
    root.join("fixtures/sidecar-cross")
  };
  let fixture: Value =
    serde_json::from_str(&std::fs::read_to_string(dir.join("bluesky-tids.json")).unwrap()).unwrap();
  for case in fixture.as_array().unwrap() {
    assert_eq!(
      tid_for(
        case["date"].as_str(),
        case["key"].as_str().unwrap(),
        case["index"].as_u64().unwrap()
      ),
      case["tid"].as_str().unwrap()
    );
  }
}
