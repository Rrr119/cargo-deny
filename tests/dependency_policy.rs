use cargo_deny::{
    Deserialize, Krates, SerializeAdvisory as SA,
    advisories::{self, DbSet, Fetch, cfg as advisories_cfg},
    cfg::Scope,
    field_eq,
    licenses::{self, LicenseStore, cfg::Config as LicensesConfig},
    root_cfg::RootConfig,
    test_utils as tu,
};
use serde_json::{Value, json};
use std::{
    process::Command,
    sync::{Arc, OnceLock},
};

const CRATE_COUNT: usize = 100;
const ADVISORY_ID: &str = "RUSTSEC-2099-0001";
const ADVISORY_DATE: jiff::civil::Date = jiff::civil::date(2026, 1, 1);
const CRATES_IO: &str = "https://github.com/rust-lang/crates.io-index";

fn policy_text() -> String {
    std::fs::read_to_string("deny.toml").expect("failed to read deny.toml")
}

fn load_policy(text: &str) -> RootConfig {
    let mut parsed = toml_span::parse(text).expect("failed to parse deny.toml");
    RootConfig::deserialize(&mut parsed).expect("failed to deserialize deny.toml")
}

fn package_id(name: &str) -> String {
    format!("registry+{CRATES_IO}#{name}@0.1.0")
}

fn package(name: &str, license: &str, source: Value) -> Value {
    json!({
        "name": name,
        "version": "0.1.0",
        "id": package_id(name),
        "source": source,
        "license": license,
        "license_file": null,
        "description": null,
        "dependencies": [],
        "targets": [{
            "kind": ["lib"],
            "crate_types": ["lib"],
            "name": name.replace('-', "_"),
            "src_path": format!("/tmp/cargo-deny-policy/{name}/src/lib.rs"),
            "edition": "2021",
            "doc": true,
            "doctest": true,
            "test": true
        }],
        "features": {},
        "manifest_path": format!("/tmp/cargo-deny-policy/{name}/Cargo.toml"),
        "authors": [],
        "categories": [],
        "keywords": [],
        "readme": null,
        "repository": null,
        "homepage": null,
        "documentation": null,
        "edition": "2021",
        "metadata": null,
        "links": null,
        "publish": null,
        "default_run": null,
        "rust_version": null
    })
}

fn policy_graph(licenses: &[String]) -> Krates {
    let root_id = "path+file:///tmp/cargo-deny-policy#policy-root@0.1.0";
    let mut packages = Vec::with_capacity(CRATE_COUNT);
    let mut nodes = Vec::with_capacity(CRATE_COUNT);
    let mut dependencies = Vec::with_capacity(CRATE_COUNT - 1);
    let mut node_dependencies = Vec::with_capacity(CRATE_COUNT - 1);
    let mut package_dependencies = Vec::with_capacity(CRATE_COUNT - 1);

    packages.push(json!({
        "name": "policy-root",
        "version": "0.1.0",
        "id": root_id,
        "source": null,
        "license": "MIT",
        "license_file": null,
        "description": null,
        "dependencies": [],
        "targets": [{
            "kind": ["lib"],
            "crate_types": ["lib"],
            "name": "policy_root",
            "src_path": "/tmp/cargo-deny-policy/src/lib.rs",
            "edition": "2021",
            "doc": true,
            "doctest": true,
            "test": true
        }],
        "features": {},
        "manifest_path": "/tmp/cargo-deny-policy/Cargo.toml",
        "authors": [],
        "categories": [],
        "keywords": [],
        "readme": null,
        "repository": null,
        "homepage": null,
        "documentation": null,
        "edition": "2021",
        "metadata": null,
        "links": null,
        "publish": null,
        "default_run": null,
        "rust_version": null
    }));

    for index in 1..CRATE_COUNT {
        let name = if index == 1 {
            "zstd-sys".to_owned()
        } else {
            format!("policy-crate-{index:03}")
        };
        let license = if index == 1 {
            "BSD-2-Clause"
        } else {
            &licenses[(index - 2) % licenses.len()]
        };
        let id = package_id(&name);

        packages.push(package(
            &name,
            license,
            json!(format!("registry+{CRATES_IO}")),
        ));
        dependencies.push(Value::String(id.clone()));
        package_dependencies.push(json!({
            "name": name,
            "source": format!("registry+{CRATES_IO}"),
            "req": "=0.1.0",
            "kind": null,
            "optional": false,
            "uses_default_features": true,
            "features": [],
            "target": null,
            "rename": null,
            "registry": null,
            "path": null
        }));
        node_dependencies.push(json!({
            "name": name,
            "pkg": id,
            "dep_kinds": [{
                "kind": "normal",
                "target": null
            }]
        }));
        nodes.push(json!({
            "id": id,
            "dependencies": [],
            "deps": [],
            "features": []
        }));
    }

    packages[0]["dependencies"] = Value::Array(package_dependencies);
    nodes.insert(
        0,
        json!({
            "id": root_id,
            "dependencies": dependencies,
            "deps": node_dependencies,
            "features": []
        }),
    );

    let metadata = json!({
        "packages": packages,
        "workspace_members": [root_id],
        "workspace_default_members": [root_id],
        "resolve": {
            "nodes": nodes,
            "root": root_id
        },
        "workspace_root": "/tmp/cargo-deny-policy",
        "target_directory": "/tmp/cargo-deny-policy/target",
        "version": 1
    });

    let metadata: krates::cm::Metadata =
        serde_json::from_value(metadata).expect("failed to deserialize synthetic metadata");
    krates::Builder::new()
        .build_with_metadata(metadata, krates::NoneFilter)
        .expect("failed to build synthetic crate graph")
}

fn license_store() -> Arc<LicenseStore> {
    static STORE: OnceLock<Arc<LicenseStore>> = OnceLock::new();
    STORE
        .get_or_init(|| Arc::new(LicenseStore::from_cache().unwrap()))
        .clone()
}

fn license_diagnostics(krates: &Krates, cfg: LicensesConfig, text: &str) -> Vec<Value> {
    let cfg = tu::Config {
        deserialized: cfg,
        config: text.to_owned(),
    };
    let mut ctx = tu::setup(krates, cargo_deny::func_name!(), cfg);
    let gatherer = licenses::Gatherer::default()
        .with_store(license_store())
        .with_confidence_threshold(ctx.valid_cfg.confidence_threshold);
    let summary = gatherer.gather(ctx.krates, &mut ctx.files, &ctx.valid_cfg);

    tu::run_gather(ctx, |ctx, tx| {
        licenses::check(ctx, summary, tx.into());
    })
}

fn advisory_diagnostics(
    krates: &Krates,
    cfg: advisories_cfg::Config,
    text: &str,
    dbs: &DbSet,
) -> Vec<Value> {
    let cfg = tu::Config {
        deserialized: cfg,
        config: text.to_owned(),
    };

    tu::gather_diagnostics::<advisories_cfg::Config, _, _>(
        krates,
        cargo_deny::func_name!(),
        cfg,
        |ctx, tx| {
            advisories::check(
                ctx,
                dbs,
                Option::<advisories::NoneReporter>::None,
                SA::Json,
                None,
                tx,
                ADVISORY_DATE,
            );
        },
    )
}

fn errors(diags: &[Value]) -> Vec<&Value> {
    diags
        .iter()
        .filter(|diag| field_eq!(diag, "/fields/severity", "error"))
        .collect()
}

fn run(command: &mut Command) {
    let status = command.status().expect("failed to run command");
    assert!(status.success(), "command failed with {status}");
}

fn advisory_dbs() -> (tempfile::TempDir, DbSet) {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("advisory-db");
    let advisory_dir = repo.join("crates/policy-crate-002");
    std::fs::create_dir_all(&advisory_dir).unwrap();
    std::fs::write(
        advisory_dir.join(format!("{ADVISORY_ID}.md")),
        format!(
            r#"```toml
[advisory]
id = "{ADVISORY_ID}"
package = "policy-crate-002"
date = "2025-01-01"
url = "https://example.com/{ADVISORY_ID}"

[versions]
patched = [">= 0.1.1"]
```

# Test advisory

Used to verify that the dependency policy gates advisories.
"#
        ),
    )
    .unwrap();

    run(Command::new("git")
        .args(["init", "-q", "--initial-branch=main"])
        .arg(&repo));
    run(Command::new("git").arg("-C").arg(&repo).args(["add", "-A"]));
    run(Command::new("git").arg("-C").arg(&repo).args([
        "-c",
        "user.name=cargo-deny tests",
        "-c",
        "user.email=cargo-deny@example.com",
        "commit",
        "-q",
        "-m",
        "test advisory",
    ]));

    let url = url::Url::from_file_path(&repo).unwrap();
    let db_root = cargo_deny::PathBuf::from_path_buf(root.path().join("dbs")).unwrap();
    let dbs = DbSet::load(db_root, vec![url], Fetch::Allow).unwrap();
    (root, dbs)
}

#[test]
fn license_policy_checks_100_crates_and_honors_exception() {
    let text = policy_text();
    let mut policy = load_policy(&text);
    let licenses = policy.licenses.take().expect("missing [licenses] policy");

    let allowed: Vec<_> = licenses
        .allow
        .iter()
        .map(|license| license.0.value.to_string())
        .collect();
    assert!(allowed.iter().any(|license| license == "MIT"));
    assert!(allowed.iter().any(|license| license == "Apache-2.0"));
    let zstd_exception = licenses
        .exceptions
        .iter()
        .find(|exception| exception.spec.name.value == "zstd-sys")
        .expect("missing zstd-sys license exception");
    assert!(
        zstd_exception
            .allow
            .iter()
            .any(|license| license.0.value.to_string() == "BSD-2-Clause")
    );

    let krates = policy_graph(&allowed);
    assert_eq!(krates.len(), CRATE_COUNT);

    let diags = license_diagnostics(&krates, licenses, &text);
    assert!(
        errors(&diags).is_empty(),
        "100-crate license policy failed:\n{}",
        serde_json::to_string_pretty(&diags).unwrap()
    );

    let mut without_exception = load_policy(&text)
        .licenses
        .expect("missing [licenses] policy");
    without_exception.exceptions.clear();

    let diags = license_diagnostics(&krates, without_exception, &text);
    let errors = errors(&diags);
    assert!(
        errors.iter().any(|diag| {
            field_eq!(diag, "/fields/graphs/0/Krate/name", "zstd-sys")
                && field_eq!(diag, "/fields/code", "rejected")
        }),
        "removing the zstd-sys exception did not reject BSD-2-Clause:\n{}",
        serde_json::to_string_pretty(&diags).unwrap()
    );
}

#[test]
fn advisory_policy_checks_100_crates_and_honors_exception() {
    let text = policy_text();
    let mut policy = load_policy(&text);
    let advisories = policy
        .advisories
        .take()
        .expect("missing [advisories] policy");

    assert!(matches!(advisories.unmaintained.value, Scope::All));
    assert!(matches!(advisories.unsound.value, Scope::All));
    assert_eq!(advisories.yanked.value, cargo_deny::LintLevel::Deny);

    let license = vec!["MIT".to_owned()];
    let krates = policy_graph(&license);
    assert_eq!(krates.len(), CRATE_COUNT);

    let (_db_root, dbs) = advisory_dbs();
    assert!(
        dbs.has_advisory(ADVISORY_ID),
        "test advisory database did not load {ADVISORY_ID}: {dbs:#?}"
    );
    let diags = advisory_diagnostics(&krates, advisories, &text, &dbs);
    let advisory_errors = errors(&diags);
    assert_eq!(
        advisory_errors.len(),
        1,
        "100-crate advisory policy did not gate the test advisory:\n{}",
        serde_json::to_string_pretty(&diags).unwrap()
    );
    assert!(field_eq!(
        advisory_errors[0],
        "/fields/graphs/0/Krate/name",
        "policy-crate-002"
    ));

    let exempted_text = text.replacen("ignore = []", &format!("ignore = [\"{ADVISORY_ID}\"]"), 1);
    assert_ne!(exempted_text, text, "failed to add advisory exemption");
    let advisories = load_policy(&exempted_text)
        .advisories
        .expect("missing [advisories] policy");

    let diags = advisory_diagnostics(&krates, advisories, &exempted_text, &dbs);
    assert!(
        errors(&diags).is_empty(),
        "advisory exemption did not suppress {ADVISORY_ID}:\n{}",
        serde_json::to_string_pretty(&diags).unwrap()
    );
    assert!(
        diags
            .iter()
            .any(|diag| field_eq!(diag, "/fields/code", "advisory-ignored")),
        "advisory exemption did not emit an ignored diagnostic"
    );
}
