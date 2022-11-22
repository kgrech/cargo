use crate::core::compiler::{CompileKind, RustcTargetData};
use crate::core::dependency::DepKind;
use crate::core::resolver::{CliFeatures, ForceAllTargets, HasDevUnits};
use crate::core::shell::Verbosity;
use crate::core::{GitReference, Package, PackageId, PackageSet, Resolve, Workspace};
use crate::ops;
use crate::ops::tree::graph::{Graph, GraphOptions};
use crate::ops::tree::{EdgeKind, Node, Target};
use crate::ops::Packages;
use crate::sources::path::PathSource;
use crate::sources::CRATES_IO_REGISTRY;
use crate::util::{CargoResult, Config};
use anyhow::{bail, Context as _};
use cargo_util::{paths, Sha256};
use serde::Serialize;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use toml_edit::easy as toml;

pub struct VendorOptions<'a> {
    pub cli_features: CliFeatures,
    pub no_delete: bool,
    pub versioned_dirs: bool,
    pub destination: &'a Path,
    pub extra: Vec<PathBuf>,
    pub edge_kinds: HashSet<EdgeKind>,
}

pub fn vendor(ws: &Workspace<'_>, opts: &VendorOptions<'_>) -> CargoResult<()> {
    let config = ws.config();
    let mut extra_workspaces = Vec::new();
    for extra in opts.extra.iter() {
        let extra = config.cwd().join(extra);
        let ws = Workspace::new(&extra, config)?;
        extra_workspaces.push(ws);
    }
    let workspaces = extra_workspaces.iter().chain(Some(ws)).collect::<Vec<_>>();
    let vendor_config = sync(config, &workspaces, opts).with_context(|| "failed to sync")?;

    if config.shell().verbosity() != Verbosity::Quiet {
        if vendor_config.source.is_empty() {
            crate::drop_eprintln!(config, "There is no dependency to vendor in this project.");
        } else {
            crate::drop_eprint!(
                config,
                "To use vendored sources, add this to your .cargo/config.toml for this project:\n\n"
            );
            crate::drop_print!(
                config,
                "{}",
                &toml::to_string_pretty(&vendor_config).unwrap()
            );
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct VendorConfig {
    source: BTreeMap<String, VendorSource>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase", untagged)]
enum VendorSource {
    Directory {
        directory: String,
    },
    Registry {
        registry: Option<String>,
        #[serde(rename = "replace-with")]
        replace_with: String,
    },
    Git {
        git: String,
        branch: Option<String>,
        tag: Option<String>,
        rev: Option<String>,
        #[serde(rename = "replace-with")]
        replace_with: String,
    },
}

fn sync(
    config: &Config,
    workspaces: &[&Workspace<'_>],
    opts: &VendorOptions<'_>,
) -> CargoResult<VendorConfig> {
    let canonical_destination = opts.destination.canonicalize();
    let canonical_destination = canonical_destination.as_deref().unwrap_or(opts.destination);
    let dest_dir_already_exists = canonical_destination.exists();

    paths::create_dir_all(&canonical_destination)?;
    let mut to_remove = HashSet::new();
    if !opts.no_delete {
        for entry in canonical_destination.read_dir()? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_str()
                .map_or(false, |s| s.starts_with('.'))
            {
                to_remove.insert(entry.path());
            }
        }
    }

    // First up attempt to work around rust-lang/cargo#5956. Apparently build
    // artifacts sprout up in Cargo's global cache for whatever reason, although
    // it's unsure what tool is causing these issues at this time. For now we
    // apply a heavy-hammer approach which is to delete Cargo's unpacked version
    // of each crate to start off with. After we do this we'll re-resolve and
    // redownload again, which should trigger Cargo to re-extract all the
    // crates.
    //
    // Note that errors are largely ignored here as this is a best-effort
    // attempt. If anything fails here we basically just move on to the next
    // crate to work with.
    for ws in workspaces {
        let (packages, resolve) =
            ops::resolve_ws(ws).with_context(|| "failed to load pkg lockfile")?;

        packages
            .get_many(resolve.iter())
            .with_context(|| "failed to download packages")?;

        for pkg in resolve.iter() {
            // Don't delete actual source code!
            if pkg.source_id().is_path() {
                if let Ok(path) = pkg.source_id().url().to_file_path() {
                    if let Ok(path) = path.canonicalize() {
                        to_remove.remove(&path);
                    }
                }
                continue;
            }
            if pkg.source_id().is_git() {
                continue;
            }
            if let Ok(pkg) = packages.get_one(pkg) {
                drop(fs::remove_dir_all(pkg.manifest_path().parent().unwrap()));
            }
        }
    }

    let mut checksums = HashMap::new();
    let mut ids = BTreeMap::new();

    // Next up let's actually download all crates and start storing internal
    // tables about them.
    for ws in workspaces {
        // TODO: Derive it from CLI flags like cargo tree does
        let requested_targets = vec![
            "x86_64-apple-darwin".to_string(),
            "armv7-linux-androideabi".to_string(),
            "i686-linux-android".to_string(),
            "aarch64-linux-android".to_string(),
            "x86_64-linux-android".to_string(),
            "x86_64-linux-android".to_string(),
            "x86_64-linux-android".to_string(),
            "aarch64-apple-ios".to_string(),
            "aarch64-apple-ios-sim".to_string(),
            "x86_64-apple-ios".to_string(),
        ];
        let requested_kinds = CompileKind::from_requested_targets(ws.config(), &requested_targets)?;
        let target_data = RustcTargetData::new(ws, &requested_kinds)?;
        let specs = Packages::Default.to_package_id_specs(ws)?;
        let has_dev = HasDevUnits::Yes;
        let force_all = ForceAllTargets::No;

        let graph_options = GraphOptions {
            target: Target::Specific(requested_targets),
            graph_features: false,
            edge_kinds: opts.edge_kinds.clone(),
        };

        let ws_resolve = ops::resolve_ws_with_opts(
            ws,
            &target_data,
            &requested_kinds,
            &opts.cli_features,
            &specs,
            has_dev,
            force_all,
        )
        .with_context(|| "failed to load pkg lockfile")?;
        println!(
            "Resolved returned {}/{} packages with {} targets",
            ws_resolve.pkg_set.packages().count(),
            ws_resolve.pkg_set.package_ids().count(),
            ws_resolve.targeted_resolve.iter().count()
        );

        let package_map: HashMap<PackageId, &Package> = ws_resolve
            .pkg_set
            .packages()
            .map(|pkg| (pkg.package_id(), pkg))
            .collect();

        println!("Collected the package map of size {}", package_map.len());

        // TODO: Should not depend on tree here
        let mut graph = ops::tree::graph::build(
            ws,
            &ws_resolve.targeted_resolve,
            &ws_resolve.resolved_features,
            &specs,
            &opts.cli_features,
            &target_data,
            &requested_kinds,
            package_map,
            &graph_options,
        )?;
        let root_ids = ws_resolve.targeted_resolve.specs_to_ids(&specs)?;
        let root_indexes = graph.indexes_from_ids(&root_ids);

        ws_resolve
            .pkg_set
            .get_many(ws_resolve.targeted_resolve.iter())
            .with_context(|| "failed to download packages")?;

        println!(
            "Resolved package number of download is {}",
            ws_resolve.pkg_set.packages().count()
        );

        traverse_graph(
            &mut ids,
            &mut checksums,
            &ws_resolve.pkg_set,
            &ws_resolve.targeted_resolve,
            root_indexes,
            &graph,
        );
    }
    println!("Collected if map of size {}", ids.len());

    let mut versions = HashMap::new();
    for id in ids.keys() {
        let map = versions.entry(id.name()).or_insert_with(BTreeMap::default);
        if let Some(prev) = map.get(&id.version()) {
            bail!(
                "found duplicate version of package `{} v{}` \
                 vendored from two sources:\n\
                 \n\
                 \tsource 1: {}\n\
                 \tsource 2: {}",
                id.name(),
                id.version(),
                prev,
                id.source_id()
            );
        }
        map.insert(id.version(), id.source_id());
    }

    let mut sources = BTreeSet::new();
    let mut tmp_buf = [0; 64 * 1024];
    for (id, pkg) in ids.iter() {
        // Next up, copy it to the vendor directory
        let src = pkg
            .manifest_path()
            .parent()
            .expect("manifest_path should point to a file");
        let max_version = *versions[&id.name()].iter().rev().next().unwrap().0;
        let dir_has_version_suffix = opts.versioned_dirs || id.version() != max_version;
        let dst_name = if dir_has_version_suffix {
            // Eg vendor/futures-0.1.13
            format!("{}-{}", id.name(), id.version())
        } else {
            // Eg vendor/futures
            id.name().to_string()
        };

        sources.insert(id.source_id());
        let dst = canonical_destination.join(&dst_name);
        to_remove.remove(&dst);
        let cksum = dst.join(".cargo-checksum.json");
        if dir_has_version_suffix && cksum.exists() {
            // Always re-copy directory without version suffix in case the version changed
            continue;
        }

        config.shell().status(
            "Vendoring",
            &format!("{} ({}) to {}", id, src.to_string_lossy(), dst.display()),
        )?;

        let _ = fs::remove_dir_all(&dst);
        let pathsource = PathSource::new(src, id.source_id(), config);
        let paths = pathsource.list_files(pkg)?;
        let mut map = BTreeMap::new();
        cp_sources(src, &paths, &dst, &mut map, &mut tmp_buf)
            .with_context(|| format!("failed to copy over vendored sources for: {}", id))?;

        // Finally, emit the metadata about this package
        let json = serde_json::json!({
            "package": checksums.get(id),
            "files": map,
        });

        paths::write(&cksum, json.to_string())?;
    }

    for path in to_remove {
        if path.is_dir() {
            paths::remove_dir_all(&path)?;
        } else {
            paths::remove_file(&path)?;
        }
    }

    // add our vendored source
    let mut config = BTreeMap::new();

    let merged_source_name = "vendored-sources";

    // replace original sources with vendor
    for source_id in sources {
        let name = if source_id.is_crates_io() {
            CRATES_IO_REGISTRY.to_string()
        } else {
            source_id.url().to_string()
        };

        let source = if source_id.is_crates_io() {
            VendorSource::Registry {
                registry: None,
                replace_with: merged_source_name.to_string(),
            }
        } else if source_id.is_remote_registry() {
            let registry = source_id.url().to_string();
            VendorSource::Registry {
                registry: Some(registry),
                replace_with: merged_source_name.to_string(),
            }
        } else if source_id.is_git() {
            let mut branch = None;
            let mut tag = None;
            let mut rev = None;
            if let Some(reference) = source_id.git_reference() {
                match *reference {
                    GitReference::Branch(ref b) => branch = Some(b.clone()),
                    GitReference::Tag(ref t) => tag = Some(t.clone()),
                    GitReference::Rev(ref r) => rev = Some(r.clone()),
                    GitReference::DefaultBranch => {}
                }
            }
            VendorSource::Git {
                git: source_id.url().to_string(),
                branch,
                tag,
                rev,
                replace_with: merged_source_name.to_string(),
            }
        } else {
            panic!("Invalid source ID: {}", source_id)
        };
        config.insert(name, source);
    }

    if !config.is_empty() {
        config.insert(
            merged_source_name.to_string(),
            VendorSource::Directory {
                // Windows-flavour paths are valid here on Windows but Unix.
                // This backslash normalization is for making output paths more
                // cross-platform compatible.
                directory: opts.destination.to_string_lossy().replace("\\", "/"),
            },
        );
    } else if !dest_dir_already_exists {
        // Nothing to vendor. Remove the destination dir we've just created.
        paths::remove_dir(canonical_destination)?;
    }

    Ok(VendorConfig { source: config })
}

fn cp_sources(
    src: &Path,
    paths: &[PathBuf],
    dst: &Path,
    cksums: &mut BTreeMap<String, String>,
    tmp_buf: &mut [u8],
) -> CargoResult<()> {
    for p in paths {
        let relative = p.strip_prefix(&src).unwrap();

        match relative.to_str() {
            // Skip git config files as they're not relevant to builds most of
            // the time and if we respect them (e.g.  in git) then it'll
            // probably mess with the checksums when a vendor dir is checked
            // into someone else's source control
            Some(".gitattributes") | Some(".gitignore") | Some(".git") => continue,

            // Temporary Cargo files
            Some(".cargo-ok") => continue,

            // Skip patch-style orig/rej files. Published crates on crates.io
            // have `Cargo.toml.orig` which we don't want to use here and
            // otherwise these are rarely used as part of the build process.
            Some(filename) => {
                if filename.ends_with(".orig") || filename.ends_with(".rej") {
                    continue;
                }
            }
            _ => {}
        };

        // Join pathname components individually to make sure that the joined
        // path uses the correct directory separators everywhere, since
        // `relative` may use Unix-style and `dst` may require Windows-style
        // backslashes.
        let dst = relative
            .iter()
            .fold(dst.to_owned(), |acc, component| acc.join(&component));

        paths::create_dir_all(dst.parent().unwrap())?;

        let cksum = copy_and_checksum(p, &dst, tmp_buf)?;
        cksums.insert(relative.to_str().unwrap().replace("\\", "/"), cksum);
    }
    Ok(())
}

fn traverse_graph(
    ids: &mut BTreeMap<PackageId, Package>,
    checksums: &mut HashMap<PackageId, Option<Option<String>>>,
    packages: &PackageSet,
    resolve: &Resolve,
    roots: Vec<usize>,
    graph: &Graph<'_>,
) {
    let mut visited_deps = HashSet::new();
    for root_index in roots.into_iter() {
        visit_node(
            ids,
            checksums,
            packages,
            resolve,
            root_index,
            &mut visited_deps,
            graph,
        );
    }
}

fn visit_node(
    ids: &mut BTreeMap<PackageId, Package>,
    checksums: &mut HashMap<PackageId, Option<Option<String>>>,
    packages: &PackageSet,
    resolve: &Resolve,
    node_index: usize,
    visited_deps: &mut HashSet<usize>,
    graph: &Graph<'_>,
) {
    if !visited_deps.insert(node_index) {
        return;
    }
    let node = graph.node(node_index);
    let package_id = match node {
        Node::Package { package_id, .. } => package_id,
        Node::Feature { node_index, .. } => {
            let for_node = graph.node(*node_index);
            match for_node {
                Node::Package { package_id, .. } => package_id,
                // The node_index in Node::Feature must point to a package
                // node, see `add_feature`.
                _ => panic!("unexpected feature node {:?}", for_node),
            }
        }
    }
    .clone();
    // No need to vendor path crates since they're already in the
    // repository
    if !package_id.source_id().is_path() {
        ids.insert(
            package_id.clone(),
            packages
                .get_one(package_id)
                .expect("failed to fetch package")
                .clone(),
        );
        checksums.insert(package_id, resolve.checksums().get(&package_id).cloned());
    }

    for kind in &[
        EdgeKind::Dep(DepKind::Normal),
        EdgeKind::Dep(DepKind::Build),
        EdgeKind::Dep(DepKind::Development),
        EdgeKind::Feature,
    ] {
        visit_dependencies(
            ids,
            checksums,
            packages,
            resolve,
            node_index,
            visited_deps,
            graph,
            kind,
        );
    }
}

fn visit_dependencies(
    ids: &mut BTreeMap<PackageId, Package>,
    checksums: &mut HashMap<PackageId, Option<Option<String>>>,
    packages: &PackageSet,
    resolve: &Resolve,
    node_index: usize,
    visited_deps: &mut HashSet<usize>,
    graph: &Graph<'_>,
    kind: &EdgeKind,
) {
    let deps = graph.connected_nodes(node_index, kind);
    if deps.is_empty() {
        return;
    }
    // TODO: Filter out packages to prune.
    let mut it = deps.iter();
    while let Some(node_index) = it.next() {
        visit_node(
            ids,
            checksums,
            packages,
            resolve,
            *node_index,
            visited_deps,
            graph,
        );
    }
}

fn copy_and_checksum(src_path: &Path, dst_path: &Path, buf: &mut [u8]) -> CargoResult<String> {
    let mut src = File::open(src_path).with_context(|| format!("failed to open {:?}", src_path))?;
    let mut dst_opts = OpenOptions::new();
    dst_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let src_metadata = src
            .metadata()
            .with_context(|| format!("failed to stat {:?}", src_path))?;
        dst_opts.mode(src_metadata.mode());
    }
    let mut dst = dst_opts
        .open(dst_path)
        .with_context(|| format!("failed to create {:?}", dst_path))?;
    // Not going to bother setting mode on pre-existing files, since there
    // shouldn't be any under normal conditions.
    let mut cksum = Sha256::new();
    loop {
        let n = src
            .read(buf)
            .with_context(|| format!("failed to read from {:?}", src_path))?;
        if n == 0 {
            break Ok(cksum.finish_hex());
        }
        let data = &buf[..n];
        cksum.update(data);
        dst.write_all(data)
            .with_context(|| format!("failed to write to {:?}", dst_path))?;
    }
}
