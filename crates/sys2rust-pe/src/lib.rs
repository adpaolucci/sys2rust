#![forbid(unsafe_code)]

pub mod dotnet;
pub mod exports;
pub mod fixture;
pub mod gac;
pub mod icons;
pub mod pe;
pub mod providers;
pub mod resources;
pub mod version_cert;

use std::path::PathBuf;
use std::sync::Arc;

use guap_table::TableProvider;

pub use providers::{
    PeDotNetProvider, PeExportsProvider, PeGacProvider, PeIconsProvider, PeInfoProvider, PeResourcesProvider,
    PeTargetSource,
};

pub fn all_pe_providers(source: Arc<PeTargetSource>) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(PeExportsProvider::new(Arc::clone(&source))),
        Arc::new(PeResourcesProvider::new(Arc::clone(&source))),
        Arc::new(PeIconsProvider::new(Arc::clone(&source))),
        Arc::new(PeDotNetProvider::new(Arc::clone(&source))),
        Arc::new(PeInfoProvider::new(Arc::clone(&source))),
        Arc::new(PeGacProvider::new(source)),
    ]
}

pub fn default_pe_source(target: Option<PathBuf>, gac_root: Option<PathBuf>) -> Arc<PeTargetSource> {
    let resolved_target = target.or_else(|| std::env::current_exe().ok());
    Arc::new(PeTargetSource::FileOrDir {
        target: resolved_target,
        gac_root,
    })
}
