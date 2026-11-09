use bunniehop_helper::binaries::Binaries;
use bunniehop_helper::config::Paths;
use bunniehop_helper::connections::{Keychain, Store};
use bunniehop_helper::hops::Hub;
use bunniehop_helper::pairing::Pairing;
use bunniehop_helper::server::{
  allowed_origins, bind, router, system_opener, AppState, Tooling, PAIR_PAGE,
};
use bunniehop_helper::uploaders::{client, registry, Endpoints};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
  // Logs never include URLs, titles, tokens or argv (PLAN ground rules).
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_env("BUNNIEHOP_LOG")
        .unwrap_or_else(|_| "info".into()),
    )
    .init();
  let paths = Paths::system();
  paths.ensure()?;
  let dev = cfg!(debug_assertions) || std::env::var_os("BUNNIEHOP_DEV_ORIGINS").is_some();
  let (listener, port) = bind().await?;
  let connections = Arc::new(Store::open(
    paths.data_dir.join("connections.json"),
    Box::new(Keychain),
  ));
  let http = client();
  let endpoints = Endpoints::default();
  let tools = Arc::new(Tooling::new(
    Binaries::new(paths.data_dir.join("bin")),
    true,
  ));
  let hub = Hub::new(
    paths.data_dir.join("hops"),
    paths.temp_dir.clone(),
    paths.vault_dir.clone(),
    tools.clone(),
    registry(connections.clone(), http.clone(), endpoints.clone()),
  );
  hub.set_remotes(bunniehop_helper::cloud::remotes(
    connections.clone(),
    http.clone(),
    endpoints.clone(),
  ));
  {
    let store = connections.clone();
    hub.set_accounts(Arc::new(move |platform: &str, id: &str| {
      store
        .get(id)
        .filter(|c| c.platform == platform)
        .map(|c| c.account)
    }));
  }
  let resumed = hub.restore();
  if !resumed.is_empty() {
    tracing::info!(count = resumed.len(), "resumed hops from the last run");
  }
  let state = AppState {
    pairing: Arc::new(Pairing::open(paths.data_dir.join("pairings.json"))),
    origins: Arc::new(allowed_origins(dev)),
    port,
    vault_dir: paths.vault_dir.clone(),
    show_code: {
      let open = system_opener();
      Arc::new(move |code: &str| {
        eprintln!("\n  BunnieHop pairing code: {code}\n  Type it on bunniehop.party. It expires in 5 minutes.\n");
        // No terminal needed: the Helper's own page shows the code (the URL carries no secret).
        open(&format!("http://127.0.0.1:{port}{PAIR_PAGE}"));
      })
    },
    tools,
    hub,
    connections,
    http,
    endpoints,
    open_url: system_opener(),
    oauth: Arc::default(),
    pending: Arc::default(),
  };
  tracing::info!(
    port,
    "BunnieHop Helper {} listening on 127.0.0.1",
    bunniehop_helper::VERSION
  );
  axum::serve(listener, router(state)).await
}
