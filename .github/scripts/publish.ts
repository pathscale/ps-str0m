const packages = new Map([
  ["crates/proto/Cargo.toml", "ps-str0m-proto"],
  ["crates/is/Cargo.toml", "ps-str0m-is"],
  ["crypto/rust-crypto/Cargo.toml", "ps-str0m-rust-crypto"],
  ["Cargo.toml", "ps-str0m"],
]);

const manifestPath = Bun.argv[2];
const expectedName = packages.get(manifestPath);
if (!expectedName || Bun.argv.length !== 3) {
  throw new Error("Pass exactly one production package manifest from the publish workflow");
}

const manifest = Bun.TOML.parse(await Bun.file(manifestPath).text());
const pkg = manifest.package as { name?: string; version?: string; publish?: boolean };
if (!pkg || pkg.name !== expectedName || typeof pkg.version !== "string" || pkg.publish === false) {
  throw new Error(`Invalid publication manifest: ${manifestPath}`);
}

const name = pkg.name;
const version = pkg.version;
const url = `https://crates.io/api/v1/crates/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
const response = await fetch(url, {
  headers: {
    Accept: "application/json",
    "User-Agent": "ps-str0m-publish (https://github.com/pathscale/ps-str0m)",
  },
  signal: AbortSignal.timeout(30_000),
});

if (response.status === 200) {
  const published = (await response.json()) as {
    version?: { crate?: string; num?: string; yanked?: boolean };
  };
  if (
    published.version?.crate !== name ||
    published.version?.num !== version ||
    published.version?.yanked !== false
  ) {
    throw new Error(`Registry returned unexpected or yanked metadata for ${name} ${version}`);
  }
  console.log(`${name} ${version} is already published; skipping`);
} else if (response.status === 404) {
  if (!Bun.env.CARGO_REGISTRY_TOKEN) {
    throw new Error("CARGO_REGISTRY_TOKEN is required to publish a missing version");
  }
  console.log(`Publishing ${name} ${version}`);
  const child = Bun.spawn(["cargo", "publish", "-p", name], {
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  const status = await child.exited;
  if (status !== 0) process.exit(status);
} else {
  throw new Error(`Registry lookup failed for ${name} ${version}: HTTP ${response.status}`);
}
