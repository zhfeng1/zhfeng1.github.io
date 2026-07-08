export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      return textResponse(`Worker error: ${err && err.stack ? err.stack : String(err)}`, 500);
    }
  }
};

const DOCKER_HUB_REGISTRY = {
  name: "dockerhub",
  aliases: new Set(["docker.io", "registry-1.docker.io", "index.docker.io"]),
  registryOrigin: "https://registry-1.docker.io",
  tokenUrl: "https://auth.docker.io/token",
  service: "registry.docker.io",
  autoLibraryNamespace: true
};

const GHCR_REGISTRY = {
  name: "ghcr",
  aliases: new Set(["ghcr.io"]),
  registryOrigin: "https://ghcr.io",
  tokenUrl: "https://ghcr.io/token",
  service: "ghcr.io",
  autoLibraryNamespace: false
};

const ALL_REGISTRIES = [GHCR_REGISTRY, DOCKER_HUB_REGISTRY];

// KV keys. AUTH_KV is preferred; WHITELIST_KV is also supported for your existing binding.
const DOCKERHUB_FALLBACK_BASIC_KV_KEY = "dockerhub:fallback_basic";
const DOCKERHUB_TOKEN_KV_PREFIX = "dockerhub:token:";
const DOCKERHUB_TOKEN_CACHE_SKEW_SECONDS = 60;

// Worker fallback credentials are used for every Docker Hub repository pull scope.
// Keep this Worker private-ish: a public proxy can spend your Docker Hub account quota.
const DOCKERHUB_FALLBACK_SCOPE_POLICY = "all-pull-scopes";

const AUTO_LIBRARY_NAMESPACE = true;
const MANIFEST_TAG_TTL = 1800;
const MANIFEST_DIGEST_TTL = 7 * 86400;
const BLOB_CACHE_TTL = 86400;

const CLIENT_IP_HEADER_NAMES = [
  "CF-Connecting-IP",
  "CF-Connecting-IPv6",
  "CF-Pseudo-IPv4",
  "True-Client-IP",
  "X-Real-IP",
  "X-Forwarded-For",
  "X-Original-Forwarded-For",
  "Forwarded",
  "Client-IP",
  "X-Client-IP",
  "X-Cluster-Client-IP",
  "Proxy-Client-IP",
  "WL-Proxy-Client-IP",
  "Fastly-Client-IP",
  "Fly-Client-IP",
  "X-Azure-ClientIP",
  "X-Azure-SocketIP",
  "X-Envoy-External-Address",
  "X-Forwarded-Host",
  "X-Forwarded-Proto",
  "X-Forwarded-Port",
  "Via"
];

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: buildCorsHeaders() });
  }

  if (url.pathname === "/admin") {
    return handleAdmin(request, env, url);
  }

  if (url.pathname === "/v2/auth") {
    return handleRegistryAuth(request, env, url);
  }

  if (url.pathname === "/v2" || url.pathname === "/v2/" || url.pathname.startsWith("/v2/")) {
    return handleDockerRegistry(request, env, ctx, url);
  }

  return textResponse([
    "Docker registry proxy is running.",
    "",
    "Pull examples:",
    `  docker pull ${url.hostname}/python:3.11-slim`,
    `  docker pull ${url.hostname}/library/python:3.11-slim`,
    `  docker pull ${url.hostname}/docker.io/library/python:3.11-slim`,
    `  docker pull ${url.hostname}/ghcr.io/owner/image:tag`,
    "",
    "Worker fallback Docker Hub auth:",
    "  POST /admin?otp=123456&dockerLogin=1  JSON: {\"username\":\"...\",\"password\":\"Docker Hub PAT\"}",
    "  GET  /admin?otp=123456&dockerStatus=1",
    "  GET  /admin?otp=123456&dockerClearTokens=1",
    "  GET  /admin?otp=123456&dockerLogout=1",
    "",
    "Client auth still works:",
    `  echo 'Docker Hub PAT' | docker login ${url.hostname} -u DOCKER_ID --password-stdin`
  ].join("\n"));
}

async function handleDockerRegistry(request, env, ctx, workerUrl) {
  const resolved = resolveRegistryTarget(workerUrl.pathname);

  if (resolved.isPing) {
    return handleRegistryPing(request, workerUrl);
  }

  const targetUrl = new URL(resolved.upstreamPathname + workerUrl.search, resolved.registry.registryOrigin);
  const cachePolicy = getRegistryCachePolicy(request, targetUrl, resolved.registry);

  if (cachePolicy) {
    return handleCachedRegistryRequest(request, env, ctx, workerUrl, targetUrl, resolved, cachePolicy);
  }

  const registryAuth = await getRegistryRequestAuth(request, env, targetUrl, resolved.registry);
  const response = await fetchRegistryWithManualRedirect(request, targetUrl, resolved.registry, registryAuth);
  const out = buildRegistryClientResponse(response, workerUrl, resolved);
  if (registryAuth && registryAuth.source) out.headers.set("X-Registry-Auth", registryAuth.source);
  return out;
}

function handleRegistryPing(request, workerUrl) {
  const headers = buildCorsHeaders();
  headers.set("Docker-Distribution-Api-Version", "registry/2.0");

  if (request.headers.has("Authorization")) {
    return new Response(null, { status: 200, headers });
  }

  headers.set("Www-Authenticate", `Bearer realm="${workerUrl.origin}/v2/auth",service="${DOCKER_HUB_REGISTRY.service}"`);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({
    errors: [{ code: "UNAUTHORIZED", message: "authentication required" }]
  }), { status: 401, headers });
}

async function handleCachedRegistryRequest(request, env, ctx, workerUrl, targetUrl, resolved, cachePolicy) {
  const cache = caches.default;
  const cacheKey = buildRegistryCacheKey(workerUrl, targetUrl, request, cachePolicy);
  const cached = await cache.match(cacheKey);

  if (cached) {
    const cachedForClient = request.method === "HEAD" ? responseWithoutBody(cached) : cached;
    const out = buildRegistryClientResponse(cachedForClient, workerUrl, resolved);
    out.headers.set("X-Registry-Cache", "HIT");
    out.headers.set("X-Registry-Auth", request.headers.has("Authorization") ? "client" : "cache");
    return out;
  }

  const upstreamRequest = cachePolicy.fetchAsGet ? cloneRequestWithMethod(request, "GET") : request;
  const registryAuth = await getRegistryRequestAuth(upstreamRequest, env, targetUrl, resolved.registry);
  const response = await fetchRegistryWithManualRedirect(upstreamRequest, targetUrl, resolved.registry, registryAuth);

  if (shouldStoreRegistryResponse(response, cachePolicy)) {
    const cacheable = new Response(response.body, response);
    cacheable.headers.set("Cache-Control", `public, max-age=${cachePolicy.ttl}`);
    cacheable.headers.delete("Set-Cookie");
    if (cacheable.headers.get("Vary") === "*") cacheable.headers.delete("Vary");

    ctx.waitUntil(cache.put(cacheKey, cacheable.clone()).catch((err) => {
      console.log(JSON.stringify({
        message: "registry_cache_put_failed",
        key: cacheKey.url,
        error: String(err && err.stack ? err.stack : err)
      }));
    }));

    const responseForClient = request.method === "HEAD" ? responseWithoutBody(cacheable) : cacheable;
    const out = buildRegistryClientResponse(responseForClient, workerUrl, resolved);
    out.headers.set("X-Registry-Cache", "MISS; stored");
    if (registryAuth && registryAuth.source) out.headers.set("X-Registry-Auth", registryAuth.source);
    return out;
  }

  const responseForClient = request.method === "HEAD" ? responseWithoutBody(response) : response;
  const out = buildRegistryClientResponse(responseForClient, workerUrl, resolved);
  out.headers.set("X-Registry-Cache", response.status === 429 ? "BYPASS; upstream-429" : "BYPASS");
  if (registryAuth && registryAuth.source) out.headers.set("X-Registry-Auth", registryAuth.source);
  return out;
}

async function handleRegistryAuth(request, env, workerUrl) {
  const registry = resolveRegistryForAuth(workerUrl);
  if (!registry) return textResponse("Unsupported registry auth service", 400);

  const authUrl = new URL(registry.tokenUrl);
  for (const [key, value] of workerUrl.searchParams) {
    if (key === "registry") continue;
    authUrl.searchParams.append(key, value);
  }
  normalizeRegistryAuthScopes(authUrl, registry);
  authUrl.searchParams.set("service", registry.service);

  const clientAuthorization = request.headers.get("Authorization");

  // Client login has priority. No client Authorization means we may use Worker fallback credentials.
  if (!clientAuthorization && registry === DOCKER_HUB_REGISTRY && isDockerHubFallbackAllowedAuthUrl(authUrl)) {
    const basicInfo = await getDockerHubFallbackBasic(env);
    if (basicInfo) {
      const tokenRecord = await getDockerHubTokenRecord(env, authUrl, basicInfo);
      if (tokenRecord) return buildDockerHubTokenResponse(tokenRecord);
    }
  }

  const headers = new Headers();
  copyHeader(request.headers, headers, "User-Agent");
  copyHeader(request.headers, headers, "Accept");
  if (clientAuthorization) headers.set("Authorization", clientAuthorization);
  stripClientIpHeaders(headers);

  const response = await fetch(authUrl.toString(), {
    method: request.method,
    headers,
    body: isBodyAllowed(request.method) ? request.body : undefined,
    redirect: "manual"
  });

  const responseHeaders = new Headers(response.headers);
  responseHeaders.set("X-DockerHub-Auth", clientAuthorization ? "client" : "anonymous");
  for (const [k, v] of buildCorsHeaders()) responseHeaders.set(k, v);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

async function fetchRegistryWithManualRedirect(request, targetUrl, registry, registryAuth) {
  let currentUrl = targetUrl.toString();
  let method = request.method;
  let bodyUsed = false;

  for (let i = 0; i < 8; i++) {
    const isFirstRegistryRequest = i === 0 && currentUrl.startsWith(registry.registryOrigin);
    const headers = isFirstRegistryRequest
      ? buildRegistryHeaders(request, registryAuth && registryAuth.authorization)
      : buildRegistryStorageHeaders(request);

    const init = {
      method,
      headers,
      redirect: "manual",
      body: !bodyUsed && isBodyAllowed(method) ? request.body : undefined
    };

    if (isBodyAllowed(method)) bodyUsed = true;

    const response = await fetch(new Request(currentUrl, init), getRegistryCfOptions(
      currentUrl,
      targetUrl.pathname,
      !!(registryAuth && registryAuth.authorization) || request.headers.has("Authorization")
    ));

    if (!isRedirect(response.status)) {
      logRegistryRateLimit(response, currentUrl, targetUrl.pathname, registryAuth);
      return response;
    }

    const location = response.headers.get("Location");
    if (!location) return response;

    if (response.body) {
      try { await response.body.cancel(); } catch (_) {}
    }

    currentUrl = new URL(location, currentUrl).toString();
    if (response.status === 303 && method !== "GET" && method !== "HEAD") method = "GET";
  }

  return textResponse("Too many upstream redirects", 502);
}

function buildRegistryHeaders(request, overrideAuthorization) {
  const headers = new Headers();
  copyHeader(request.headers, headers, "User-Agent");
  copyHeader(request.headers, headers, "Accept");
  copyHeader(request.headers, headers, "Accept-Encoding");
  copyHeader(request.headers, headers, "Range");
  copyHeader(request.headers, headers, "If-None-Match");
  copyHeader(request.headers, headers, "If-Modified-Since");

  if (overrideAuthorization) headers.set("Authorization", overrideAuthorization);
  else copyHeader(request.headers, headers, "Authorization");

  if (isBodyAllowed(request.method)) copyHeader(request.headers, headers, "Content-Type");
  stripClientIpHeaders(headers);
  return headers;
}

function buildRegistryStorageHeaders(request) {
  const headers = new Headers();
  copyHeader(request.headers, headers, "User-Agent");
  copyHeader(request.headers, headers, "Accept");
  copyHeader(request.headers, headers, "Accept-Encoding");
  copyHeader(request.headers, headers, "Range");
  copyHeader(request.headers, headers, "If-None-Match");
  copyHeader(request.headers, headers, "If-Modified-Since");
  stripClientIpHeaders(headers);
  return headers;
}

function buildRegistryClientResponse(response, workerUrl, resolved) {
  const headers = new Headers(response.headers);
  rewriteRegistryAuthHeader(headers, workerUrl.origin, resolved.registry, resolved.clientRepositoryPrefix);
  headers.set("Docker-Distribution-Api-Version", "registry/2.0");
  for (const [k, v] of buildCorsHeaders()) headers.set(k, v);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function responseWithoutBody(response) {
  return new Response(null, {
    status: response.status,
    statusText: response.statusText,
    headers: new Headers(response.headers)
  });
}

function getRegistryCachePolicy(request, targetUrl, registry) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (registry !== DOCKER_HUB_REGISTRY) return null;

  const manifest = parseRegistryManifestPath(targetUrl.pathname);
  if (!manifest) return null;

  // Safe default: cache only official public Docker Hub images.
  if (!manifest.name.toLowerCase().startsWith("library/")) return null;

  return {
    kind: "manifest",
    registryName: registry.name,
    ttl: isDigestReference(manifest.reference) ? MANIFEST_DIGEST_TTL : MANIFEST_TAG_TTL,
    fetchAsGet: request.method === "HEAD",
    name: manifest.name,
    reference: manifest.reference
  };
}

function buildRegistryCacheKey(workerUrl, targetUrl, request, cachePolicy) {
  const cacheUrl = new URL(workerUrl.origin);
  cacheUrl.pathname = `/__registry_cache/${cachePolicy.registryName}${targetUrl.pathname}`;
  cacheUrl.search = targetUrl.search;
  cacheUrl.searchParams.set("__kind", cachePolicy.kind);
  cacheUrl.searchParams.set("__accept", normalizeHeaderForCacheKey(request.headers.get("Accept")).slice(0, 512));
  cacheUrl.searchParams.set("__accept_encoding", normalizeHeaderForCacheKey(request.headers.get("Accept-Encoding")).slice(0, 128));
  return new Request(cacheUrl.toString(), { method: "GET" });
}

function shouldStoreRegistryResponse(response, cachePolicy) {
  if (!cachePolicy) return false;
  if (response.status !== 200) return false;
  if (response.headers.has("Set-Cookie")) return false;
  return true;
}

function getRegistryCfOptions(urlString, upstreamPathname, hasAuthorization) {
  if (!hasAuthorization) return {};

  if (
    urlString.includes("/blobs/sha256") ||
    urlString.includes("/blobs/sha256:") ||
    upstreamPathname.includes("/blobs/sha256") ||
    upstreamPathname.includes("/blobs/sha256:")
  ) {
    return { cf: { cacheTtl: BLOB_CACHE_TTL, cacheEverything: true } };
  }

  return {};
}

function resolveRegistryTarget(pathname) {
  if (pathname === "/v2" || pathname === "/v2/") return { isPing: true };

  const rest = pathname.startsWith("/v2/") ? pathname.slice("/v2/".length) : pathname.replace(/^\/+/, "");
  const parts = rest.split("/").filter(Boolean);
  if (!parts.length) return { isPing: true };

  const first = parts[0].toLowerCase();
  const explicitRegistry = ALL_REGISTRIES.find((registry) => registry.aliases.has(first));

  if (explicitRegistry) {
    const registryAlias = parts[0];
    const strippedParts = parts.slice(1);
    const upstreamPathname = strippedParts.length ? "/v2/" + strippedParts.join("/") : "/v2/";
    return {
      registry: explicitRegistry,
      upstreamPathname: normalizeRegistryPath(explicitRegistry, upstreamPathname),
      clientRepositoryPrefix: registryAlias
    };
  }

  return {
    registry: DOCKER_HUB_REGISTRY,
    upstreamPathname: normalizeRegistryPath(DOCKER_HUB_REGISTRY, pathname)
  };
}

function normalizeRegistryPath(registry, pathname) {
  if (registry === DOCKER_HUB_REGISTRY && AUTO_LIBRARY_NAMESPACE && registry.autoLibraryNamespace) {
    return normalizeDockerHubPath(pathname);
  }
  return pathname;
}

function normalizeDockerHubPath(pathname) {
  if (!pathname.startsWith("/v2/")) return pathname;

  const rest = pathname.slice("/v2/".length);
  const parts = rest.split("/").filter(Boolean);
  if (parts.length < 2) return pathname;

  const opIndex = parts.findIndex((p) => p === "manifests" || p === "blobs" || p === "tags" || p === "referrers");
  if (opIndex === 1) {
    parts.unshift("library");
    return "/v2/" + parts.join("/");
  }
  return pathname;
}

function resolveRegistryForAuth(url) {
  const registryParam = url.searchParams.get("registry");
  if (registryParam) {
    const byParam = findRegistryByAliasOrService(registryParam);
    if (byParam) return byParam;
  }

  const byScope = resolveRegistryFromAuthScopes(url.searchParams.getAll("scope"));
  if (byScope) return byScope;

  const service = url.searchParams.get("service");
  if (service) {
    const byService = findRegistryByAliasOrService(service);
    if (byService) return byService;
    return null;
  }

  return DOCKER_HUB_REGISTRY;
}

function resolveRegistryFromAuthScopes(scopes) {
  for (const scope of scopes) {
    const match = String(scope).match(/^repository:([^:]+):(.+)$/);
    if (!match) continue;
    const repo = match[1];
    const first = repo.split("/")[0].toLowerCase();
    const byRepoPrefix = ALL_REGISTRIES.find((registry) => registry.aliases.has(first));
    if (byRepoPrefix) return byRepoPrefix;
  }
  return null;
}

function findRegistryByAliasOrService(value) {
  const v = String(value || "").toLowerCase();
  for (const registry of ALL_REGISTRIES) {
    if (registry.service.toLowerCase() === v) return registry;
    if (registry.aliases.has(v)) return registry;
    try {
      const host = new URL(registry.registryOrigin).hostname.toLowerCase();
      if (host === v) return registry;
    } catch (_) {}
  }
  return null;
}

function normalizeRegistryAuthScopes(authUrl, registry) {
  const scopes = authUrl.searchParams.getAll("scope");
  if (!scopes.length) return;

  authUrl.searchParams.delete("scope");

  for (const scope of scopes) {
    if (registry === DOCKER_HUB_REGISTRY) authUrl.searchParams.append("scope", normalizeDockerHubScope(scope));
    else if (registry === GHCR_REGISTRY) authUrl.searchParams.append("scope", normalizeGhcrScope(scope));
    else authUrl.searchParams.append("scope", scope);
  }
}

function normalizeDockerHubScope(scope) {
  const match = String(scope).match(/^repository:([^:]+):(.+)$/);
  if (!match) return scope;

  const repo = match[1];
  const actions = match[2];

  if (!repo.includes("/")) return `repository:library/${repo}:${actions}`;
  if (repo.toLowerCase().startsWith("docker.io/")) return `repository:${repo.slice("docker.io/".length)}:${actions}`;
  return scope;
}

function normalizeGhcrScope(scope) {
  const match = String(scope).match(/^repository:([^:]+):(.+)$/);
  if (!match) return scope;

  const repo = match[1];
  const actions = match[2];
  if (repo.toLowerCase().startsWith("ghcr.io/")) return `repository:${repo.slice("ghcr.io/".length)}:${actions}`;
  return scope;
}

function rewriteRegistryAuthHeader(headers, workerOrigin, registry, clientRepositoryPrefix) {
  const authHeader = headers.get("Www-Authenticate");
  if (!authHeader) return;

  let newHeader = authHeader;
  if (/realm="[^"]+"/i.test(newHeader)) newHeader = newHeader.replace(/realm="[^"]+"/i, `realm="${workerOrigin}/v2/auth"`);
  else if (/realm=[^,\s]+/i.test(newHeader)) newHeader = newHeader.replace(/realm=[^,\s]+/i, `realm="${workerOrigin}/v2/auth"`);

  newHeader = rewriteRegistryAuthScope(newHeader, registry, clientRepositoryPrefix);
  headers.set("Www-Authenticate", newHeader);
}

function rewriteRegistryAuthScope(authHeader, registry, clientRepositoryPrefix) {
  if (!clientRepositoryPrefix) return authHeader;
  if (registry !== GHCR_REGISTRY) return authHeader;

  const prefix = String(clientRepositoryPrefix).replace(/^\/+|\/+$/g, "");
  if (!prefix) return authHeader;

  return authHeader.replace(/scope="repository:([^":]+(?:\/[^":]+)*):([^"]+)"/i, (match, repo, actions) => {
    if (repo.toLowerCase().startsWith(prefix.toLowerCase() + "/")) return match;
    return `scope="repository:${prefix}/${repo}:${actions}"`;
  });
}

async function getRegistryRequestAuth(request, env, targetUrl, registry) {
  const clientAuthorization = request.headers.get("Authorization");
  if (clientAuthorization) return { authorization: clientAuthorization, source: "client" };

  if (registry !== DOCKER_HUB_REGISTRY) return null;

  const scope = buildPullScopeFromRegistryPath(targetUrl.pathname);
  if (!scope || !isDockerHubFallbackAllowedScope(scope)) return null;

  const basicInfo = await getDockerHubFallbackBasic(env);
  if (!basicInfo) return null;

  const authUrl = new URL(DOCKER_HUB_REGISTRY.tokenUrl);
  authUrl.searchParams.set("service", DOCKER_HUB_REGISTRY.service);
  authUrl.searchParams.append("scope", scope);

  const tokenRecord = await getDockerHubTokenRecord(env, authUrl, basicInfo);
  const token = tokenRecord && (tokenRecord.token || tokenRecord.accessToken);
  if (!token) return null;

  return { authorization: "Bearer " + token, source: "worker" };
}

function buildPullScopeFromRegistryPath(pathname) {
  if (!pathname.startsWith("/v2/")) return null;

  const match = pathname.match(/^\/v2\/(.+)\/(manifests|blobs|tags|referrers)(?:\/|$)/);
  if (!match) return null;

  const repo = safeDecodeURIComponent(match[1]);
  if (!repo || repo.includes("..") || repo.startsWith("/")) return null;
  return `repository:${repo}:pull`;
}

function isDockerHubFallbackAllowedAuthUrl(authUrl) {
  const scopes = authUrl.searchParams.getAll("scope");
  if (!scopes.length) return false;
  return scopes.every(isDockerHubFallbackAllowedScope);
}

function isDockerHubFallbackAllowedScope(scope) {
  const match = String(scope || "").match(/^repository:([^:]+):(.+)$/);
  if (!match) return false;

  const actions = match[2].split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (actions.some((action) => action !== "pull")) return false;

  return true;
}

async function getDockerHubFallbackBasic(env) {
  const fromEnv = getDockerHubFallbackBasicFromEnv(env);
  if (fromEnv) return fromEnv;

  const kv = getStateKv(env);
  if (!kv) return null;

  const raw = await kv.get(DOCKERHUB_FALLBACK_BASIC_KV_KEY);
  if (!raw) return null;

  try {
    const data = JSON.parse(raw);
    if (!data || !data.basic) return null;
    return {
      basic: String(data.basic).replace(/^Basic\s+/i, ""),
      username: data.username || "",
      source: "kv"
    };
  } catch (_) {
    return null;
  }
}

function getDockerHubFallbackBasicFromEnv(env) {
  if (!env) return null;

  const rawBasic = env.DOCKERHUB_BASIC_AUTH || env.DOCKER_HUB_BASIC_AUTH;
  if (rawBasic) {
    return {
      basic: String(rawBasic).replace(/^Basic\s+/i, ""),
      username: "",
      source: "env"
    };
  }

  const username = env.DOCKERHUB_USERNAME || env.DOCKER_USERNAME || env.DOCKER_HUB_USERNAME;
  const password = env.DOCKERHUB_TOKEN || env.DOCKERHUB_PASSWORD || env.DOCKER_TOKEN || env.DOCKER_PASSWORD || env.DOCKER_HUB_TOKEN;
  if (!username || !password) return null;

  return {
    basic: base64EncodeUtf8(`${username}:${password}`),
    username,
    source: "env"
  };
}

async function getDockerHubTokenRecord(env, authUrl, basicInfo) {
  const kv = getStateKv(env);
  const cacheKey = kv ? await dockerHubTokenCacheKey(authUrl, basicInfo.basic) : null;
  const now = Math.floor(Date.now() / 1000);

  if (kv && cacheKey) {
    const cachedRaw = await kv.get(cacheKey);
    if (cachedRaw) {
      try {
        const cached = JSON.parse(cachedRaw);
        if (cached && cached.bodyText && cached.expiresAt && cached.expiresAt > now + 10) {
          const tokenData = JSON.parse(cached.bodyText);
          return {
            status: 200,
            statusText: "OK",
            bodyText: cached.bodyText,
            contentType: "application/json",
            token: tokenData.token || tokenData.access_token || "",
            accessToken: tokenData.access_token || tokenData.token || "",
            expiresAt: cached.expiresAt,
            authSource: "worker-cache"
          };
        }
      } catch (_) {}
    }
  }

  const headers = new Headers();
  headers.set("Accept", "application/json");
  headers.set("User-Agent", "docker-worker-proxy/1.0");
  headers.set("Authorization", "Basic " + basicInfo.basic);
  stripClientIpHeaders(headers);

  const response = await fetch(authUrl.toString(), {
    method: "GET",
    headers,
    redirect: "manual"
  });

  const bodyText = await response.text();
  const contentType = response.headers.get("Content-Type") || "application/json";

  if (!response.ok) {
    console.log(JSON.stringify({
      message: "dockerhub_fallback_token_failed",
      status: response.status,
      statusText: response.statusText,
      service: authUrl.searchParams.get("service") || "",
      scopes: authUrl.searchParams.getAll("scope")
    }));

    return {
      status: response.status,
      statusText: response.statusText,
      bodyText,
      contentType,
      authSource: "worker-error"
    };
  }

  let tokenData;
  try { tokenData = JSON.parse(bodyText); } catch (_) { tokenData = {}; }

  const token = tokenData.token || tokenData.access_token || "";
  const expiresIn = Math.max(0, Number(tokenData.expires_in || 60));
  const effectiveTtl = Math.max(0, expiresIn - DOCKERHUB_TOKEN_CACHE_SKEW_SECONDS);
  const expiresAt = now + effectiveTtl;

  if (kv && cacheKey && token && effectiveTtl >= 60) {
    await kv.put(cacheKey, JSON.stringify({
      bodyText,
      expiresAt,
      createdAt: now,
      scopes: authUrl.searchParams.getAll("scope"),
      source: basicInfo.source
    }), { expirationTtl: effectiveTtl });
  }

  return {
    status: response.status,
    statusText: response.statusText,
    bodyText,
    contentType,
    token,
    accessToken: tokenData.access_token || token,
    expiresAt,
    authSource: "worker"
  };
}

function buildDockerHubTokenResponse(tokenRecord) {
  const headers = buildCorsHeaders();
  headers.set("Content-Type", tokenRecord.contentType || "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("X-DockerHub-Auth", tokenRecord.authSource || "worker");

  return new Response(tokenRecord.bodyText || "", {
    status: tokenRecord.status || 200,
    statusText: tokenRecord.statusText || "OK",
    headers
  });
}

async function dockerHubTokenCacheKey(authUrl, basic) {
  const clone = new URL(authUrl.toString());
  const params = [];
  for (const [k, v] of clone.searchParams) params.push([k, v]);
  params.sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]));
  const canonical = params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
  const hash = await sha256Hex(`${basic}\n${clone.origin}${clone.pathname}?${canonical}`);
  return DOCKERHUB_TOKEN_KV_PREFIX + hash;
}

async function handleAdmin(request, env, url) {
  const otp = url.searchParams.get("otp");
  if (!otp) return textResponse("Missing otp", 400);

  const ok = await verifyTOTP(otp, env.TOTP_SECRET);
  if (!ok) return textResponse("Invalid OTP", 403);

  if (url.searchParams.has("dockerStatus")) {
    const kv = getStateKv(env);
    const basicInfo = await getDockerHubFallbackBasic(env);
    const tokenCount = kv ? await countDockerHubTokenCache(kv) : 0;
    return jsonResponse({
      configured: !!basicInfo,
      source: basicInfo ? basicInfo.source : "none",
      username: basicInfo ? basicInfo.username || "" : "",
      kvBound: !!kv,
      tokenCacheCount: tokenCount,
      fallbackScopePolicy: DOCKERHUB_FALLBACK_SCOPE_POLICY,
      envSupported: true
    });
  }

  const kv = getStateKv(env);
  if (!kv) return textResponse("AUTH_KV or WHITELIST_KV is not bound", 500);

  if (url.searchParams.has("dockerClearTokens")) {
    const deleted = await clearDockerHubTokenCache(kv);
    return jsonResponse({ ok: true, deletedTokenCacheKeys: deleted });
  }

  if (url.searchParams.has("dockerLogout")) {
    await kv.delete(DOCKERHUB_FALLBACK_BASIC_KV_KEY);
    const deleted = await clearDockerHubTokenCache(kv);
    return jsonResponse({ ok: true, removed: "dockerhub fallback auth", deletedTokenCacheKeys: deleted });
  }

  if (url.searchParams.has("dockerLogin")) {
    if (request.method !== "POST") {
      const headers = buildCorsHeaders();
      headers.set("Allow", "POST, OPTIONS");
      return new Response("Use POST with JSON body", { status: 405, headers });
    }

    let data;
    try { data = await request.json(); } catch (_) { return textResponse("Invalid JSON body", 400); }

    const username = String(data.username || data.user || "").trim();
    const password = String(data.password || data.token || data.pat || "");
    if (!username || !password) return textResponse("Missing username or password/token", 400);

    const now = Math.floor(Date.now() / 1000);
    await kv.put(DOCKERHUB_FALLBACK_BASIC_KV_KEY, JSON.stringify({
      username,
      basic: base64EncodeUtf8(`${username}:${password}`),
      createdAt: now,
      updatedAt: now
    }));

    const deleted = await clearDockerHubTokenCache(kv);
    return jsonResponse({ ok: true, stored: "dockerhub fallback auth", username, deletedOldTokenCacheKeys: deleted });
  }

  return textResponse([
    "Admin usage:",
    "POST /admin?otp=123456&dockerLogin=1  JSON: {\"username\":\"...\",\"password\":\"Docker Hub PAT\"}",
    "GET  /admin?otp=123456&dockerStatus=1",
    "GET  /admin?otp=123456&dockerClearTokens=1",
    "GET  /admin?otp=123456&dockerLogout=1"
  ].join("\n"));
}

async function clearDockerHubTokenCache(kv) {
  let cursor = undefined;
  let deleted = 0;

  do {
    const result = await kv.list({ prefix: DOCKERHUB_TOKEN_KV_PREFIX, cursor });
    for (const key of result.keys) {
      await kv.delete(key.name);
      deleted++;
    }
    cursor = result.list_complete ? undefined : result.cursor;
  } while (cursor);

  return deleted;
}

async function countDockerHubTokenCache(kv) {
  let cursor = undefined;
  let count = 0;

  do {
    const result = await kv.list({ prefix: DOCKERHUB_TOKEN_KV_PREFIX, cursor });
    count += result.keys.length;
    cursor = result.list_complete ? undefined : result.cursor;
  } while (cursor);

  return count;
}

function parseRegistryManifestPath(pathname) {
  if (!pathname.startsWith("/v2/")) return null;
  const marker = "/manifests/";
  const markerIndex = pathname.indexOf(marker);
  if (markerIndex < 0) return null;

  const name = pathname.slice("/v2/".length, markerIndex);
  const reference = pathname.slice(markerIndex + marker.length);
  if (!name || !reference || reference.includes("/")) return null;

  return { name: safeDecodeURIComponent(name), reference: safeDecodeURIComponent(reference) };
}

function isDigestReference(reference) {
  return /^sha256:[a-f0-9]{64}$/i.test(reference);
}

function cloneRequestWithMethod(request, method) {
  return new Request(request.url, {
    method,
    headers: request.headers,
    body: isBodyAllowed(method) && isBodyAllowed(request.method) ? request.body : undefined
  });
}

function normalizeHeaderForCacheKey(value) {
  return String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
}

function logRegistryRateLimit(response, currentUrl, upstreamPathname, registryAuth) {
  if (response.status !== 429) return;
  console.log(JSON.stringify({
    message: "upstream_registry_429",
    upstreamHost: safeHostname(currentUrl),
    upstreamPathname,
    authSource: registryAuth && registryAuth.source ? registryAuth.source : "none",
    retryAfter: response.headers.get("Retry-After") || "",
    rateLimitLimit: response.headers.get("RateLimit-Limit") || "",
    rateLimitRemaining: response.headers.get("RateLimit-Remaining") || "",
    dockerRateLimitSource: response.headers.get("Docker-RateLimit-Source") || ""
  }));
}

function buildCorsHeaders() {
  return new Headers({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "*"
  });
}

function textResponse(text, status = 200) {
  return new Response(text, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...Object.fromEntries(buildCorsHeaders())
    }
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...Object.fromEntries(buildCorsHeaders())
    }
  });
}

function copyHeader(from, to, name) {
  const value = from.get(name);
  if (value) to.set(name, value);
}

function stripClientIpHeaders(headers) {
  for (const name of CLIENT_IP_HEADER_NAMES) headers.delete(name);
  return headers;
}

function isBodyAllowed(method) {
  return method !== "GET" && method !== "HEAD";
}

function isRedirect(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function safeDecodeURIComponent(value) {
  try { return decodeURIComponent(value); } catch (_) { return value; }
}

function safeHostname(urlString) {
  try { return new URL(urlString).hostname; } catch (_) { return ""; }
}

function getStateKv(env) {
  return env && (env.AUTH_KV || env.WHITELIST_KV) || null;
}

function base64EncodeUtf8(value) {
  const bytes = new TextEncoder().encode(String(value));
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value)));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTOTP(inputCode, secretBase32) {
  if (!secretBase32) throw new Error("Missing TOTP_SECRET");
  if (!/^\d{6}$/.test(inputCode)) return false;

  const now = Math.floor(Date.now() / 1000);
  const currentStep = Math.floor(now / 30);
  const steps = [currentStep - 1, currentStep, currentStep + 1];

  for (const step of steps) {
    const code = await generateTOTP(secretBase32, step);
    if (code === inputCode) return true;
  }

  return false;
}

async function generateTOTP(secretBase32, counter) {
  const keyBytes = base32Decode(secretBase32);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  const high = Math.floor(counter / 4294967296);
  const low = counter % 4294967296;
  view.setUint32(0, high);
  view.setUint32(4, low);

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, msg);
  const hmac = new Uint8Array(signature);
  const offset = hmac[hmac.length - 1] & 15;
  const binary =
    ((hmac[offset] & 127) << 24) |
    ((hmac[offset + 1] & 255) << 16) |
    ((hmac[offset + 2] & 255) << 8) |
    (hmac[offset + 3] & 255);

  return String(binary % 1000000).padStart(6, "0");
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(input || "").toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  if (!clean) throw new Error("Empty Base32 secret");

  let bits = "";
  for (const ch of clean) {
    const val = alphabet.indexOf(ch);
    if (val === -1) throw new Error("Invalid Base32 secret");
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}
