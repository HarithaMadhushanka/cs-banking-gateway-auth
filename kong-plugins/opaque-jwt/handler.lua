local redis = require "resty.redis"
local kong = kong

local plugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

local function get_bearer_token()
  local h = kong.request.get_header("authorization")
  if not h then return nil end
  local m = h:match("^[Bb]earer%s+(.+)$")
  return m
end

local function redis_connect(conf)
  local r = redis:new()
  r:set_timeout(conf.redis_timeout_ms)

  local ok, err = r:connect(conf.redis_host, conf.redis_port)
  if not ok then
    return nil, "redis connect failed: " .. (err or "unknown")
  end

  if conf.redis_password and conf.redis_password ~= "" then
    local ok2, err2 = r:auth(conf.redis_password)
    if not ok2 then
      return nil, "redis auth failed: " .. (err2 or "unknown")
    end
  end

  if conf.redis_database and conf.redis_database ~= 0 then
    local ok3, err3 = r:select(conf.redis_database)
    if not ok3 then
      return nil, "redis select failed: " .. (err3 or "unknown")
    end
  end

  return r, nil
end

local function redis_get_jwt(r, key)
  local jwt, err = r:get(key)
  if err then
    return nil, "redis get error: " .. err
  end
  if jwt == ngx.null then
    return nil, nil
  end
  return jwt, nil
end

function plugin:access(conf)
  local opaque = get_bearer_token()

  -- No token → public route
  if not opaque or opaque == "" then
    return
  end

  --------------------------------------------------------------------
  -- 🔒 ALWAYS preserve opaque token BEFORE any early returns
  --------------------------------------------------------------------
  kong.service.request.set_header("X-Opaque-Token", opaque)

  --------------------------------------------------------------------
  -- Only accept opaque tokens (client must NEVER send JWT)
  --------------------------------------------------------------------
  if not opaque:match("^opaque_") then
    return kong.response.exit(401, { message = "invalid token" })
  end

  --------------------------------------------------------------------
  -- Worker cache
  --------------------------------------------------------------------
  local cache_key = "opaque_jwt:" .. opaque
  if conf.cache_ttl_sec and conf.cache_ttl_sec > 0 then
    local cached = kong.cache:get(cache_key, nil, function() return nil end)
    if cached and cached ~= "" then
      kong.service.request.set_header("authorization", "Bearer " .. cached)
      return
    end
  end

  --------------------------------------------------------------------
  -- Redis lookup
  --------------------------------------------------------------------
  local r, err = redis_connect(conf)
  if not r then
    kong.log.err("[opaque-jwt] ", err)
    if conf.fail_open then return end
    return kong.response.exit(503, { message = "auth unavailable" })
  end

  local key = conf.key_prefix .. opaque
  local jwt, err2 = redis_get_jwt(r, key)

  r:set_keepalive(10000, 100)

  if err2 then
    kong.log.err("[opaque-jwt] ", err2)
    if conf.fail_open then return end
    return kong.response.exit(503, { message = "auth unavailable" })
  end

  if not jwt or jwt == "" then
    return kong.response.exit(401, { message = "invalid token" })
  end

  --------------------------------------------------------------------
  -- Cache JWT
  --------------------------------------------------------------------
  if conf.cache_ttl_sec and conf.cache_ttl_sec > 0 then
    kong.cache:invalidate_local(cache_key)
    kong.cache:get(cache_key, { ttl = conf.cache_ttl_sec }, function()
      return jwt
    end)
  end

  --------------------------------------------------------------------
  -- Rewrite Authorization → JWT (opaque NEVER leaves gateway)
  --------------------------------------------------------------------
  kong.service.request.set_header("authorization", "Bearer " .. jwt)
end

return plugin
