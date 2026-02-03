local typedefs = require "kong.db.schema.typedefs"

return {
  name = "opaque-jwt",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { redis_host = { type = "string", required = true, default = "redis" } },
          { redis_port = { type = "number", required = true, default = 6379 } },
          { redis_password = { type = "string", required = false } },
          { redis_database = { type = "number", required = true, default = 0 } },
          { redis_timeout_ms = { type = "number", required = true, default = 2000 } },

          -- Key format in redis. Example: "opaque:token:<opaque>"
          { key_prefix = { type = "string", required = true, default = "opaque:token:" } },

          -- If jwt not found, return 401
          { fail_open = { type = "boolean", required = true, default = false } },

          -- Optional: cache within Kong worker for N seconds to reduce Redis hits
          { cache_ttl_sec = { type = "number", required = true, default = 5 } },
        },
      },
    },
  },
}
