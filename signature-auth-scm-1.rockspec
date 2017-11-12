package = "signature-auth"
version = "scm-1"
source = {
   url = "https://github.com/beckjiang218/kong-plugins-signature-auth.git"
}
description = {
   homepage = "*** please enter a project homepage ***",
   license = "*** please specify a license ***"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.signature-auth.config"] = "kong/plugins/signature-auth/config.lua",
      ["kong.plugins.signature-auth.handler"] = "kong/plugins/signature-auth/handler.lua",
      ["kong.plugins.signature-auth.schema"] = "kong/plugins/signature-auth/schema.lua"
   }
}