package = "signature-auth"
version = "scm-1"
source = {
   url = "git@github.com:beckjiang218/kong-plugins-signature-auth.git"
}
description = {
   homepage = "*** please enter a project homepage ***",
   license = "*** please specify a license ***"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      handler = "src/handler.lua",
      schema = "src/schema.lua"
   }
}