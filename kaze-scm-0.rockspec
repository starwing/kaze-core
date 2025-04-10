package = "kaze"
version = "scm-0"
source = {
   url = "git+https://github.com/starwing/kaze-core.git",
   branch = "master"
}
description = {
   summary = "Kaze channel binding for Lua",
   detailed = [[
A Lua binding for kaze channel library.
  ]],
   homepage = "https://github.com/starwing/kaze-core",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      kaze = "kaze.c",
   }
}
