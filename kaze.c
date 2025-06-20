#define KZ_STATIC_API
#include "kaze.h"

#define LUA_LIB
#include <lauxlib.h>
#include <lua.h>

#define LKZ_State   "kaze.State"
#define LKZ_Context "kaze.Context"

/* clang-format off */
static int Lkz_pusherror_aux(lua_State *L)
{ return lua_pushstring(L, (char *)lua_touserdata(L, 1)), 1; }
/* clang-format on */

static int lkz_pusherror(lua_State *L, int r) {
    luaL_pushfail(L);
    if (r == KZ_FAIL) {
        const char *errmsg = kz_failerror();
        lua_pushcfunction(L, Lkz_pusherror_aux);
        lua_pushlightuserdata(L, (void *)errmsg);
        lua_pcall(L, 1, 1, 0);
        kz_freefailerror(errmsg);
        return 2;
    }
    switch (r) { /* clang-format off */
    case KZ_OK:      lua_pushliteral(L, "No error"); break;
    case KZ_INVALID: lua_pushliteral(L, "INVALID"); break;
    case KZ_CLOSED:  lua_pushliteral(L, "CLOSED"); break;
    case KZ_TOOBIG:  lua_pushliteral(L, "TOOBIG"); break;
    case KZ_AGAIN:   lua_pushliteral(L, "AGAIN"); break;
    case KZ_BUSY:    lua_pushliteral(L, "BUSY"); break;
    case KZ_TIMEOUT: lua_pushliteral(L, "TIMEOUT"); break;
    default: lua_pushfstring(L, "Unknown(%d)", r); break;
    } /* clang-format on */
    return 2;
}

/* context */

static kz_Context *lkz_checkcontext(lua_State *L, int idx) {
    kz_Context *ctx = (kz_Context *)luaL_checkudata(L, idx, LKZ_Context);
    if (ctx->result != KZ_OK && ctx->result != KZ_AGAIN)
        return luaL_argerror(L, 1, "context closed"), NULL;
    return ctx;
}

static int Lctx_cancel(lua_State *L) {
    kz_Context *ctx = lkz_checkcontext(L, 1);
    kz_cancel(ctx);
    ctx->result = KZ_FAIL;
    return 0;
}

static int Lctx_isread(lua_State *L) {
    kz_Context *ctx = lkz_checkcontext(L, 1);
    return kz_isread(ctx) ? (lua_settop(L, 1), 1) : 0;
}

static int Lctx_wouldblock(lua_State *L) {
    kz_Context *ctx = lkz_checkcontext(L, 1);
    return ctx->result == KZ_AGAIN ? (lua_settop(L, 1), 1) : 0;
}

static int lkz_buffer_aux(lua_State *L) {
    kz_Context *ctx = (kz_Context *)lua_touserdata(L, 1);
    size_t      len;
    char       *buf = kz_buffer(ctx, &len);
    return lua_pushlstring(L, buf, len), 1;
}

static int Lctx_read(lua_State *L) {
    kz_Context *ctx = lkz_checkcontext(L, 1);
    if (!kz_isread(ctx))
        return luaL_error(L, "attempt to call 'read' of a write context");
    else {
        int r;
        lua_pushcfunction(L, lkz_buffer_aux);
        lua_pushlightuserdata(L, ctx);
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
            luaL_pushfail(L);
            lua_insert(L, -2);
            return 2;
        }
        r = kz_commit(ctx, 0);
        if (r != KZ_OK) {
            r = lkz_pusherror(L, r);
            lua_remove(L, -r);
            return r;
        }
        return ctx->result = KZ_CLOSED, 1;
    }
}

static int Lctx_write(lua_State *L) {
    kz_Context *ctx = (kz_Context *)luaL_checkudata(L, 1, LKZ_Context);
    if (kz_isread(ctx)) {
        return luaL_error(L, "attempt to call 'write' of a read context");
    } else {
        int         r;
        size_t      dlen, len;
        const char *data = luaL_checklstring(L, 2, &dlen);
        char       *buf = kz_buffer(ctx, &len);
        if (dlen > len) luaL_error(L, "data too large");
        memcpy(buf, data, dlen);
        r = kz_commit(ctx, dlen);
        if (r != KZ_OK) return lkz_pusherror(L, r);
        ctx->result = KZ_CLOSED;
        return lua_pushinteger(L, dlen), 1;
    }
}

static int Lctx_wait(lua_State *L) {
    kz_Context *ctx = (kz_Context *)luaL_checkudata(L, 1, LKZ_Context);
    lua_Integer millis = luaL_optinteger(L, 2, -1);
    int         r = kz_waitcontext(ctx, millis);
    return r == KZ_OK ? (lua_settop(L, 1), 1) : lkz_pusherror(L, r);
}

static int open_context(lua_State *L) {
    luaL_Reg libs[] = {/* clang-format off */
        { "__name",  NULL },
        { "__index", NULL },
#define ENTRY(name) { #name, Lctx_##name }
        ENTRY(cancel),
        ENTRY(isread),
        ENTRY(wouldblock),
        ENTRY(read),
        ENTRY(write),   
        ENTRY(wait),
#undef  ENTRY
        { NULL, NULL }
    }; /* clang-format off */
    if (luaL_newmetatable(L, LKZ_Context)) {
        luaL_setfuncs(L, libs, 0);
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
    }
    lua_pop(L, 1);
    return LUA_OK;
}

/* state */

static int Laligned(lua_State *L) {
    lua_Integer bufsize = luaL_checkinteger(L, 1);
    lua_Integer pagesize = luaL_optinteger(L, 2, 4096);
    return lua_pushinteger(L, kz_aligned(bufsize, pagesize)), 1;
}

static int Lexists(lua_State *L) {
    const char *shmname = luaL_checkstring(L, 1);
    int         owner = 0, user = 0;
    int         r = kz_exists(shmname, &owner, &user);
    if (r < 0) return lkz_pusherror(L, r);
    lua_pushboolean(L, r);
    lua_pushinteger(L, owner);
    lua_pushinteger(L, user);
    return 3;
}

static int Lunlink(lua_State *L) {
    const char *shmname = luaL_checkstring(L, 1);
    int         r = kz_unlink(shmname);
    if (r < 0) return lkz_pusherror(L, r);
    return lua_pushboolean(L, 1), 1;
}

static int lkz_parseflags(lua_State *L, int idx) {
    const char *mode = luaL_optstring(L, idx, "");
    int         r = 0;
    for (; *mode != '\0'; ++mode) {
        switch (*mode) { /* clang-format off */
        case 'c': r |= KZ_CREATE; break;
        case 'e': r |= KZ_EXCL;   break;
        case 'r': r |= KZ_RESET;  break;
        } /* clang-format on */
    }
    return r;
}

static kz_State *lkz_checkstate(lua_State *L, int idx) {
    kz_State **pS = (kz_State **)luaL_checkudata(L, idx, LKZ_State);
    if (*pS == NULL) luaL_argerror(L, 1, "state closed");
    return *pS;
}

static int Lcreate(lua_State *L) {
    const char *shmname = luaL_checkstring(L, 1);
    lua_Integer bufsize = luaL_checkinteger(L, 2);
    int         mode  = (int)luaL_optinteger(L, 4, 0666);
    int         flags = KZ_CREATE | lkz_parseflags(L, 3) | mode;
    kz_State   *S = kz_open(shmname, flags, bufsize);
    if (S == NULL) return lkz_pusherror(L, KZ_FAIL);
    *(kz_State **)lua_newuserdata(L, sizeof(kz_State *)) = S;
    luaL_setmetatable(L, LKZ_State);
    return 1;
}

static int Lopen(lua_State *L) {
    const char *shmname = luaL_checkstring(L, 1);
    int         flags = lkz_parseflags(L, 2);
    lua_Integer bufsize = luaL_optinteger(L, 3, 0);
    kz_State   *S = kz_open(shmname, flags, bufsize);
    if (S == NULL) return lkz_pusherror(L, KZ_FAIL);
    *(kz_State **)lua_newuserdata(L, sizeof(kz_State *)) = S;
    luaL_setmetatable(L, LKZ_State);
    return 1;
}

static int lkz_parsemode(lua_State *L, int idx) {
    const char *mode = luaL_optstring(L, idx, "");
    int         r = 0;
    for (; *mode != '\0'; ++mode) {
        switch (*mode) { /* clang-format off */
        case 'r': r |= KZ_READ; break;
        case 'w': r |= KZ_WRITE; break;
        } /* clang-format on */
    }
    return r;
}

static int Lshutdown(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    int       mode = lkz_parsemode(L, 2);
    int       r = kz_shutdown(S, mode);
    return r == KZ_OK ? (lua_settop(L, 1), 1) : lkz_pusherror(L, r);
}

static int Lclose(lua_State *L) {
    kz_State **pS = (kz_State **)luaL_checkudata(L, 1, LKZ_State);
    if (*pS != NULL) kz_close(*pS);
    *pS = NULL;
    return 0;
}

static int Lname(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    return lua_pushstring(L, kz_name(S)), 1;
}

static int Lsize(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    return lua_pushinteger(L, kz_size(S)), 1;
}

static int Lpid(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    return lua_pushinteger(L, kz_pid(S)), 1;
}

static int Lisowner(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    return kz_isowner(S) ? 1 : 0;
}

static int Lisclosed(lua_State *L) {
    kz_State *S = lkz_checkstate(L, 1);
    int       mode = lkz_parsemode(L, 2);
    int       r = kz_isclosed(S);
    lua_settop(L, 1);
    if (mode == 0 && (r > 0)) return 1;
    if ((mode & r) == mode) return 1;
    return 0;
}

static int Lreadcontext(lua_State *L) {
    kz_State   *S = lkz_checkstate(L, 1);
    kz_Context *ctx = (kz_Context *)lua_newuserdata(L, sizeof(kz_Context));
    int         r = kz_read(S, ctx);
    if (r != KZ_OK && r != KZ_AGAIN) return lkz_pusherror(L, r);
    luaL_setmetatable(L, LKZ_Context);
    if (r == KZ_AGAIN) return lua_pushliteral(L, "AGAIN"), 2;
    return 1;
}

static int Lwritecontext(lua_State *L) {
    kz_State   *S = lkz_checkstate(L, 1);
    lua_Integer request = luaL_checkinteger(L, 2);
    kz_Context *ctx = (kz_Context *)lua_newuserdata(L, sizeof(kz_Context));
    int         r = kz_write(S, ctx, request);
    if (r != KZ_OK && r != KZ_AGAIN) return lkz_pusherror(L, r);
    luaL_setmetatable(L, LKZ_Context);
    if (r == KZ_AGAIN) return lua_pushliteral(L, "AGAIN"), 2;
    return 1;
}

static int Lwait(lua_State *L) {
    kz_State   *S = lkz_checkstate(L, 1);
    lua_Integer request = luaL_checkinteger(L, 2);
    lua_Integer millis = luaL_optinteger(L, 3, -1);
    int         r = kz_wait(S, request, millis);
    if (r <= 0) return lkz_pusherror(L, r);
    lua_pushboolean(L, (r & KZ_READ));
    lua_pushboolean(L, (r & KZ_WRITE));
    return 2;
}

static int Lread(lua_State *L) {
    kz_State   *S = lkz_checkstate(L, 1);
    lua_Integer millis = luaL_optinteger(L, 2, -1);
    kz_Context  ctx;
    int         r = kz_read(S, &ctx);
    if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, millis);
    if (r == KZ_CLOSED) return 0;
    if (r != KZ_OK) return lkz_pusherror(L, r), lua_error(L);
    lua_pushcfunction(L, lkz_buffer_aux);
    lua_pushlightuserdata(L, &ctx);
    lua_pcall(L, 1, 1, 0);
    r = kz_commit(&ctx, 0);
    if (r == KZ_CLOSED) return 0;
    if (r != KZ_OK) return lkz_pusherror(L, r), lua_error(L);
    return 1;
}

static int Lwrite(lua_State *L) {
    kz_State   *S = lkz_checkstate(L, 1);
    size_t      len;
    const char *data = luaL_checklstring(L, 2, &len);
    lua_Integer millis = luaL_optinteger(L, 3, -1);
    kz_Context  ctx;
    int         r = kz_write(S, &ctx, len);
    if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, millis);
    if (r == KZ_CLOSED) return 0;
    if (r != KZ_OK) return lkz_pusherror(L, r), lua_error(L);
    memcpy(kz_buffer(&ctx, NULL), data, len);
    r = kz_commit(&ctx, len);
    if (r == KZ_CLOSED) return 0;
    if (r != KZ_OK) return lkz_pusherror(L, r), lua_error(L);
    return lua_settop(L, 1), 1;
}

LUALIB_API int luaopen_kaze(lua_State *L) {
    luaL_Reg libs[] = {
            {"__gc", Lclose},    {"__close", Lclose},
#define ENTRY(name) {#name, L##name}
            ENTRY(aligned),      ENTRY(exists),       ENTRY(unlink),
            ENTRY(create),       ENTRY(open),         ENTRY(close),
            ENTRY(shutdown),     ENTRY(name),         ENTRY(size),
            ENTRY(pid),          ENTRY(isowner),      ENTRY(isclosed),
            ENTRY(read),         ENTRY(write),        ENTRY(readcontext),
            ENTRY(writecontext), ENTRY(wait),
#undef ENTRY
            {NULL, NULL}};
    open_context(L);
    if (luaL_newmetatable(L, LKZ_State)) {
        luaL_setfuncs(L, libs, 0);
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
    }
    return 1;
}

/* cc: flags+='-Wall -O3'
 * maccc: flags+='-shared -undefined dynamic_lookup' output='kaze.so'
 */
