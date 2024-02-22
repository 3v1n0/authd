#!/usr/bin/env bash

set -euo pipefail
set -x

module_libname=pam_authd.so
loader_libname=pam_go_loader.so

if [ -d "$PROJECT_ROOT"/vendor ]; then
    echo Vendored dependencies detected, not re-generating pam_module.go
else
    go run github.com/msteinert/pam/v2/cmd/pam-moduler \
        -libname "$module_libname" -type pamModule \
        "${@}"
    go generate -x -tags pam_module_generation
fi

cc_args=()
if [ -v AUTHD_PAM_MODULES_PATH ]; then
    cc_args+=(-DAUTHD_PAM_MODULES_PATH=\""${AUTHD_PAM_MODULES_PATH}"\")
fi

${CC:-cc} -o go-loader/"$loader_libname" \
    go-loader/module.c ${CFLAGS:-} -Wl,--as-needed -Wl,--allow-shlib-undefined \
    -shared -fPIC -Wl,--unresolved-symbols=report-all \
    -Wl,-soname,"$loader_libname" -lpam ${LDFLAGS:-} "${cc_args[@]}"

chmod 644 go-loader/"$loader_libname"
