project('pam-go-loader', 'c',
    version: '0.1',
    default_options: [
        'buildtype=debugoptimized',
        'warning_level=3',
        'c_std=gnu99',
    ],
)

cc = meson.get_compiler('c')
fs = import('fs')

common_cflags = cc.get_supported_arguments([
    '-Wno-unused-parameter',
])
add_project_arguments(common_cflags, language: 'c')

pam_dep = cc.find_library('pam',
    has_headers: [
        'security/pam_modules.h',
        'security/pam_ext.h',
    ]
)

prefix = get_option('prefix')
pam_prefix = prefix == '/usr' or prefix == '/usr/local' ? '/' : prefix
pam_modules_dir = pam_prefix / get_option('libdir') / 'security'
pam_config_dir = pam_prefix / get_option('sysconfdir') / 'pam.d'
pam_auth_update_configs = get_option('datadir') / 'pam-configs'
debug_build = get_option('buildtype').startswith('debug')

pam_module = shared_module('pam_go_loader',
    name_prefix: '',
    sources: [
        'module.c',
    ],
    c_args: [
        '-DPAM_MODULES_DIR="@0@"'.format(pam_modules_dir),
    ] + (debug_build ? [
        '-DDEBUG_MODE',
    ] : []),
    dependencies: [
        pam_dep,
    ],
    link_args: [
        '-Wl,--unresolved-symbols=report-all',
    ],
    install: true,
    install_dir: pam_modules_dir,
)
pam_module_name = fs.name(pam_module.full_path())

if get_option('pam-auth-update-support')
    install_data(configure_file(
        input: 'libpam-authd.pam-auth-update.in',
        output: 'libpam-authd.pam-auth-update',
        configuration: {
                'pam_loader': pam_prefix == '/' ?
                    pam_module_name : pam_modules_dir / pam_module_name,
                'loaded_module': get_option('loaded_module'),
                'loaded_module_args': ' '.join(get_option('loaded_module_args')),
            }
        ),
        rename: 'authd',
        install_dir: pam_auth_update_configs,
    )
endif
