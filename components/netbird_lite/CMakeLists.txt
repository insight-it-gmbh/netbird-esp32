idf_component_register(
    SRCS
        "src/nbl_acl.c"
        "src/nbl_ctrl.c"
        "src/nbl_crypto.c"
        "src/nbl_grpc.c"
        "src/nbl_h2p.c"
        "src/nbl_netmap.c"
        "src/nbl_relay.c"
        "src/nbl_relaymsg.c"
        "src/nbl_ws.c"
        "src/nbl_wg.c"
        "proto_gen/nbl_mgmt.pb.c"
        "proto_gen/nbl_signal.pb.c"
        "vendor/nanopb/pb_common.c"
        "vendor/nanopb/pb_decode.c"
        "vendor/nanopb/pb_encode.c"
        "vendor/tweetnacl/tweetnacl.c"
        "vendor/wireguard-lwip/wireguard.c"
        "vendor/wireguard-lwip/wireguardif.c"
        "vendor/wireguard-lwip/crypto.c"
        "vendor/wireguard-lwip/crypto/refc/blake2s.c"
        "vendor/wireguard-lwip/crypto/refc/chacha20.c"
        "vendor/wireguard-lwip/crypto/refc/chacha20poly1305.c"
        "vendor/wireguard-lwip/crypto/refc/poly1305-donna.c"
        "vendor/wireguard-lwip/crypto/refc/x25519.c"
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
        "proto_gen"
        "vendor/nanopb"
        "vendor/tweetnacl"
        "vendor/wireguard-lwip"
        "vendor/wireguard-lwip/crypto/refc"
    REQUIRES
        esp_event
    PRIV_REQUIRES
        esp-tls
        mbedtls
        lwip
        nvs_flash
        esp_timer
        esp_netif
        esp_hw_support
        esp_system
        vfs
        bootloader_support
)
if(CONFIG_NBL_H2_NGHTTP2)
    # The nghttp2 fallback is opt-in so that normal builds neither download nor compile it.
    # ESP-IDF 5.4 ignores Kconfig conditions in idf_component.yml, so the project adds it.
    idf_build_get_property(nbl_build_components BUILD_COMPONENTS)
    if(NOT "espressif__nghttp" IN_LIST nbl_build_components)
        message(FATAL_ERROR "CONFIG_NBL_H2_NGHTTP2 needs the nghttp2 component. Add it to your project with:\n"
                            "  idf.py add-dependency \"espressif/nghttp^1.65.0\"")
    endif()
    target_sources(${COMPONENT_LIB} PRIVATE "src/nbl_h2.c")
    idf_component_optional_requires(PRIVATE espressif__nghttp)
else()
    target_sources(${COMPONENT_LIB} PRIVATE "src/nbl_h2_lite.c")
endif()

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    PB_FIELD_32BIT=0
    WIREGUARD_MAX_PEERS=${CONFIG_NBL_MAX_PEERS}
)
# Vendored third-party code: silence known warnings and keep them from failing the build
set_source_files_properties(
    "vendor/tweetnacl/tweetnacl.c"
    "vendor/wireguard-lwip/wireguard.c"
    "vendor/wireguard-lwip/wireguardif.c"
    "vendor/wireguard-lwip/crypto.c"
    "vendor/wireguard-lwip/crypto/refc/x25519.c"
    "vendor/wireguard-lwip/crypto/refc/blake2s.c"
    "vendor/wireguard-lwip/crypto/refc/chacha20.c"
    "vendor/wireguard-lwip/crypto/refc/chacha20poly1305.c"
    "vendor/wireguard-lwip/crypto/refc/poly1305-donna.c"
    PROPERTIES COMPILE_OPTIONS "-Wno-unused-function;-Wno-unused-variable;-Wno-format;-Wno-sign-compare;-Wno-stringop-overread;-Wno-error=array-parameter;-Wno-error=array-bounds")
