#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>
namespace ytflow_core { struct Connection; }

namespace ytflow_core {

constexpr static const uintptr_t ACTION_LIMIT = 15;

struct Database;

struct Runtime;

struct FfiResultPtrType {
  void *_0;
  uintptr_t _1;
};

using FfiErrorFields = char*[3];

union FfiResultUnion {
  FfiResultPtrType res;
  FfiErrorFields err;
};

struct FfiResult {
  uint32_t code;
  FfiResultUnion data;
};

extern "C" {

const char *ytflow_get_version();

FfiResult ytflow_plugin_verify(const char *plugin,
                               uint16_t plugin_version,
                               const uint8_t *param,
                               uintptr_t param_len);

#if defined(_WIN32)
FfiResult ytflow_db_new_win32(const uint16_t *path, uintptr_t len);
#endif

#if defined(__unix__)
FfiResult ytflow_db_new_unix(const uint8_t *path, uintptr_t len);
#endif

FfiResult ytflow_db_free(Database *db);

FfiResult ytflow_db_conn_new(const Database *db);

FfiResult ytflow_db_conn_free(Connection *conn);

FfiResult ytflow_profiles_get_all(const Connection *conn);

FfiResult ytflow_plugins_get_by_profile(uint32_t profile_id, const Connection *conn);

FfiResult ytflow_plugins_get_entry(uint32_t profile_id, const Connection *conn);

FfiResult ytflow_profile_create(const char *name, const char *locale, const Connection *conn);

FfiResult ytflow_profile_update(uint32_t profile_id,
                                const char *name,
                                const char *locale,
                                const Connection *conn);

FfiResult ytflow_profile_delete(uint32_t profile_id, const Connection *conn);

FfiResult ytflow_plugin_create(uint32_t profile_id,
                               const char *name,
                               const char *desc,
                               const char *plugin,
                               uint16_t plugin_version,
                               const uint8_t *param,
                               uintptr_t param_len,
                               const Connection *conn);

FfiResult ytflow_plugin_update(uint32_t plugin_id,
                               uint32_t profile_id,
                               const char *name,
                               const char *desc,
                               const char *plugin,
                               uint16_t plugin_version,
                               const uint8_t *param,
                               uintptr_t param_len,
                               const Connection *conn);

FfiResult ytflow_plugin_delete(uint32_t plugin_id, const Connection *conn);

FfiResult ytflow_plugin_set_as_entry(uint32_t plugin_id,
                                     uint32_t profile_id,
                                     const Connection *conn);

FfiResult ytflow_plugin_unset_as_entry(uint32_t plugin_id,
                                       uint32_t profile_id,
                                       const Connection *conn);

FfiResult ytflow_proxy_group_get_all(const Connection *conn);

FfiResult ytflow_proxy_group_get_by_id(uint32_t proxy_group_id, const Connection *conn);

FfiResult ytflow_proxy_group_create(const char *name, const char *type, const Connection *conn);

FfiResult ytflow_proxy_group_create_subscription(const char *name,
                                                 const char *format,
                                                 const char *url,
                                                 Connection *conn);

FfiResult ytflow_proxy_group_rename(uint32_t proxy_group_id,
                                    const char *name,
                                    const Connection *conn);

FfiResult ytflow_proxy_group_delete(uint32_t proxy_group_id, const Connection *conn);

FfiResult ytflow_proxy_subscription_query_by_proxy_group_id(uint32_t proxy_group_id,
                                                            const Connection *conn);

FfiResult ytflow_proxy_subscription_update_retrieved_by_proxy_group_id(uint32_t proxy_group_id,
                                                                       const uint64_t *upload_bytes_used,
                                                                       const uint64_t *download_bytes_used,
                                                                       const uint64_t *bytes_total,
                                                                       const char *expires_at,
                                                                       const Connection *conn);

FfiResult ytflow_proxy_get_by_proxy_group(uint32_t proxy_group_id, const Connection *conn);

FfiResult ytflow_proxy_create(uint32_t proxy_group_id,
                              const char *name,
                              const uint8_t *proxy,
                              uintptr_t proxy_len,
                              uint16_t proxy_version,
                              const Connection *conn);

FfiResult ytflow_proxy_update(uint32_t proxy_id,
                              const char *name,
                              const uint8_t *proxy,
                              uintptr_t proxy_len,
                              uint16_t proxy_version,
                              const Connection *conn);

FfiResult ytflow_proxy_delete(uint32_t proxy_id, const Connection *conn);

FfiResult ytflow_proxy_reorder(uint32_t proxy_group_id,
                               int32_t range_start_order,
                               int32_t range_end_order,
                               int32_t moves,
                               Connection *conn);

FfiResult ytflow_proxy_batch_update_by_group(uint32_t proxy_group_id,
                                             const uint8_t *new_proxies_buf,
                                             uintptr_t new_proxies_buf_len,
                                             Connection *conn);

FfiResult ytflow_resource_get_all(const Connection *conn);

FfiResult ytflow_resource_delete(uint32_t resource_id, const Connection *conn);

FfiResult ytflow_resource_create_with_url(const char *key,
                                          const char *type,
                                          const char *local_file,
                                          const char *url,
                                          Connection *conn);

FfiResult ytflow_resource_create_with_github_release(const char *key,
                                                     const char *type,
                                                     const char *local_file,
                                                     const char *github_username,
                                                     const char *github_repo,
                                                     const char *asset_name,
                                                     Connection *conn);

FfiResult ytflow_resource_url_query_by_resource_id(uint32_t resource_id, const Connection *conn);

FfiResult ytflow_resource_url_update_retrieved_by_resource_id(uint32_t resource_id,
                                                              const char *etag,
                                                              const char *last_modified,
                                                              const Connection *conn);

FfiResult ytflow_resource_github_release_query_by_resource_id(uint32_t resource_id,
                                                              const Connection *conn);

FfiResult ytflow_resource_github_release_update_retrieved_by_resource_id(uint32_t resource_id,
                                                                         const char *git_tag,
                                                                         const char *release_title,
                                                                         const Connection *conn);

void ytflow_result_free(FfiResult *result);

FfiResult ytflow_buffer_free(void *ptr, uintptr_t metadata);

FfiResult ytflow_runtime_new();

FfiResult ytflow_runtime_free(Runtime *runtime);

#if defined(_WIN32)
extern int X509_STORE_up_ref(void *v);
#endif

} // extern "C"

} // namespace ytflow_core
