#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef __cplusplus
namespace ytflow_core {
#endif // __cplusplus

typedef struct ytflow_connection ytflow_connection;
typedef struct ytflow_database ytflow_database;

#ifdef __cplusplus
} // namespace ytflow_core
#endif // __cplusplus


#ifdef __cplusplus
namespace ytflow_core {
#endif // __cplusplus

typedef struct ytflow_runtime ytflow_runtime;

typedef struct ytflow_result_content {
  void *_0;
  uintptr_t _1;
} ytflow_result_content;

typedef char *ytflow_error_fields[3];

typedef union ytflow_result_data {
  struct ytflow_result_content res;
  ytflow_error_fields err;
} ytflow_result_data;

typedef struct ytflow_result {
  uint32_t code;
  union ytflow_result_data data;
} ytflow_result;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

const char *ytflow_get_version(void);

struct ytflow_result ytflow_plugin_verify(const char *plugin,
                                          uint16_t plugin_version,
                                          const uint8_t *param,
                                          uintptr_t param_len);

#if defined(_WIN32)
struct ytflow_result ytflow_db_new_win32(const uint16_t *path, uintptr_t len);
#endif

#if defined(__unix__)
struct ytflow_result ytflow_db_new_unix(const uint8_t *path, uintptr_t len);
#endif

struct ytflow_result ytflow_db_free(ytflow_database *db);

struct ytflow_result ytflow_db_conn_new(const ytflow_database *db);

struct ytflow_result ytflow_db_conn_free(ytflow_connection *conn);

struct ytflow_result ytflow_profiles_get_all(const ytflow_connection *conn);

struct ytflow_result ytflow_plugins_get_by_profile(uint32_t profile_id,
                                                   const ytflow_connection *conn);

struct ytflow_result ytflow_plugins_get_entry(uint32_t profile_id, const ytflow_connection *conn);

struct ytflow_result ytflow_profile_create(const char *name,
                                           const char *locale,
                                           const ytflow_connection *conn);

struct ytflow_result ytflow_profile_update(uint32_t profile_id,
                                           const char *name,
                                           const char *locale,
                                           const ytflow_connection *conn);

struct ytflow_result ytflow_profile_delete(uint32_t profile_id, const ytflow_connection *conn);

struct ytflow_result ytflow_plugin_create(uint32_t profile_id,
                                          const char *name,
                                          const char *desc,
                                          const char *plugin,
                                          uint16_t plugin_version,
                                          const uint8_t *param,
                                          uintptr_t param_len,
                                          const ytflow_connection *conn);

struct ytflow_result ytflow_plugin_update(uint32_t plugin_id,
                                          uint32_t profile_id,
                                          const char *name,
                                          const char *desc,
                                          const char *plugin,
                                          uint16_t plugin_version,
                                          const uint8_t *param,
                                          uintptr_t param_len,
                                          const ytflow_connection *conn);

struct ytflow_result ytflow_plugin_delete(uint32_t plugin_id, const ytflow_connection *conn);

struct ytflow_result ytflow_plugin_set_as_entry(uint32_t plugin_id,
                                                uint32_t profile_id,
                                                const ytflow_connection *conn);

struct ytflow_result ytflow_plugin_unset_as_entry(uint32_t plugin_id,
                                                  uint32_t profile_id,
                                                  const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_get_all(const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_get_by_id(uint32_t proxy_group_id,
                                                  const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_create(const char *name,
                                               const char *type,
                                               const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_create_subscription(const char *name,
                                                            const char *format,
                                                            const char *url,
                                                            ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_rename(uint32_t proxy_group_id,
                                               const char *name,
                                               const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_group_delete(uint32_t proxy_group_id,
                                               const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_subscription_query_by_proxy_group_id(uint32_t proxy_group_id,
                                                                       const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_subscription_update_retrieved_by_proxy_group_id(uint32_t proxy_group_id,
                                                                                  const uint64_t *upload_bytes_used,
                                                                                  const uint64_t *download_bytes_used,
                                                                                  const uint64_t *bytes_total,
                                                                                  const char *expires_at,
                                                                                  const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_get_by_proxy_group(uint32_t proxy_group_id,
                                                     const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_create(uint32_t proxy_group_id,
                                         const char *name,
                                         const uint8_t *proxy,
                                         uintptr_t proxy_len,
                                         uint16_t proxy_version,
                                         const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_update(uint32_t proxy_id,
                                         const char *name,
                                         const uint8_t *proxy,
                                         uintptr_t proxy_len,
                                         uint16_t proxy_version,
                                         const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_delete(uint32_t proxy_id, const ytflow_connection *conn);

struct ytflow_result ytflow_proxy_reorder(uint32_t proxy_group_id,
                                          int32_t range_start_order,
                                          int32_t range_end_order,
                                          int32_t moves,
                                          ytflow_connection *conn);

struct ytflow_result ytflow_proxy_batch_update_by_group(uint32_t proxy_group_id,
                                                        const uint8_t *new_proxies_buf,
                                                        uintptr_t new_proxies_buf_len,
                                                        ytflow_connection *conn);

struct ytflow_result ytflow_resource_get_all(const ytflow_connection *conn);

struct ytflow_result ytflow_resource_delete(uint32_t resource_id, const ytflow_connection *conn);

struct ytflow_result ytflow_resource_create_with_url(const char *key,
                                                     const char *type,
                                                     const char *local_file,
                                                     const char *url,
                                                     ytflow_connection *conn);

struct ytflow_result ytflow_resource_create_with_github_release(const char *key,
                                                                const char *type,
                                                                const char *local_file,
                                                                const char *github_username,
                                                                const char *github_repo,
                                                                const char *asset_name,
                                                                ytflow_connection *conn);

struct ytflow_result ytflow_resource_url_query_by_resource_id(uint32_t resource_id,
                                                              const ytflow_connection *conn);

struct ytflow_result ytflow_resource_url_update_retrieved_by_resource_id(uint32_t resource_id,
                                                                         const char *etag,
                                                                         const char *last_modified,
                                                                         const ytflow_connection *conn);

struct ytflow_result ytflow_resource_github_release_query_by_resource_id(uint32_t resource_id,
                                                                         const ytflow_connection *conn);

struct ytflow_result ytflow_resource_github_release_update_retrieved_by_resource_id(uint32_t resource_id,
                                                                                    const char *git_tag,
                                                                                    const char *release_title,
                                                                                    const ytflow_connection *conn);

void ytflow_result_free(struct ytflow_result *result);

struct ytflow_result ytflow_buffer_free(void *ptr, uintptr_t metadata);

struct ytflow_result ytflow_runtime_new(void);

struct ytflow_result ytflow_runtime_free(struct ytflow_runtime *runtime);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#ifdef __cplusplus
} // namespace ytflow_core
#endif // __cplusplus
