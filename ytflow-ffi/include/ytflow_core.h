#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>
namespace ytflow_core { struct Connection; }

namespace ytflow_core {

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

void ytflow_result_free(FfiResult *result);

FfiResult ytflow_buffer_free(void *ptr, uintptr_t metadata);

FfiResult ytflow_runtime_new();

FfiResult ytflow_runtime_free(Runtime *runtime);

} // extern "C"

} // namespace ytflow_core
