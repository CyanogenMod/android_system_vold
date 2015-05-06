#include <stddef.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// General functions
int e4crypt_enable(const char* path);
int e4crypt_main(int argc, char* argv[]);
int e4crypt_change_password(const char* path, int crypt_type,
                            const char* password);
int e4crypt_crypto_complete(const char* path);
int e4crypt_check_passwd(const char* path, const char* password);
int e4crypt_get_password_type(const char* path);
const char* e4crypt_get_password(const char* path);
void e4crypt_clear_password(const char* path);
int e4crypt_restart(const char* path);
int e4crypt_get_field(const char* path, const char* fieldname,
                      char* value, size_t len);
int e4crypt_set_field(const char* path, const char* fieldname,
                      const char* value);

__END_DECLS
