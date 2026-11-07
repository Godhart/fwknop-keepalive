#include <stdlib.h>
#include <string.h>
#include "vendor/lib/fko.h"
#include "packet.h"

int spa_packet(const char *message, const char *username, int timeout,
    const unsigned char *key, int key_len, const unsigned char *hmac, int hmac_len,
    char **output) {
    fko_ctx_t ctx=NULL;
    char *data=NULL;
    int rc;
    if(!output) return FKO_ERROR_INVALID_DATA;
    *output=NULL;
    if(!message || !username || !key || !hmac || key_len<16 || key_len>32 || hmac_len<32 || hmac_len>64 || timeout<30 || timeout>86400)
        return FKO_ERROR_INVALID_DATA;
    if((rc=fko_new(&ctx))!=FKO_SUCCESS) return rc;
#define CHECK(call) do { rc=(call); if(rc!=FKO_SUCCESS) goto done; } while(0)
    CHECK(fko_set_username(ctx,username));
    CHECK(fko_set_spa_message_type(ctx,FKO_CLIENT_TIMEOUT_ACCESS_MSG));
    CHECK(fko_set_spa_message(ctx,message));
    CHECK(fko_set_spa_client_timeout(ctx,timeout));
    CHECK(fko_set_spa_digest_type(ctx,FKO_DIGEST_SHA256));
    CHECK(fko_set_spa_encryption_mode(ctx,FKO_ENC_MODE_CBC));
    CHECK(fko_set_spa_hmac_type(ctx,FKO_HMAC_SHA256));
    CHECK(fko_spa_data_final(ctx,(const char*)key,key_len,(const char*)hmac,hmac_len));
    CHECK(fko_get_spa_data(ctx,&data));
    *output=strdup(data);
    if(!*output) rc=FKO_ERROR_MEMORY_ALLOCATION;
 done:
    fko_destroy(ctx);
    return rc;
}
