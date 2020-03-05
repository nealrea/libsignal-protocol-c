#include "key_helper.h"

#include <assert.h>

#include "session_pre_key.h"
#include "ratchet.h"
#include "curve.h"
#include "signal_protocol_internal.h"
#include "utlist.h"
#include "sc.h"
#include <string.h> 
#include "ge.h"
#include <openssl/hmac.h>
#define DJB_KEY_LEN 32

struct signal_protocol_key_helper_pre_key_list_node
{
    session_pre_key *element;
    struct signal_protocol_key_helper_pre_key_list_node *next;
};

int signal_protocol_key_helper_generate_identity_key_pair(ratchet_identity_key_pair **key_pair, signal_context *global_context)
{
    int result = 0;
    ratchet_identity_key_pair *result_pair = 0;
    ec_key_pair *ec_pair = 0;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;

    assert(global_context);

    result = curve_generate_key_pair(global_context, &ec_pair);
    if(result < 0) {
        goto complete;
    }

    public_key = ec_key_pair_get_public(ec_pair);
    private_key = ec_key_pair_get_private(ec_pair);

    result = ratchet_identity_key_pair_create(
            &result_pair, public_key, private_key);

complete:
    if(result >= 0) {
        *key_pair = result_pair;
    }
    SIGNAL_UNREF(ec_pair);
    return result;
}

int signal_protocol_key_helper_generate_registration_id(uint32_t *registration_id, int extended_range, signal_context *global_context)
{
    uint32_t range;
    uint32_t id_value;
    int result = 0;

    assert(global_context);
    assert(global_context->crypto_provider.random_func);

    if(extended_range == 0) {
        range = 16380;
    }
    else if(extended_range == 1) {
        range = INT32_MAX - 1;
    }
    else {
        return SG_ERR_INVAL;
    }

    result = global_context->crypto_provider.random_func(
            (uint8_t *)(&id_value), sizeof(id_value),
            global_context->crypto_provider.user_data);
    if(result < 0) {
        return result;
    }

    id_value = (id_value % range) + 1;

    *registration_id = id_value;

    return 0;
}

int signal_protocol_key_helper_get_random_sequence(int *value, int max, signal_context *global_context)
{
    int result = 0;
    int32_t result_value;

    assert(global_context);
    assert(global_context->crypto_provider.random_func);

    result = global_context->crypto_provider.random_func(
            (uint8_t *)(&result_value), sizeof(result_value),
            global_context->crypto_provider.user_data);
    if(result < 0) {
        return result;
    }

    result_value = ((result_value & 0x7FFFFFFF) % max);

    *value = result_value;

    return 0;
}

int signal_protocol_key_helper_generate_pre_keys(signal_protocol_key_helper_pre_key_list_node **head,
        unsigned int start, unsigned int count,
        signal_context *global_context)
{
    int result = 0;
    ec_key_pair *ec_pair = 0;
    session_pre_key *pre_key = 0;
    signal_protocol_key_helper_pre_key_list_node *result_head = 0;
    signal_protocol_key_helper_pre_key_list_node *cur_node = 0;
    signal_protocol_key_helper_pre_key_list_node *node = 0;
    unsigned int start_index = start - 1;
    unsigned int i;

    assert(global_context);

    for(i = 0; i < count; i++) {
        uint32_t id = 0;
        result = curve_generate_key_pair(global_context, &ec_pair);
        if(result < 0) {
            goto complete;
        }

        id = ((start_index + i) % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1;

        result = session_pre_key_create(&pre_key, id, ec_pair);
        if(result < 0) {
            goto complete;
        }

        SIGNAL_UNREF(ec_pair);
        ec_pair = 0;

        node = malloc(sizeof(signal_protocol_key_helper_pre_key_list_node));
        if(!node) {
            result = SG_ERR_NOMEM;
            goto complete;
        }
        node->element = pre_key;
        node->next = 0;
        if(!result_head) {
            result_head = node;
            cur_node = node;
        }
        else {
            cur_node->next = node;
            cur_node = node;
        }
        pre_key = 0;
        node = 0;
    }

complete:
    if(ec_pair) {
        SIGNAL_UNREF(ec_pair);
    }
    if(pre_key) {
        SIGNAL_UNREF(pre_key);
    }
    if(node) {
        free(node);
    }
    if(result < 0) {
        if(result_head) {
            signal_protocol_key_helper_pre_key_list_node *tmp_node;
            LL_FOREACH_SAFE(result_head, cur_node, tmp_node) {
                LL_DELETE(result_head, cur_node);
                SIGNAL_UNREF(cur_node->element);
                free(cur_node);
            }
        }
    }
    else {
        *head = result_head;
    }
    return result;
}

session_pre_key *signal_protocol_key_helper_key_list_element(const signal_protocol_key_helper_pre_key_list_node *node)
{
    assert(node);
    assert(node->element);
    return node->element;
}

signal_protocol_key_helper_pre_key_list_node *signal_protocol_key_helper_key_list_next(const signal_protocol_key_helper_pre_key_list_node *node)
{
    assert(node);
    return node->next;
}

void signal_protocol_key_helper_key_list_free(signal_protocol_key_helper_pre_key_list_node *head)
{
    if(head) {
        signal_protocol_key_helper_pre_key_list_node *cur_node;
        signal_protocol_key_helper_pre_key_list_node *tmp_node;
        LL_FOREACH_SAFE(head, cur_node, tmp_node) {
            LL_DELETE(head, cur_node);
            SIGNAL_UNREF(cur_node->element);
            free(cur_node);
        }
    }
}

int signal_protocol_key_helper_generate_rhat(signal_context *global_context, signal_buffer **rhat_buf) {
    ec_private_key *rhat = 0;
    int result;
    result = curve_generate_private_key(global_context, &rhat);
    if (result >= 0) {
       *rhat_buf = signal_buffer_create(get_private_data(rhat), DJB_KEY_LEN);
    }
    return result;
}

// Not sure if any other test needs the signal_hmac_sha256_init version from test_common_crypto 
// But we need the one from test_common_openssl
int hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    HMAC_CTX *ctx = HMAC_CTX_new();
    if(!ctx) {
        return SG_ERR_NOMEM;
    }
#else
    HMAC_CTX *ctx = malloc(sizeof(HMAC_CTX));
    if(!ctx) {
        return SG_ERR_NOMEM;
    }
    HMAC_CTX_init(ctx);
#endif

    *hmac_context = ctx;

    if(HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), 0) != 1) {
        return SG_ERR_UNKNOWN;
    }

    return 0;
}

int hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len) {
    HMAC_CTX *ctx = hmac_context;
    int result = HMAC_Update(ctx, data, data_len);
    return (result == 1) ? 0 : -1;
}

int hmac_sha256_final(void *hmac_context, signal_buffer **output) {
    int result = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC_CTX *ctx = hmac_context;

    if(HMAC_Final(ctx, md, &len) != 1) {
        return SG_ERR_UNKNOWN;
    }

    signal_buffer *output_buffer = signal_buffer_create(md, len);
    if(!output_buffer) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    *output = output_buffer;

complete:
    return result;
}

int hmac_sha256_cleanup(void *hmac_context) {
    if(hmac_context) {
        HMAC_CTX *ctx = hmac_context;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        HMAC_CTX_free(ctx);
#else
        HMAC_CTX_cleanup(ctx);
        free(ctx);
#endif
    }
}

int signal_protocol_key_helper_generate_chat(signal_context *global_context, const ratchet_identity_key_pair *identity_key_pair, ec_public_key *public_key, signal_buffer **chat_buf) {
    void *hmac_context = 0;
    uint8_t csalt[DJB_KEY_LEN];
    memset(csalt, 0, sizeof(csalt));
    int result;
    // initialize HMAC_CTX
    result = hmac_sha256_init(&hmac_context, csalt, DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // digest input message stream B
    result = hmac_sha256_update(hmac_context, get_public_data(ratchet_identity_key_pair_get_public(identity_key_pair)), DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // digest input message stream Y
    result = hmac_sha256_update(hmac_context, get_public_data(public_key), DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // place authentication code in chat_buf
    result = hmac_sha256_final(hmac_context, chat_buf);
    if (result < 0) {
        goto complete;
    }
    
    hmac_sha256_cleanup(hmac_context);

 complete:
    return result;
}

void signal_protocol_key_helper_generate_shat(ec_key_pair *ec_pair, signal_buffer *chat_buf, signal_buffer *rhat_buf, signal_buffer *shat_buf) {
    sc_muladd(shat_buf->data, get_private_data(ec_key_pair_get_private(ec_pair)), signal_buffer_data(chat_buf), signal_buffer_data(rhat_buf));
}

int signal_protocol_key_helper_generate_signed_pre_key(session_signed_pre_key **signed_pre_key,
        const ratchet_identity_key_pair *identity_key_pair,
        uint32_t signed_pre_key_id,
        uint64_t timestamp,
        signal_context *global_context)
{
    int result = 0;
    session_signed_pre_key *result_signed_pre_key = 0;
    ec_key_pair *ec_pair = 0;
    signal_buffer *public_buf = 0;
    signal_buffer *signature_buf = 0;
    signal_buffer *rhat_buf = 0;
    ge_p3 Rhatfull;
    signal_buffer *Rhatfull_buf = 0;
    signal_buffer *shat_buf = 0;
    signal_buffer *chat_buf = 0;
    ge_p3 Yfull;
    signal_buffer *Yfull_buf = 0;
    rhat_buf = signal_buffer_alloc(DJB_KEY_LEN);
    chat_buf = signal_buffer_alloc(DJB_KEY_LEN);
    shat_buf = signal_buffer_alloc(DJB_KEY_LEN);
    Rhatfull_buf = signal_buffer_alloc(128);
    Yfull_buf = signal_buffer_alloc(128);
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;

    assert(global_context);

    result = curve_generate_key_pair(global_context, &ec_pair);
    if(result < 0) {
        goto complete;
    }

    public_key = ec_key_pair_get_public(ec_pair);
    result = ec_public_key_serialize(&public_buf, public_key);
    if(result < 0) {
        goto complete;
    }

    private_key = ratchet_identity_key_pair_get_private(identity_key_pair);

    result = curve_calculate_signature(global_context,
            &signature_buf,
            private_key,
            signal_buffer_data(public_buf),
            signal_buffer_len(public_buf));
    if(result < 0) {
        goto complete;
    }

    // generate random value for rhat
    result = signal_protocol_key_helper_generate_rhat(global_context, &rhat_buf);
    if (result < 0) {
        goto complete;
    }    

    // generate hash value for chat
    result = signal_protocol_key_helper_generate_chat(global_context, identity_key_pair, public_key, &chat_buf);
    if (result < 0) {
        goto complete;
    }

    // generate value for shat 
    // shat = rhat + chat*y
    signal_protocol_key_helper_generate_shat(ec_pair, chat_buf, rhat_buf, shat_buf);

    // generate value for Rhatfull
    ge_scalarmult_base(&Rhatfull, rhat_buf->data);
    ge_p3_tobytes_128(Rhatfull_buf->data, &Rhatfull);

    // generate value for Yfull
    ge_scalarmult_base(&Yfull, get_private_data(ec_key_pair_get_private(ec_pair)));
    ge_p3_tobytes_128(Yfull_buf->data, &Yfull);

    result = session_signed_pre_key_create(&result_signed_pre_key,
            signed_pre_key_id, timestamp, ec_pair,
            signal_buffer_data(signature_buf),
            signal_buffer_len(signature_buf),
            signal_buffer_data(rhat_buf),
            signal_buffer_data(Rhatfull_buf),
            signal_buffer_data(shat_buf),
            signal_buffer_data(chat_buf),
            signal_buffer_data(Yfull_buf));

complete:
    SIGNAL_UNREF(ec_pair);
    signal_buffer_free(public_buf);
    signal_buffer_free(signature_buf);
    if(result >= 0) {
        *signed_pre_key = result_signed_pre_key;
    }
    return result;
}

int signal_protocol_key_helper_generate_sender_signing_key(ec_key_pair **key_pair, signal_context *global_context)
{
    int result;

    assert(global_context);

    result = curve_generate_key_pair(global_context, key_pair);

    return result;
}

int signal_protocol_key_helper_generate_sender_key(signal_buffer **key_buffer, signal_context *global_context)
{
    int result = 0;
    signal_buffer *result_buffer = 0;

    assert(global_context);

    result_buffer = signal_buffer_alloc(32);
    if(!result_buffer) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = signal_crypto_random(global_context,
            signal_buffer_data(result_buffer),
            signal_buffer_len(result_buffer));

complete:
    if(result < 0) {
        signal_buffer_free(result_buffer);
    }
    else {
        *key_buffer = result_buffer;
        result = 0;
    }
    return result;
}

int signal_protocol_key_helper_generate_sender_key_id(uint32_t *key_id, signal_context *global_context)
{
    int result;
    int value;

    result = signal_protocol_key_helper_get_random_sequence(&value, INT32_MAX, global_context);

    if(result >= 0) {
        *key_id = (uint32_t)value;
    }
    return result;
}
