#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>
#include <time.h>

#include "../src/signal_protocol.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "session_pre_key.h"
#include "curve.h"
#include "ratchet.h"
#include "protocol.h"
#include "test_common.h"
#include "key_helper.h"
#define DJB_KEY_LEN 32

static signal_protocol_address bob_address = {
        "+14152222222", 12, 1
};

signal_context *global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

void run_interaction(signal_protocol_store_context *alice_store, signal_protocol_store_context *bob_store);
int test_basic_pre_key_v3_decrypt_callback(session_cipher *cipher, signal_buffer *plaintext, void *decrypt_context);

void test_lock(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void test_unlock(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

void test_setup()
{
    int result;

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    result = signal_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    signal_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);

    result = signal_context_set_locking_functions(global_context, test_lock, test_unlock);
    ck_assert_int_eq(result, 0);
}

void test_teardown()
{
    signal_context_destroy(global_context);

    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}

//Test Schnorr proof verification. Disregard any protocol after verification.
START_TEST(test_schnorr_verification)
{
    int iterations = 1000;
    double bob_signed_pre_key_runtime_sum = 0;
    double bob_bundle_runtime_sum = 0;
    double alice_verify_bob_runtime_sum = 0;
    double bob_verify_alice_runtime_sum = 0;
    double total_runtime_sum = 0;
    double bob_signed_pre_key_runtime_avg;
    double bob_bundle_runtime_avg;
    double alice_verify_bob_runtime_avg;
    double bob_verify_alice_runtime_avg;
    double total_runtime_avg;
    int i;

    for(i = 0; i < iterations; i++)
    {
        double bob_signed_pre_key_runtime;
        double bob_bundle_runtime;
        double alice_verify_bob_runtime;
        double bob_verify_alice_runtime;
        double total_runtime;

        clock_t total_begin = clock();

        int64_t timestamp = 1411152577000LL;

        int result = 0;
        session_record *bob_record = 0;
        session_state *state = 0;

        /* Create Alice's data store and session builder */
        signal_protocol_store_context *alice_store = 0;
        setup_test_store_context(&alice_store, global_context);
        session_builder *alice_session_builder = 0;
        result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
        ck_assert_int_eq(result, 0);

        /* Create Bob's data store and pre key bundle */
        signal_protocol_store_context *bob_store = 0;
        setup_test_store_context(&bob_store, global_context);

        uint32_t bob_local_registration_id = 0;
        result = signal_protocol_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
        ck_assert_int_eq(result, 0);

        ec_key_pair *bob_pre_key_pair = 0;
        result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
        ck_assert_int_eq(result, 0);

        ratchet_identity_key_pair *bob_identity_key_pair = 0;
        result = signal_protocol_identity_get_key_pair(bob_store, &bob_identity_key_pair);
        ck_assert_int_eq(result, 0);

        //Generate Bob's signed pre key with actual Schnorr proof values included
        clock_t bob_signed_pre_key_begin = clock();
        session_signed_pre_key *bob_signed_pre_key = 0;
        result = signal_protocol_key_helper_generate_signed_pre_key(&bob_signed_pre_key,
                bob_identity_key_pair, 22, timestamp, global_context);
        ck_assert_int_eq(result, 0);
        clock_t bob_signed_pre_key_end = clock();
        bob_signed_pre_key_runtime = (double)(bob_signed_pre_key_end - bob_signed_pre_key_begin) / CLOCKS_PER_SEC;
        bob_signed_pre_key_runtime_sum += bob_signed_pre_key_runtime;
        ec_key_pair *bob_signed_pre_key_pair = session_signed_pre_key_get_key_pair(bob_signed_pre_key);

        signal_buffer *bob_signed_pre_key_public_serialized = 0;
        result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
                ec_key_pair_get_public(bob_signed_pre_key_pair));
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_signed_pre_key_signature = 0;
        result = curve_calculate_signature(global_context,
                &bob_signed_pre_key_signature,
                ratchet_identity_key_pair_get_private(bob_identity_key_pair),
                signal_buffer_data(bob_signed_pre_key_public_serialized),
                signal_buffer_len(bob_signed_pre_key_public_serialized));
        ck_assert_int_eq(result, 0);

        clock_t bob_bundle_begin = clock();
        session_pre_key_bundle *bob_pre_key = 0;
        result = session_pre_key_bundle_create(&bob_pre_key,
                bob_local_registration_id,
                1, /* device ID */
                31337, /* pre key ID */
                ec_key_pair_get_public(bob_pre_key_pair),
                22, /* signed pre key ID */
                ec_key_pair_get_public(bob_signed_pre_key_pair),
                signal_buffer_data(bob_signed_pre_key_signature),
                signal_buffer_len(bob_signed_pre_key_signature),
                ratchet_identity_key_pair_get_public(bob_identity_key_pair),
                session_signed_pre_key_get_Rhatfull(bob_signed_pre_key),
                session_signed_pre_key_get_shat(bob_signed_pre_key),
                session_signed_pre_key_get_chat(bob_signed_pre_key),
                session_signed_pre_key_get_Yfull(bob_signed_pre_key));
        ck_assert_int_eq(result, 0);
        clock_t bob_bundle_end = clock();
        bob_bundle_runtime = (double)(bob_bundle_end - bob_bundle_begin) / CLOCKS_PER_SEC;
        bob_bundle_runtime_sum += bob_bundle_runtime;

        signal_buffer_free(bob_signed_pre_key_public_serialized);

        /* 
            Alice processes Bob's pre key bundle.
            She can verify Bob's Schnorr proof from within
            session_builder_process_pre_key_bundle().
        */
        clock_t alice_verify_bob_begin = clock();
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
        ck_assert_int_eq(result, 0);
        clock_t alice_verify_bob_end = clock();
        alice_verify_bob_runtime = (double)(alice_verify_bob_end - alice_verify_bob_begin) / CLOCKS_PER_SEC;
        alice_verify_bob_runtime_sum += alice_verify_bob_runtime;
         
        /* Bob loads session state, including Alice's Schnorr proof */
        clock_t bob_verify_alice_begin = clock();
        result = signal_protocol_session_load_session(alice_store, &bob_record, &bob_address);
        state = session_record_get_state(bob_record);

        /*Bob can verify Alice's Schnorr proof*/
        result = bobs_schnorr_check_of_alice(state);
        ck_assert_int_eq(result, 0); 
        clock_t bob_verify_alice_end = clock();
        bob_verify_alice_runtime = (double)(bob_verify_alice_end - bob_verify_alice_begin) / CLOCKS_PER_SEC;
        bob_verify_alice_runtime_sum += bob_verify_alice_runtime;

        clock_t total_end = clock();
        total_runtime = (double)(total_end - total_begin) / CLOCKS_PER_SEC;
        total_runtime_sum += total_runtime;


        /* Cleanup */
        SIGNAL_UNREF(bob_pre_key);
        signal_buffer_free(bob_signed_pre_key_signature);
        SIGNAL_UNREF(bob_pre_key_pair);
        SIGNAL_UNREF(bob_signed_pre_key_pair);
        SIGNAL_UNREF(bob_identity_key_pair);
        signal_protocol_store_context_destroy(bob_store);
        session_builder_free(alice_session_builder);
        signal_protocol_store_context_destroy(alice_store);
    }
    bob_signed_pre_key_runtime_avg = bob_signed_pre_key_runtime_sum/iterations;
    bob_bundle_runtime_avg = bob_bundle_runtime_sum/iterations;
    alice_verify_bob_runtime_avg = alice_verify_bob_runtime_sum/iterations;
    bob_verify_alice_runtime_avg = bob_verify_alice_runtime_sum/iterations;
    total_runtime_avg = total_runtime_sum/iterations;
    printf("ITERATIONS: %i\n", iterations);
    printf("AVERAGE RUNTIMES:\n");
    printf("\tbob signed pre key: %f seconds\n", bob_signed_pre_key_runtime_avg);
    printf("\tbob bundle: %f seconds\n", bob_bundle_runtime_avg);
    printf("\talice verify bob: %f seconds\n", alice_verify_bob_runtime_avg);
    printf("\tbob_verify_alice: %f seconds\n", bob_verify_alice_runtime_avg);
    printf("\ttotal: %f seconds\n", total_runtime_avg);
}
END_TEST

Suite *session_builder_suite(void)
{
    Suite *suite = suite_create("benchmarks");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_schnorr_verification);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = session_builder_suite();
    runner = srunner_create(suite);

    //allows for breakpoint setting in test processes
    srunner_set_fork_status(runner, CK_NOFORK);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
