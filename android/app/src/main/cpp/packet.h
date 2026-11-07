#pragma once
/* output must be freed by caller; never reuse generated packet for another send */
int spa_packet(const char *message, const char *username, int timeout,
    const unsigned char *key, int key_len, const unsigned char *hmac, int hmac_len,
    char **output);
