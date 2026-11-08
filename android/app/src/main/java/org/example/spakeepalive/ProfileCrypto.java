package org.example.spakeepalive;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Shared wire format with tools/profile_crypto.py. No Android-specific crypto. */
final class ProfileCrypto {
    static byte[] decrypt(char[] password, byte[] salt, byte[] nonce, byte[] ciphertext, int iterations) throws Exception {
        if (iterations != 600000 || salt.length != 16 || nonce.length != 12 || ciphertext.length < 17 || ciphertext.length > 8192
            || password.length == 0 || new String(password).getBytes(StandardCharsets.UTF_8).length > 1024)
            throw new IllegalArgumentException("Invalid encrypted profile");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        byte[] key = null;
        try {
            key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD("fwknop-keepalive/profile/v2".getBytes(StandardCharsets.US_ASCII));
            return cipher.doFinal(ciphertext);
        } finally {
            spec.clearPassword();
            if (key != null) Arrays.fill(key, (byte)0);
        }
    }
    static byte[] base64(String text) {
        byte[] bytes = Base64.getDecoder().decode(text);
        if (!Base64.getEncoder().encodeToString(bytes).equals(text)) throw new IllegalArgumentException("Invalid base64");
        return bytes;
    }
}
