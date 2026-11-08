package org.example.spakeepalive;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class ProfileImport {
    static JSONObject parse(String text) throws Exception {
        if (text.getBytes(StandardCharsets.UTF_8).length > 16384) throw new Exception("Profile too large");
        // Use the same duplicate-field rejecting parser as the plain profile.
        return Profile.parseObject(text);
    }
    static boolean encrypted(JSONObject value) { return value.optInt("version") == 2; }
    static String decrypt(JSONObject e, char[] password) throws Exception {
        if(e.length()!=7 || !e.has("version") || !e.has("format") || !e.has("kdf") || !e.has("iterations")
            || !e.has("salt") || !e.has("nonce") || !e.has("ciphertext")
            || !(e.get("version") instanceof Integer) || e.getInt("version")!=2
            || !(e.get("iterations") instanceof Integer)
            || !"spa-profile-aes256-gcm".equals(e.getString("format")) || !"pbkdf2-sha256".equals(e.getString("kdf")))
            throw new Exception("Unsupported encrypted profile");
        byte[] plain = ProfileCrypto.decrypt(password, ProfileCrypto.base64(e.getString("salt")),
            ProfileCrypto.base64(e.getString("nonce")), ProfileCrypto.base64(e.getString("ciphertext")), e.getInt("iterations"));
        try { return new String(plain, StandardCharsets.UTF_8); }
        finally { Arrays.fill(plain, (byte)0); }
    }
}
