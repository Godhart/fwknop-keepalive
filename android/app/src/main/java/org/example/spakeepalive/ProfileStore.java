package org.example.spakeepalive;
import android.content.Context;
import android.security.keystore.*;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Device-bound encryption; no exported provider, no cloud backup. */
final class ProfileStore {
    static final String ALIAS="spa-profile-v1";
    static javax.crypto.SecretKey key() throws Exception {
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
        if(!ks.containsAlias(ALIAS)) {
            KeyGenerator gen=KeyGenerator.getInstance("AES","AndroidKeyStore");
            gen.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
            gen.generateKey();
        }
        return (javax.crypto.SecretKey)ks.getKey(ALIAS,null);
    }
    static void save(Context c,Profile p) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,key());
        String iv=Base64.getEncoder().encodeToString(cipher.getIV());
        String encrypted=Base64.getEncoder().encodeToString(cipher.doFinal(p.json.toString().getBytes(StandardCharsets.UTF_8)));
        if(!c.getSharedPreferences("private",0).edit().putString("iv",iv).putString("data",encrypted).commit()) throw new Exception("Не удалось сохранить профиль");
    }
    static Profile load(Context c) throws Exception {
        android.content.SharedPreferences prefs=c.getSharedPreferences("private",0);
        String data=prefs.getString("data",null);
        if(data==null) throw new Exception("Сначала импортируйте QR");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.getDecoder().decode(prefs.getString("iv",""))));
        return new Profile(c,new String(cipher.doFinal(Base64.getDecoder().decode(data)),StandardCharsets.UTF_8));
    }
    static void clear(Context c) throws Exception {
        c.getSharedPreferences("private",0).edit().clear().commit();
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore"); ks.load(null); ks.deleteEntry(ALIAS);
    }
}
