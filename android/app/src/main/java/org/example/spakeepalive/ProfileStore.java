package org.example.spakeepalive;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.*;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** One encrypted list, atomically committed; legacy v1 profile migrates on first read. */
final class ProfileStore {
    static final int MAX_PROFILES=16;
    static final String ALIAS="spa-profile-v1";
    static javax.crypto.SecretKey key(boolean create) throws Exception {
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
        if(!ks.containsAlias(ALIAS)) {
            if(!create) throw new Exception("Device key unavailable");
            KeyGenerator gen=KeyGenerator.getInstance("AES","AndroidKeyStore");
            gen.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
            gen.generateKey();
        }
        return (javax.crypto.SecretKey)ks.getKey(ALIAS,null);
    }
    private static String decrypt(SharedPreferences prefs,String dataKey,String ivKey) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,Base64.getDecoder().decode(prefs.getString(ivKey,""))));
        return new String(cipher.doFinal(Base64.getDecoder().decode(prefs.getString(dataKey,""))),StandardCharsets.UTF_8);
    }
    private static void write(Context c,LinkedHashMap<String,Profile> profiles) throws Exception {
        JSONArray array=new JSONArray();
        for(Map.Entry<String,Profile> entry:profiles.entrySet())
            array.put(new JSONObject().put("id",entry.getKey()).put("profile",entry.getValue().json));
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,key(true));
        byte[] data=cipher.doFinal(array.toString().getBytes(StandardCharsets.UTF_8));
        // Migration removes legacy ciphertext in the SAME transaction as the new list.
        if(!c.getSharedPreferences("private",0).edit().putString("profiles",Base64.getEncoder().encodeToString(data))
            .putString("profiles_iv",Base64.getEncoder().encodeToString(cipher.getIV())).remove("data").remove("iv").commit())
            throw new Exception("Не удалось сохранить профили");
    }
    static synchronized LinkedHashMap<String,Profile> list(Context c) throws Exception {
        SharedPreferences prefs=c.getSharedPreferences("private",0);
        LinkedHashMap<String,Profile> result=new LinkedHashMap<>();
        if(prefs.contains("profiles")) {
            JSONArray array=new JSONArray(decrypt(prefs,"profiles","profiles_iv"));
            if(array.length()>MAX_PROFILES) throw new Exception("Too many profiles");
            for(int i=0;i<array.length();i++) {
                JSONObject row=array.getJSONObject(i); String id=row.getString("id");
                UUID.fromString(id);
                if(result.containsKey(id)) throw new Exception("Duplicate id");
                result.put(id,new Profile(c,row.getJSONObject("profile").toString()));
            }
        } else if(prefs.contains("data")) {
            result.put(UUID.randomUUID().toString(),new Profile(c,decrypt(prefs,"data","iv")));
            write(c,result);
        }
        return result;
    }
    static synchronized String add(Context c,Profile profile) throws Exception {
        LinkedHashMap<String,Profile> profiles=list(c);
        if(profiles.size()>=MAX_PROFILES) throw new Exception("Не более 16 профилей");
        String id=UUID.randomUUID().toString();profiles.put(id,profile);write(c,profiles);return id;
    }
    static synchronized void remove(Context c,String id) throws Exception {
        LinkedHashMap<String,Profile> profiles=list(c);profiles.remove(id);write(c,profiles);
    }
}
