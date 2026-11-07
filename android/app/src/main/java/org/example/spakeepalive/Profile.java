package org.example.spakeepalive;

import android.content.Context;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** Schema scalar validation is shared with the Python tool through the asset. */
final class Profile {
    final JSONObject json;
    Profile(Context context, String text) throws Exception {
        if (text.getBytes(StandardCharsets.UTF_8).length > 8192) throw new Exception("QR слишком велик");
        // Android JSONObject silently accepts duplicate fields; reject them explicitly.
        JSONTokener tok = new JSONTokener(text);
        if (tok.nextClean() != '{') throw new Exception("Ожидался JSON объект");
        JSONObject data = new JSONObject();
        if (tok.nextClean() != '}') {
            tok.back();
            while (true) {
                Object key = tok.nextValue();
                if (!(key instanceof String) || data.has((String)key) || tok.nextClean() != ':') throw new Exception("Некорректные или повторные поля");
                data.put((String)key, tok.nextValue());
                char ch = tok.nextClean();
                if (ch == '}') break;
                if (ch != ',') throw new Exception("Некорректный JSON");
            }
        }
        if (tok.nextClean() != 0) throw new Exception("Данные после JSON");
        String schemaText;
        try (java.io.InputStream in=context.getAssets().open("profile.schema.json")) {
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk=new byte[4096]; int n;
            while((n=in.read(chunk))!=-1) buf.write(chunk,0,n);
            schemaText = new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }
        JSONObject schema = new JSONObject(schemaText), props = schema.getJSONObject("properties");
        JSONArray required = schema.getJSONArray("required");
        for (int i=0;i<required.length();i++) if (!data.has(required.getString(i))) throw new Exception("Отсутствует поле " + required.getString(i));
        Iterator<String> keys = data.keys();
        while (keys.hasNext()) {
            String k=keys.next();
            if (!props.has(k)) throw new Exception("Неизвестное поле");
            JSONObject rule=props.getJSONObject(k); Object value=data.get(k);
            if (rule.getString("type").equals("integer")) {
                if (!(value instanceof Integer || value instanceof Long)) throw new Exception("Нужно целое число: "+k);
                long n=((Number)value).longValue();
                if (rule.has("const") && n!=rule.getLong("const") || rule.has("minimum") && n<rule.getLong("minimum") || rule.has("maximum") && n>rule.getLong("maximum")) throw new Exception("Вне диапазона: "+k);
            } else {
                if (!(value instanceof String)) throw new Exception("Нужна строка: "+k);
                String s=(String)value;
                if (s.length()<rule.optInt("minLength",0) || s.length()>rule.optInt("maxLength",8192) || rule.has("pattern") && !Pattern.compile(rule.getString("pattern")).matcher(s).matches()) throw new Exception("Некорректное поле: "+k);
            }
        }
        json=data;
        if (!s("allow_ip").equals("source")) {
            String[] parts=s("allow_ip").split("\\."); long ip=0;
            for(String v:parts) {
                int n=Integer.parseInt(v);
                if(n>255 || !Integer.toString(n).equals(v)) throw new Exception("Некорректный IPv4");
                ip=(ip<<8)|n;
            }
            if(ip==0 || ip==0xffffffffL || (ip>>28)==14) throw new Exception("Недопустимый IPv4");
        }
        for(String pair:s("access").split(",")) {
            int port=Integer.parseInt(pair.split("/")[1]);
            if(port<1 || port>65535) throw new Exception("Некорректный порт");
        }
        if(i("interval_seconds")>=i("access_timeout_seconds")) throw new Exception("Период должен быть меньше срока доступа");
        key("key_base64",16,32); key("hmac_key_base64",32,64);
        if(s("key_base64").equals(s("hmac_key_base64"))) throw new Exception("Ключи должны отличаться");
    }
    byte[] key(String field,int min,int max) throws Exception {
        byte[] raw;
        try {raw=Base64.getDecoder().decode(s(field));} catch(IllegalArgumentException e) {throw new Exception("Некорректный ключ");}
        if(raw.length<min || raw.length>max || !Base64.getEncoder().encodeToString(raw).equals(s(field))) throw new Exception("Некорректный ключ");
        return raw;
    }
    String s(String key) { return json.optString(key); }
    int i(String key) { return json.optInt(key); }
    String message() { return (s("allow_ip").equals("source") ? "0.0.0.0" : s("allow_ip"))+","+s("access"); }
}
