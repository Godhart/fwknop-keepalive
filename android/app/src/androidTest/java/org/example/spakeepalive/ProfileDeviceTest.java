package org.example.spakeepalive;

import android.content.Context;
import android.content.Intent;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.Cipher;
import org.json.JSONObject;
import org.junit.*;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

/** Run on a dedicated test installation: these tests reset its saved profiles. */
@RunWith(AndroidJUnit4.class)
public class ProfileDeviceTest {
    private Context context;
    private ActivityScenario<MainActivity> activity;

    @Before public void before() throws Exception {
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        context.stopService(new Intent(context,KeepaliveService.class));
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        context.getSharedPreferences("private",0).edit().clear().commit();
        activity=ActivityScenario.launch(MainActivity.class);
    }
    @After public void after() {
        context.stopService(new Intent(context,KeepaliveService.class));
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        if(activity!=null)activity.close();
        context.getSharedPreferences("private",0).edit().clear().commit();
    }
    private Profile profile(int port) throws Exception {
        byte[] key=new byte[32], hmac=new byte[32];Arrays.fill(key,(byte)1);Arrays.fill(hmac,(byte)2);
        return new Profile(context,new JSONObject().put("version",1).put("name","Test")
            .put("server","127.0.0.1").put("spa_port",port).put("access","tcp/443")
            .put("allow_ip","source").put("username","mobile").put("interval_seconds",15)
            .put("access_timeout_seconds",60).put("key_base64",Base64.getEncoder().encodeToString(key))
            .put("hmac_key_base64",Base64.getEncoder().encodeToString(hmac)).toString());
    }
    @Test public void legacyMigrationAndIndependentRemoval() throws Exception {
        Profile p=profile(62201);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,ProfileStore.key(true));
        context.getSharedPreferences("private",0).edit()
            .putString("data",Base64.getEncoder().encodeToString(cipher.doFinal(p.json.toString().getBytes(StandardCharsets.UTF_8))))
            .putString("iv",Base64.getEncoder().encodeToString(cipher.getIV())).commit();
        Map<String,Profile> migrated=ProfileStore.list(context);
        assertEquals(1,migrated.size());
        assertFalse(context.getSharedPreferences("private",0).contains("data"));
        String old=migrated.keySet().iterator().next();
        String second=ProfileStore.add(context,p);
        assertNotEquals(old,second);
        assertEquals(2,ProfileStore.list(context).size());
        ProfileStore.remove(context,old);
        assertEquals(Collections.singleton(second),ProfileStore.list(context).keySet());
        assertEquals(p.s("key_base64"),ProfileStore.list(context).get(second).s("key_base64"));
    }
    private void start(String id) {
        activity.onActivity(a->a.startForegroundService(new Intent(a,KeepaliveService.class)
            .setAction(KeepaliveService.START).putExtra("id",id)));
    }
    private void receive(DatagramSocket socket) throws Exception {
        DatagramPacket packet=new DatagramPacket(new byte[4096],4096);socket.receive(packet);
        assertTrue(packet.getLength()>50);
    }
    @Test public void twoProfilesSendAndStopIndependently() throws Exception {
        try(DatagramSocket a=new DatagramSocket(0,InetAddress.getByName("127.0.0.1"));
            DatagramSocket b=new DatagramSocket(0,InetAddress.getByName("127.0.0.1"))) {
            a.setSoTimeout(5000);b.setSoTimeout(5000);
            String first=ProfileStore.add(context,profile(a.getLocalPort()));
            String second=ProfileStore.add(context,profile(b.getLocalPort()));
            start(first);start(second);receive(a);receive(b);
            assertTrue(KeepaliveService.isActive(first));assertTrue(KeepaliveService.isActive(second));
            activity.onActivity(x->x.startService(new Intent(x,KeepaliveService.class)
                .setAction(KeepaliveService.STOP).putExtra("id",first)));
            // The surviving profile must send its NEXT scheduled packet.
            b.setSoTimeout(22000);receive(b);
            assertFalse(KeepaliveService.isActive(first));assertTrue(KeepaliveService.isActive(second));
            a.setSoTimeout(1000);
            try {receive(a);fail("Stopped profile sent another packet");}catch(SocketTimeoutException expected){}
            activity.onActivity(x->x.stopService(new Intent(x,KeepaliveService.class)));
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            assertFalse(KeepaliveService.isActive(second));
        }
    }
    @Test public void limitDoesNotReplaceProfiles() throws Exception {
        for(int i=0;i<ProfileStore.MAX_PROFILES;i++)ProfileStore.add(context,profile(62201));
        Set<String> ids=ProfileStore.list(context).keySet();
        try {ProfileStore.add(context,profile(62201));fail("Limit ignored");}catch(Exception expected){}
        assertEquals(ids,ProfileStore.list(context).keySet());
    }
}
