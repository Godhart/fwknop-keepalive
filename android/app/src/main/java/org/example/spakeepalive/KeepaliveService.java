package org.example.spakeepalive;
import android.app.*;
import android.content.*;
import android.os.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;

public class KeepaliveService extends Service {
    private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor();
    private PowerManager.WakeLock wake;
    private Profile profile;
    private boolean started=false;
    private volatile boolean stopped=false;
    static final String STOP="org.example.spakeepalive.STOP";
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(intent!=null && STOP.equals(intent.getAction())) {stopSelf(); return START_NOT_STICKY;}
        if(started) return START_NOT_STICKY;
        started=true;
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("spa","Периодические SPA",NotificationManager.IMPORTANCE_LOW));
        startForeground(1,notification("Запуск"));
        try {
            profile=ProfileStore.load(this);
            wake=getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,getPackageName()+":keepalive");
            // User-enabled continuous mode: CPU stays available between sends.
            // This still requires a Doze exemption for network access while idle.
            wake.acquire();
            worker.scheduleWithFixedDelay(this::send,0,profile.i("interval_seconds"),TimeUnit.SECONDS);
        } catch(Exception e) { status("Не удалось загрузить профиль; импортируйте QR заново"); stopSelf(); }
        return START_NOT_STICKY; // No surprise restart after user/system termination.
    }
    private Notification notification(String text) {
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,KeepaliveService.class).setAction(STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,"spa").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SPA Keepalive работает").setContentText(text).setContentIntent(open)
            .setOngoing(true).addAction(new Notification.Action.Builder(null,"Остановить",stop).build()).build();
    }
    private void status(String text) {
        if(stopped) return;
        getSharedPreferences("status",0).edit().putString("last",text).apply();
        getSystemService(NotificationManager.class).notify(1,notification(text));
    }
    private void send() {
        if(stopped) return;
        byte[] key=null,hmac=null;
        try {
            // Resolve every time: reconnecting and changes in server DNS need no restart.
            InetAddress address=null;
            for(InetAddress candidate:InetAddress.getAllByName(profile.s("server")))
                if(candidate instanceof Inet4Address) {address=candidate; break;}
            if(address==null) throw new UnknownHostException();
            key=profile.key("key_base64",16,32); hmac=profile.key("hmac_key_base64",32,64);
            byte[] packet=NativeSpa.encode(profile.message(),profile.s("username"),profile.i("access_timeout_seconds"),key,hmac).getBytes(StandardCharsets.US_ASCII);
            if(stopped) return;
            try(DatagramSocket socket=new DatagramSocket()) {
                socket.send(new DatagramPacket(packet,packet.length,address,profile.i("spa_port")));
            }
            status("UDP отправлен в "+java.text.DateFormat.getTimeInstance().format(new java.util.Date())+"; приём не подтверждён");
        } catch(Exception | LinkageError e) {status("Ошибка отправки ("+e.getClass().getSimpleName()+"); повтор по таймеру");}
        finally {if(key!=null) Arrays.fill(key,(byte)0); if(hmac!=null) Arrays.fill(hmac,(byte)0);}
    }
    @Override public void onDestroy() {
        stopped=true; worker.shutdownNow();
        if(wake!=null && wake.isHeld()) wake.release();
        getSharedPreferences("status",0).edit().putString("last","Остановлено").apply();
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy();
    }
}
