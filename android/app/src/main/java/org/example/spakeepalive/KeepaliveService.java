package org.example.spakeepalive;
import android.app.*;
import android.content.*;
import android.os.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class KeepaliveService extends Service {
    static final String START="org.example.spakeepalive.START";
    static final String STOP="org.example.spakeepalive.STOP";
    static final String STOP_ALL="org.example.spakeepalive.STOP_ALL";
    // Runtime state is deliberately not persisted: no phantom activity after a process death.
    private static final ConcurrentMap<String,String> states=new ConcurrentHashMap<>();
    private static final Set<String> active=ConcurrentHashMap.newKeySet();
    static boolean isActive(String id){return active.contains(id);}
    static String state(String id){return states.getOrDefault(id,"Остановлено");}
    private final Map<String,Session> sessions=new HashMap<>(); // main thread only
    private final ScheduledExecutorService worker=Executors.newScheduledThreadPool(ProfileStore.MAX_PROFILES);
    private final Handler main=new Handler(Looper.getMainLooper());
    private PowerManager.WakeLock wake;
    private boolean foreground=false;
    private volatile boolean destroyed=false;
    private static class Session {
        final String id; final Profile profile;
        volatile boolean stopped=false;
        ScheduledFuture<?> future;
        Session(String id,Profile profile){this.id=id;this.profile=profile;}
    }
    @Override public IBinder onBind(Intent intent){return null;}
    @Override public void onCreate(){
        super.onCreate();
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("spa","Периодические SPA",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        String action=intent==null?STOP_ALL:intent.getAction();
        if(STOP_ALL.equals(action)){stopSelf();return START_NOT_STICKY;}
        String id=intent.getStringExtra("id");
        if(STOP.equals(action)){
            stop(id);if(sessions.isEmpty())stopSelf();else updateNotification();return START_NOT_STICKY;
        }
        // Every startForegroundService request gets its foreground acknowledgement,
        // including an invalid id, before profile IO or error handling.
        if(!foreground){startForeground(1,notification());foreground=true;}
        try {
            if(!START.equals(action) || id==null)throw new Exception("Invalid request");
            if(!sessions.containsKey(id)){
                Profile p=ProfileStore.list(this).get(id);
                if(p==null)throw new Exception("Profile missing");
                if(wake==null){
                    wake=getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,getPackageName()+":keepalive");
                    wake.acquire();
                }
                Session session=new Session(id,p);sessions.put(id,session);active.add(id);states.put(id,"Запуск");
                session.future=worker.scheduleWithFixedDelay(()->send(session),0,p.i("interval_seconds"),TimeUnit.SECONDS);
            }
        }catch(Exception e){if(id!=null)states.put(id,"Ошибка запуска");if(sessions.isEmpty())stopSelf();}
        updateNotification();return START_NOT_STICKY;
    }
    private Notification notification(){
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,KeepaliveService.class).setAction(STOP_ALL),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,"spa").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SPA Keepalive — активных профилей: "+sessions.size())
            .setContentText("Отправка по индивидуальным периодам").setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null,"Остановить все",stop).build()).build();
    }
    private void updateNotification(){if(!destroyed && foreground)getSystemService(NotificationManager.class).notify(1,notification());}
    private void stop(String id){
        Session s=sessions.remove(id);
        if(s!=null){synchronized(s){s.stopped=true;}s.future.cancel(true);}
        if(id!=null){active.remove(id);states.put(id,"Остановлено");}
    }
    private void send(Session s){
        byte[] key=null,hmac=null;
        try{
            if(s.stopped||destroyed)return;
            InetAddress address=null;
            for(InetAddress a:InetAddress.getAllByName(s.profile.s("server")))if(a instanceof Inet4Address){address=a;break;}
            if(address==null)throw new UnknownHostException();
            key=s.profile.key("key_base64",16,32);hmac=s.profile.key("hmac_key_base64",32,64);
            byte[] packet=NativeSpa.encode(s.profile.message(),s.profile.s("username"),s.profile.i("access_timeout_seconds"),key,hmac).getBytes(StandardCharsets.US_ASCII);
            synchronized(s){
                if(s.stopped||destroyed)return;
                try(DatagramSocket socket=new DatagramSocket()){
                    socket.send(new DatagramPacket(packet,packet.length,address,s.profile.i("spa_port")));
                }
            }
            status(s,"UDP отправлен в "+java.text.DateFormat.getTimeInstance().format(new Date())+"; приём не подтверждён");
        }catch(Exception|LinkageError e){status(s,"Ошибка отправки ("+e.getClass().getSimpleName()+"); повтор по таймеру");}
        finally{if(key!=null)Arrays.fill(key,(byte)0);if(hmac!=null)Arrays.fill(hmac,(byte)0);}
    }
    private void status(Session s,String text){
        main.post(()->{if(!destroyed && sessions.get(s.id)==s && !s.stopped)states.put(s.id,text);});
    }
    @Override public void onDestroy(){
        destroyed=true;
        for(String id:new ArrayList<>(sessions.keySet()))stop(id);
        worker.shutdownNow();main.removeCallbacksAndMessages(null);
        if(wake!=null&&wake.isHeld())wake.release();
        stopForeground(STOP_FOREGROUND_REMOVE);super.onDestroy();
    }
}
