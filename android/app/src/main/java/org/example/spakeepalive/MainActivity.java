package org.example.spakeepalive;
import android.Manifest;
import android.app.AlertDialog;
import android.content.*;
import android.os.*;
import android.provider.Settings;
import android.view.WindowManager;
import android.widget.*;
import androidx.activity.ComponentActivity;
import androidx.activity.result.ActivityResultLauncher;
import com.journeyapps.barcodescanner.*;

public class MainActivity extends ComponentActivity {
    private TextView info;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final Runnable refresh=new Runnable(){public void run(){render();handler.postDelayed(this,2000);}};
    private final ActivityResultLauncher<ScanOptions> scanner=registerForActivityResult(new ScanContract(),result->{
        if(result.getContents()!=null) importProfile(result.getContents());
    });
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL); box.setPadding(32,32,32,32);
        ScrollView scroll=new ScrollView(this);scroll.addView(box);setContentView(scroll);
        TextView title=new TextView(this);title.setText("SPA Keepalive 0.1.0");title.setTextSize(25);box.addView(title);
        info=new TextView(this);info.setTextSize(16);box.addView(info);
        button(box,"Импортировать QR",()->scanner.launch(new ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Профиль SPA Keepalive").setBeepEnabled(false).setOrientationLocked(false)));
        button(box,"Запустить",()->{
            try {
                ProfileStore.load(this);
                if(Build.VERSION.SDK_INT>=33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},10);
                    toast("Разрешите уведомления, затем нажмите Запустить ещё раз");return;
                }
                startForegroundService(new Intent(this,KeepaliveService.class));
            } catch(Exception e){toast("Сначала импортируйте корректный профиль");}
        });
        button(box,"Остановить",()->stopService(new Intent(this,KeepaliveService.class)));
        button(box,"Настройки батареи",()->startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)));
        button(box,"Удалить профиль",()->new AlertDialog.Builder(this).setMessage("Остановить отправку и удалить сохранённые ключи?").setPositiveButton("Удалить",(d,v)->{
            stopService(new Intent(this,KeepaliveService.class));
            try{ProfileStore.clear(this);render();}catch(Exception e){toast("Ошибка удаления");}
        }).setNegativeButton("Отмена",null).show());
        TextView hint=new TextView(this);hint.setText("Разрешите работу без оптимизации батареи. Постоянная отправка расходует заряд. После перезагрузки или принудительной остановки запустите приложение вручную. UDP не подтверждает открытие доступа сервером.");box.addView(hint);
    }
    private void importProfile(String text) {
        try {
            Profile p=new Profile(this,text);
            new AlertDialog.Builder(this).setTitle("Импортировать профиль?")
                .setMessage(p.s("name")+"\n"+p.s("server")+":"+p.i("spa_port")+"\n"+p.s("access")+"\nКаждые "+p.i("interval_seconds")+" с; доступ "+p.i("access_timeout_seconds")+" с\nIP: "+p.s("allow_ip"))
                .setPositiveButton("Импортировать",(d,v)->{
                    stopService(new Intent(this,KeepaliveService.class));
                    try {ProfileStore.save(this,p);render();toast("Сохранено. Нажмите Запустить");}catch(Exception e){toast("Не удалось сохранить");}
                }).setNegativeButton("Отмена",null).show();
        }catch(Exception e){toast("QR не соответствует формату профиля v1");}
    }
    private void button(LinearLayout box,String text,Runnable action){Button b=new Button(this);b.setText(text);b.setOnClickListener(v->action.run());box.addView(b);}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    private void render(){
        if(info==null)return;
        String text="Профиль не загружен";
        try{Profile p=ProfileStore.load(this);text=p.s("name")+"\n"+p.s("server")+":"+p.i("spa_port")+"\n"+p.s("access")+"; период "+p.i("interval_seconds")+" с";}catch(Exception ignored){}
        boolean exempt=getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName());
        info.setText(text+"\nБатарея: "+(exempt?"без оптимизации":"ограничения включены")+"\nПоследнее событие: "+getSharedPreferences("status",0).getString("last","нет")+"\n");
    }
    @Override public void onResume(){super.onResume();handler.post(refresh);}
    @Override public void onPause(){handler.removeCallbacks(refresh);super.onPause();}
}
