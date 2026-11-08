package org.example.spakeepalive;
import android.Manifest;
import android.app.AlertDialog;
import android.content.*;
import android.os.*;
import android.provider.Settings;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.*;
import androidx.activity.ComponentActivity;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import com.journeyapps.barcodescanner.*;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;

public class MainActivity extends ComponentActivity {
    private LinearLayout rows;
    private TextView info;
    private final Map<String,TextView> statuses=new HashMap<>();
    private final Map<String,Button> toggles=new HashMap<>();
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService imports=Executors.newSingleThreadExecutor();
    private boolean busy=false;
    private final Runnable refresh=new Runnable(){public void run(){refreshStatus();handler.postDelayed(this,1000);}};
    private final ActivityResultLauncher<ScanOptions> scanner=registerForActivityResult(new ScanContract(),result->{
        if(result.getContents()!=null) importProfile(result.getContents());
    });
    private final ActivityResultLauncher<String[]> picker=registerForActivityResult(new ActivityResultContracts.OpenDocument(),uri->{
        if(uri==null)return;
        try(java.io.InputStream in=getContentResolver().openInputStream(uri)){
            java.io.ByteArrayOutputStream data=new java.io.ByteArrayOutputStream();byte[] buf=new byte[2048];int n;
            if(in==null)throw new Exception();
            while((n=in.read(buf))!=-1){data.write(buf,0,n);if(data.size()>16384)throw new Exception();}
            importProfile(new String(data.toByteArray(),java.nio.charset.StandardCharsets.UTF_8));
        }catch(Exception e){toast("Не удалось прочитать JSON (максимум 16 KiB)");}
    });
    @Override public void onCreate(Bundle state){
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(32,32,32,32);
        ScrollView scroll=new ScrollView(this);scroll.addView(box);setContentView(scroll);
        TextView title=new TextView(this);title.setText("SPA Keepalive 0.3.0");title.setTextSize(25);box.addView(title);
        info=new TextView(this);box.addView(info);
        button(box,"Импортировать QR",()->{if(!busy)scanner.launch(new ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Профиль SPA Keepalive").setBeepEnabled(false).setOrientationLocked(false));});
        button(box,"Импортировать JSON",()->{if(!busy)picker.launch(new String[]{"application/json","text/plain","application/octet-stream"});});
        button(box,"Остановить все",()->{stopService(new Intent(this,KeepaliveService.class));});
        button(box,"Настройки батареи",()->startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)));
        rows=new LinearLayout(this);rows.setOrientation(LinearLayout.VERTICAL);box.addView(rows);
        TextView hint=new TextView(this);hint.setText("До 16 профилей могут работать одновременно. После перезагрузки или остановки системой запустите нужные профили вручную. UDP не подтверждает принятие пакета сервером.");box.addView(hint);
        renderProfiles();
    }
    private void start(String id){
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED){
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},10);toast("Разрешите уведомления и повторите запуск");return;
        }
        try{startForegroundService(new Intent(this,KeepaliveService.class).setAction(KeepaliveService.START).putExtra("id",id));}
        catch(Exception e){toast("Не удалось запустить сервис");}
    }
    private void stop(String id){
        if(KeepaliveService.isActive(id))startService(new Intent(this,KeepaliveService.class).setAction(KeepaliveService.STOP).putExtra("id",id));
    }
    private void importProfile(String text){
        if(busy)return;
        try{
            JSONObject envelope=ProfileImport.parse(text);
            if(!ProfileImport.encrypted(envelope)){confirmImport(new Profile(this,text));return;}
            EditText password=new EditText(this);password.setSingleLine(true);password.setSaveEnabled(false);
            password.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
            password.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO);
            AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Зашифрованный профиль")
                .setMessage("Введите пароль для импорта. Затем профиль будет храниться под защитой Android Keystore.")
                .setView(password).setPositiveButton("Открыть",null).setNegativeButton("Отмена",(d,w)->password.setText("")).create();
            dialog.setOnShowListener(ignored->{
                dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                    char[] pass=new char[password.length()];password.getText().getChars(0,pass.length,pass,0);
                    password.setText("");dialog.dismiss();busy=true;refreshStatus();
                    // Password derivation runs off the UI thread and never enters saved instance state.
                    imports.execute(()->{
                        Profile profile=null;
                        try{profile=new Profile(getApplicationContext(),ProfileImport.decrypt(envelope,pass));}catch(Exception ignoredError){}
                        finally{Arrays.fill(pass,'\0');}
                        Profile ready=profile;
                        handler.post(()->{busy=false;if(isFinishing()||isDestroyed())return;refreshStatus();
                            if(ready==null)toast("Неверный пароль, повреждённый или неподдерживаемый профиль. Повторите импорт.");else confirmImport(ready);
                        });
                    });
                });
            });dialog.show();
        }catch(Exception e){toast("Некорректный профиль");}
    }
    private void confirmImport(Profile p){
        new AlertDialog.Builder(this).setTitle("Добавить профиль?")
            .setMessage(p.s("name")+"\n"+p.s("server")+":"+p.i("spa_port")+"\n"+p.s("access")+"\nПериод: "+p.i("interval_seconds")+" с; доступ: "+p.i("access_timeout_seconds")+" с\nIP: "+p.s("allow_ip"))
            .setPositiveButton("Добавить",(d,v)->{try{ProfileStore.add(this,p);renderProfiles();toast("Профиль добавлен");}catch(Exception e){toast("Не удалось сохранить профиль (максимум 16)");}})
            .setNegativeButton("Отмена",null).show();
    }
    private void renderProfiles(){
        if(rows==null)return;rows.removeAllViews();statuses.clear();toggles.clear();
        try{
            Map<String,Profile> profiles=ProfileStore.list(this);
            if(profiles.isEmpty()){TextView empty=new TextView(this);empty.setText("Добавьте профиль через QR или JSON");rows.addView(empty);}
            for(Map.Entry<String,Profile> entry:profiles.entrySet()){
                String id=entry.getKey();Profile p=entry.getValue();
                TextView label=new TextView(this);label.setTextSize(18);
                label.setText("\n"+p.s("name")+" ["+id.substring(0,8)+"]\n"+p.s("server")+":"+p.i("spa_port")+"\n"+p.s("access")+"; каждые "+p.i("interval_seconds")+" с");rows.addView(label);
                TextView status=new TextView(this);rows.addView(status);statuses.put(id,status);
                Button toggle=button(rows,"Запустить",()->{if(KeepaliveService.isActive(id))stop(id);else start(id);});toggles.put(id,toggle);
                button(rows,"Удалить профиль",()->new AlertDialog.Builder(this).setMessage("Остановить и удалить «"+p.s("name")+"»?")
                    .setPositiveButton("Удалить",(d,v)->{try{stop(id);ProfileStore.remove(this,id);renderProfiles();}catch(Exception e){toast("Не удалось удалить профиль");}})
                    .setNegativeButton("Отмена",null).show());
            }
        }catch(Exception e){toast("Не удалось прочитать сохранённые профили");}
        refreshStatus();
    }
    private void refreshStatus(){
        if(info==null)return;
        boolean exempt=getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName());
        info.setText((busy?"Расшифровка…\n":"")+"Батарея: "+(exempt?"без оптимизации":"ограничения включены"));
        for(String id:statuses.keySet()){
            statuses.get(id).setText((KeepaliveService.isActive(id)?"Активен. ":"")+KeepaliveService.state(id));
            toggles.get(id).setText(KeepaliveService.isActive(id)?"Остановить":"Запустить");
        }
    }
    private Button button(LinearLayout box,String text,Runnable action){Button b=new Button(this);b.setText(text);b.setOnClickListener(v->action.run());box.addView(b);return b;}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override public void onResume(){super.onResume();handler.post(refresh);}
    @Override public void onPause(){handler.removeCallbacks(refresh);super.onPause();}
    @Override public void onDestroy(){imports.shutdown();handler.removeCallbacks(refresh);super.onDestroy();}
}
