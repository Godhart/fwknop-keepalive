"""Optional local YAML editor; imports the same validation/export functions as CLI."""
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import customtkinter as ctk
import yaml
from profile_crypto import is_encrypted, unlock
from spa_config import ROOT, UniqueLoader, validate, generate, private_write, with_new_keys

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('SPA Keepalive 0.3.0 — редактор профиля')
        self.geometry('880x700')
        ctk.CTkLabel(self,text='YAML содержит секретные ключи. Генерация QR выполняется локально.').pack(pady=8)
        bar=ctk.CTkFrame(self); bar.pack(fill='x',padx=12)
        for label, fn in [('Открыть',self.open),('Сохранить YAML',self.save),('Проверить',self.check),('Создать QR и bash',self.export)]:
            ctk.CTkButton(bar,text=label,command=fn,width=160).pack(side='left',padx=5,pady=8)
        keys=ctk.CTkFrame(self); keys.pack(fill='x',padx=12,pady=6)
        ctk.CTkLabel(keys,text='Ключ: байт').pack(side='left',padx=4)
        self.key_len=ctk.CTkOptionMenu(keys,values=[str(i) for i in range(16,33)],width=70); self.key_len.set('32'); self.key_len.pack(side='left')
        ctk.CTkLabel(keys,text='HMAC: байт').pack(side='left',padx=4)
        self.hmac_len=ctk.CTkOptionMenu(keys,values=[str(i) for i in range(32,65)],width=70); self.hmac_len.set('32'); self.hmac_len.pack(side='left')
        ctk.CTkButton(keys,text='Новый профиль',command=self.new_profile,width=140).pack(side='left',padx=5)
        ctk.CTkButton(keys,text='Заменить ключи',command=self.rekey,width=140).pack(side='left',padx=5)
        vault=ctk.CTkFrame(self); vault.pack(fill='x',padx=12)
        self.encrypt_vault=ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(vault,text='Шифровать открытый / новый vault',variable=self.encrypt_vault).pack(side='left',padx=6,pady=8)
        ctk.CTkButton(vault,text='Обновить vault.yaml',command=self.update_vault).pack(side='right',padx=6)
        self.protect_export=ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self,text='Шифровать JSON, QR и bash паролем',variable=self.protect_export).pack(pady=5)
        self.editor=ctk.CTkTextbox(self,font=('monospace',14)); self.editor.pack(fill='both',expand=True,padx=12,pady=12)
        self.set_profile(with_new_keys(yaml.safe_load((ROOT/'profile.example.yaml').read_text())))
    def set_profile(self,c):
        self.editor.delete('1.0','end')
        self.editor.insert('1.0',yaml.safe_dump(c,allow_unicode=True,sort_keys=False))
    def new_profile(self):
        if messagebox.askyesno('Новый профиль','Заменить текст редактора новым профилем и новыми ключами? Несохранённые изменения будут потеряны.'):
            self.safe(lambda: self.set_profile(with_new_keys(yaml.safe_load((ROOT/'profile.example.yaml').read_text()),int(self.key_len.get()),int(self.hmac_len.get()))))
    def rekey(self):
        if messagebox.askyesno('Новые ключи','Сгенерировать новые SPA-ключи? После сохранения потребуется обновить vault, сервер, QR и bash.'):
            self.safe(lambda: self.set_profile(with_new_keys(yaml.load(self.editor.get('1.0','end'),Loader=UniqueLoader),int(self.key_len.get()),int(self.hmac_len.get()))))
    def update_vault(self):
        def action():
            from vault_update import update_vault
            c=self.config_data()
            path=filedialog.asksaveasfilename(title='Выберите существующий vault.yaml / vault.yml или имя нового',defaultextension='.yaml',confirmoverwrite=False)
            if not path: return
            target=Path(path)
            encrypted=False
            if target.exists():
                with target.open('rb') as f: encrypted=f.read(15).startswith(b'$ANSIBLE_VAULT;')
            encrypt=self.encrypt_vault.get()
            password=None
            if encrypted or encrypt:
                password=filedialog.askopenfilename(title='Файл пароля Ansible Vault')
                if not password:return
            if not messagebox.askyesno('Обновить локальный vault',
                'Заменить только spa_key_base64 и spa_hmac_key_base64 ключами из редактора?\n'
                +('Файл будет зашифрован.' if encrypted or encrypt else 'Файл останется открытым YAML.')
                +'\nБудет создана резервная копия существующего файла. Сервер автоматически не обновляется. Сохраните профиль отдельно.'):
                return
            result=update_vault(c,path,password_file=password,encrypt=encrypt,create=not target.exists())
            messagebox.showinfo('Vault','Обновлён' if result['changed'] else 'Ключи уже совпадают')
        self.safe(action)
    def config_data(self):
        return validate(yaml.load(self.editor.get('1.0','end'), Loader=UniqueLoader))
    def safe(self,fn):
        try: fn()
        except Exception as e: messagebox.showerror('Ошибка',str(e) if isinstance(e,ValueError) else type(e).__name__)
    def open(self):
        path=filedialog.askopenfilename(filetypes=[('YAML / JSON','*.yaml *.yml *.json')])
        if path:
            def action():
                p=Path(path)
                if p.stat().st_size>16384: raise ValueError('Файл слишком велик')
                text=p.read_text()
                data=yaml.load(text,Loader=UniqueLoader)
                if is_encrypted(data):
                    password=simpledialog.askstring('Пароль','Пароль профиля:',show='*',parent=self)
                    if password is None:return
                    text=yaml.safe_dump(validate(unlock(data,password)),allow_unicode=True,sort_keys=False)
                self.editor.delete('1.0','end'); self.editor.insert('1.0',text)
            self.safe(action)
    def save(self):
        path=filedialog.asksaveasfilename(defaultextension='.yaml')
        if path: self.safe(lambda: private_write(path,self.editor.get('1.0','end').encode()))
    def check(self):
        def action(): self.config_data(); messagebox.showinfo('Профиль','Проверка пройдена')
        self.safe(action)
    def export(self):
        parent=filedialog.askdirectory(title='Родительский каталог для нового каталога spa-export')
        if parent:
            def action():
                password=None
                if self.protect_export.get():
                    password=simpledialog.askstring('Защита профиля','Пароль для JSON, QR и bash:',show='*',parent=self)
                    if password is None:return
                    confirm=simpledialog.askstring('Подтверждение','Повторите пароль:',show='*',parent=self)
                    if confirm is None:return
                    if not password or password!=confirm:raise ValueError('Пустой пароль или пароли не совпадают')
                generate(self.config_data(),Path(parent)/'spa-export',password=password)
                messagebox.showinfo('Готово','Создан каталог spa-export: QR, JSON и keepalive.sh')
            self.safe(action)
if __name__=='__main__': App().mainloop()
