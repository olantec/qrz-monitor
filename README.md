# QRZ Monitor

---


## 🇧🇷 Português

Projeto oficial do QRZ Digital: [https://qrz.digital](https://qrz.digital)

Monitor de logs de contatos de rádio, integrando com a API do QRZ Digital. Compatível com softwares como JTDX, M1NN, WSJT-X e outros da família hamradio.

### Funcionalidades
- Recebe logs via UDP de softwares de rádio digital
- Envia automaticamente os logs para a API do QRZ Digital
- Armazena logs pendentes e faz reenvio automático em caso de falha de conexão
- Suporte a modo texto (console) e modo gráfico (tray icon, Linux/X11)
- Configuração automática de usuário, senha e porta UDP via arquivo `config.ini` ou prompts interativos
- Autenticação segura com token
- Compatível com Linux
- Instalação automatizada via `install-linux.sh` (Linux) ou `install-windows.bat` (Windows)
- Escolha de modo gráfico ou texto ao iniciar (`start-linux.sh`)
- Interface gráfica com ícone na bandeja, menu de status e janela de configurações (Linux/X11)
- Modo texto para ambientes sem interface gráfica
- Repositório atualizado automaticamente via `git pull` no instalador
- Detecção e instalação automática de dependências essenciais
- Suporte a múltiplos idiomas na documentação

### Requisitos
- Python 3.12+
- Linux (modo gráfico requer ambiente X11)
- Dependências: requests, pystray, Pillow (instale via pip)


### Obtenção do código fonte
Para baixar o QRZ Monitor, instale o Git e clone o repositório:
```bash
sudo apt install git        # Debian/Ubuntu/Raspberry Pi
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```
No Windows, baixe e instale o Git em https://git-scm.com/download/win e use o Git Bash ou o Prompt de Comando:
```cmd
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```

### Instalação
Linux:
```bash
chmod +x install-linux.sh start-linux.sh
./install-linux.sh
```
Windows:
1. Instale o Python 3.12+ pelo site oficial: https://www.python.org/downloads/windows/
2. Clique com o botão direito em install-windows.bat e escolha "Executar como administrador" para instalar as dependências.
3. Depois, clique com o botão direito em start-windows.bat e escolha "Executar como administrador" para iniciar o monitor.
   Ou, no Prompt de Comando (cmd) ou PowerShell, execute:
   ```cmd
   install-windows.bat
   start-windows.bat
   ```

### Uso
Linux:
```bash
./start-linux.sh
```
Windows:
```cmd
install-windows.bat
start-windows.bat
```
No primeiro uso, informe seu indicativo e senha quando solicitado.
O monitor ficará aguardando logs dos softwares compatíveis na porta UDP configurada (padrão: 2333).
Logs enviados com sucesso são confirmados no console. Logs pendentes são reenviados automaticamente.

### Configuração
Edite o arquivo `config.ini` para definir:
- Username: seu indicativo
- Password: sua senha
- UDPPort: porta UDP para receber os logs

### Modo gráfico
Se executado em ambiente gráfico Linux/X11, o monitor pode exibir ícone na bandeja do sistema, menu de status e janela de configurações.

### Licença
MIT

---


## 🇬🇧 English

Official QRZ Digital project: [https://qrz.digital](https://qrz.digital)

Radio log monitor integrating with QRZ Digital API. Compatible with JTDX, M1NN, WSJT-X and other hamradio family software.

### Features
- Receives logs via UDP from digital radio software
- Automatically sends logs to QRZ Digital API
- Stores pending logs and retries automatically if connection fails
- Supports text mode (console) and graphical mode (tray icon, Linux/X11)
- Automatic configuration of username, password and UDP port via `config.ini` or interactive prompts
- Secure authentication with token
- Compatible with Linux
- Automated installation via `install-linux.sh` (Linux) or `install-windows.bat` (Windows)
- Choose graphical or text mode on startup (`start-linux.sh`)
- Graphical interface with tray icon, status menu and configuration window (Linux/X11)
- Text mode for headless environments
- Repository auto-update via `git pull` in installer
- Automatic detection and installation of essential dependencies
- Multilingual documentation support

### Requirements
- Python 3.12+
- Linux (graphical mode requires X11)
- Dependencies: requests, pystray, Pillow (install via pip)


### Getting the source code
To download QRZ Monitor, install Git and clone the repository:
```bash
sudo apt install git        # Debian/Ubuntu/Raspberry Pi
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```
On Windows, download and install Git from https://git-scm.com/download/win and use Git Bash or Command Prompt:
```cmd
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```

### Installation
Linux:
```bash
chmod +x install-linux.sh start-linux.sh
./install-linux.sh
```
Windows:
1. Download and install Python 3.12+ from https://www.python.org/downloads/windows/
2. Right-click install-windows.bat and choose "Run as administrator" to install dependencies.
3. Then, right-click start-windows.bat and choose "Run as administrator" to start the monitor.
   Or, in Command Prompt (cmd) or PowerShell, run:
   ```cmd
   install-windows.bat
   start-windows.bat
   ```

### Usage
Linux:
```bash
./start-linux.sh
```
Windows:
```cmd
install-windows.bat
start-windows.bat
```
On first use, enter your callsign and password when prompted.
The monitor will wait for logs from compatible software on the configured UDP port (default: 2333).
Successfully sent logs are confirmed in the console. Pending logs are retried automatically.

### Configuration
Edit the `config.ini` file to set:
- Username: your callsign
- Password: your password
- UDPPort: UDP port to receive logs

### Graphical mode
If running in a graphical Linux/X11 environment, the monitor can show a system tray icon, status menu and configuration window.

### License
MIT

---


## 🇪🇸 Español

Proyecto oficial de QRZ Digital: [https://qrz.digital](https://qrz.digital)

Monitor de registros de radio, integrando com a API de QRZ Digital. Compatible com JTDX, M1NN, WSJT-X e outros programas de radioaficionados.

### Funcionalidades
- Recibe registros vía UDP de programas de radio digital
- Envía automáticamente los registros a la API de QRZ Digital
- Almacena registros pendientes y reintenta automáticamente en caso de fallo de conexión
- Soporte para modo texto (consola) e modo gráfico (icono en la bandeja, Linux/X11)
- Configuración automática de usuario, contraseña y puerto UDP vía archivo `config.ini` o preguntas interactivas
- Autenticación segura com token
- Compatible com Linux
- Instalación automatizada vía `install-linux.sh` (Linux) o `install-windows.bat` (Windows)
- Elección de modo gráfico o texto al iniciar (`start-linux.sh`)
- Interfaz gráfica con icono en la bandeja, menú de estado y ventana de configuración (Linux/X11)
- Modo texto para entornos sin interfaz gráfica
- Actualización automática del repositorio vía `git pull` en el instalador
- Detección e instalación automática de dependencias essenciais
- Documentación multilingüe

### Requisitos
- Python 3.12+
- Linux (el modo gráfico requiere X11)
- Dependencias: requests, pystray, Pillow (instalar con pip)


### Obtener el código fuente
Para descargar QRZ Monitor, instale Git y clone el repositorio:
```bash
sudo apt install git        # Debian/Ubuntu/Raspberry Pi
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```
En Windows, descargue e instale Git desde https://git-scm.com/download/win y use Git Bash o el símbolo del sistema:
```cmd
git clone https://github.com/olantec/qrz-monitor.git
cd qrz-monitor
```

### Instalación
Linux:
```bash
chmod +x install-linux.sh start-linux.sh
./install-linux.sh
```
Windows:
1. Descargue e instale Python 3.12+ desde https://www.python.org/downloads/windows/
2. Haga clic derecho en install-windows.bat y elija "Ejecutar como administrador" para instalar las dependencias.
3. Luego, haga clic derecho en start-windows.bat y elija "Ejecutar como administrador" para iniciar el monitor.
   O, en el símbolo del sistema (cmd) o PowerShell, ejecute:
   ```cmd
   install-windows.bat
   start-windows.bat
   ```

### Uso
Linux:
```bash
./start-linux.sh
```
Windows:
```cmd
install-windows.bat
start-windows.bat
```
En el primer uso, ingrese su indicativo y contraseña cuando se le solicite.
El monitor esperará registros de los programas compatibles en el puerto UDP configurado (por defecto: 2333).
Los registros enviados con éxito se confirman en la consola. Los registros pendientes se reenvían automáticamente.

### Configuração
Edite o arquivo `config.ini` para definir:
- Username: seu indicativo
- Password: sua senha
- UDPPort: porta UDP para receber os registros

### Modo gráfico
Se executado em ambiente gráfico Linux/X11, o monitor pode exibir ícone na bandeja do sistema, menu de status e janela de configurações.

### Licença
MIT
