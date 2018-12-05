![AutoRDPwn](https://user-images.githubusercontent.com/34335312/45109339-8b203580-b13f-11e8-9de7-1210114313bb.png)


**AutoRDPwn** es un script creado en Powershell y diseñado para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición. Para su correcto funcionamiento, es necesario cumplir los requisitos que se describen en la guía de uso.


# Requisitos
Powershell 4.0 o superior


# Cambios

## Versión 4.6
• Nueva interfaz de usuario totalmente rediseñada

• Ejecución en memoria mejorada

• Ahora los binarios se descargan en base64 y se generan en local

• Nuevo módulo disponible: Consola de Netcat (conexión directa e inversa)

• Nuevo módulo disponible: Recuperar contraseñas de los navegadores con SharpWeb

• Nuevo módulo disponible: Recuperar contraseñas Wi-Fi

• Nuevo módulo disponible: TCP Port Scan

• Nuevo módulo disponible: Local Port Forwarding

• Nuevo módulo disponible: Powershell Web Server

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
Esta aplicación puede usarse de forma local, remota o para pivotar entre equipos. 
Gracias a los módulos adicionales, es posible volcar hashes y contraseñas o incluso recuperar el histórico de conexiones RDP.

**Ejecución en una línea:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**La guía detallada de uso se encuentra en el siguiente enlace:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Capturas de pantalla
![autordpwn_es1](https://user-images.githubusercontent.com/34335312/49990172-02563880-ff7d-11e8-8031-8ac6fef02107.png)
![autordpwn_es2](https://user-images.githubusercontent.com/34335312/50776477-624cb000-1299-11e9-8d19-a09c282539d0.png)


# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
• **Mark Russinovich** por su herramienta PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **HarmJ0y & Matt Graeber** por su script Get-System -> https://github.com/HarmJ0y/Misc-PowerShell

• **Stas'M Corp.** por su herramienta RDP Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** por su script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** por su herramienta Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** por su script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m


# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net

-------------------------------------------------------------------------------------------------------------
# English description

**AutoRDPwn** is a script created in Powershell and designed to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability allows a remote attacker to view his victim's desktop without his consent, and even control it on request. For its correct operation, it is necessary to comply with the requirements described in the user guide.


# Requirements
Powershell 4.0 or higher


# Changes
## Version 4.6
• New completely redesigned user interface

• Improved memory execution

• Binaries are now downloaded in base64 and generated locally

• New module available: Netcat console (bind and reverse)

• New module available: Recover passwords from browsers with SharpWeb

• New module available: Recover Wi-Fi passwords

• New module available: TCP Port Scan

• New module available: Local Port Forwarding

• New module available: Powershell Web Server

*The rest of the changes can be consulted in the CHANGELOG file


# Use
This application can be used locally, remotely or to pivot between computers. Thanks to the additional modules, it is possible to dump hashes and passwords or even recover the history of RDP connections.


**One line execution:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**The detailed guide of use can be found at the following link:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Screenshots
![autordpwn_en1](https://user-images.githubusercontent.com/34335312/49990174-02563880-ff7d-11e8-896f-894a961a5214.png)
![autordpwn_en2](https://user-images.githubusercontent.com/34335312/50776478-624cb000-1299-11e9-8771-8648f559afe5.png)


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
• **Mark Russinovich** for his tool PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **HarmJ0y & Matt Graeber** for his script Get-System -> https://github.com/HarmJ0y/Misc-PowerShell

• **Stas'M Corp.** for its RDP tool Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** for his script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** for his tool Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** for his script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net
