# WhoIsWhoAPT [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.png?v=103)](https://github.com/ellerbrock/open-source-badges/)


## About 

<p align="center">
  <img width="500" height="324" src="https://user-images.githubusercontent.com/113699569/191086330-69b67599-0c99-40b9-a3f2-7457227ebb2c.png">
</p>

**WhoIsWhoAPT** is a tool whose purpose is to help malware analysts, threat hunters and researchers to interrelate the different APT groups (Advanced Persistent Threats) based on their tactics, techniques and procedures (TTP) assigned by **MITRE ATT&CK®** (https://attack.mitre.org/) to each group, thus obtaining their relationship index. In addition, the tool allows you to compare your own TTP sets with the rest of the APTs defined in MITRE, thus obtaining their degree of similarity.

Finally, it is possible from an APT to generate a layer with its TTPs or from two APTs to be able to generate a layer in which the TTPs of each group are differentiated and in which they coincide. These layers are intended to work with the **MITER ATT&CK® Navigator tool** (https://mitre-attack.github.io/attack-navigator/) thus facilitating their reading and analysis/modification.

Hope you can find my tool useful and if you want to report any bugs, add/suggest new features or ask any questions do not hesitate to contact me on LinkedIn. <p>
  <a href="https://www.linkedin.com/in/javier-mu%C3%B1oz-alc%C3%A1zar-644b11162" rel="nofollow noreferrer">
    <img src="https://i.stack.imgur.com/gVE0j.png" alt="linkedin"> My LinkedIn
  </a> &nbsp; 
</p>

## Installation
1. Install Python3 (and create a virtual environment\*)
            `python3.9 -m venv env`
            `source env/bin/activate`
2. Download project:
-  `git clone https://github.com/JavierMun/WhoIsWhoAPT`
-  Download directly from github\*
3. Install python packages python -m pip install -r WhoIsWhoAPTrequirements.txt
4. Run WhoIsWhoAPT.py

> **\* Note1: The creation of the virtual environment is recommended, although it is not necessary for the tool's execution.**

> **\* Note2: Although it is not necessary, I recommend to download the "resources" folder and its content along with the tool as it prevents the tool from having to download the latest version of MITER ATT&CK® and configure the APTs database on its first run, an action that can take several minutes**


## Usage
### Add custom layer
You can add any custom layers to the APT database, you just have to create the layer json with your custom TTPs on MITRE ATT&CK® Navigator and add it into the resources folder e.g. 
Name your group of TTPs as you want. This will be the name they will have on our tool.

![Captura6](https://user-images.githubusercontent.com/113699569/191077532-e604c1dd-1014-4101-a1d8-50399b85d95f.PNG)

Add the .json generated into the resources folder.

![Captura7](https://user-images.githubusercontent.com/113699569/191077553-7e2a777b-0979-4e1a-8bae-181f88d72e20.PNG)

Now you can already work with your custom "APT"

### Commands
| Command       | Parameters   | Command Details             | 
| ------------- |-------------| -------------         | 
| -c, --compare     | \<APT Name\> | Compare an APT with all the others APTs  | 
| -v, --versus      | \<APT1 Name\> \<APT2 Name\> | Compare two APTs and extract the comparison matrix. Default layer colour: (AP1 -> Green) (APT2 -> Blue) (Matching TTP -> Purple) | 
| -l, --layer       | \<APT Name\>| Create a layer with selected APT\'s TTPs. Default colour: Green| 
| -col, --colours   | \<APT1 Colour\> \<APT2 Colour\> \<Match Colour\>| Choose the colours with which the data will be represented in the layer. Most be a colour hexcode.| 

### Usage examples  
- **Comparing APT "Wizard Spider" with all other APTs**  

![captura1](https://user-images.githubusercontent.com/113699569/190997510-e0e71f0a-8309-4a58-a458-4736f3e4f11e.PNG)

- **Obtaining comparison layer between two APTs ("Wizard Spider" and "FIN8")**

![Captura2](https://user-images.githubusercontent.com/113699569/190997530-7f41153c-1bf4-4406-83dc-80b24509168e.PNG)

![Captura3](https://user-images.githubusercontent.com/113699569/190997542-eee5758d-93da-487d-9a49-cb4a597a9b8f.PNG)

- **Obtaining comparison layer between two APTs ("Wizard Spider" and "FIN8") and modifying its colours**

![customcolor3](https://user-images.githubusercontent.com/113699569/191191545-493fdcd9-3002-4374-8a4a-d462f287c51c.PNG)

![customcolor4](https://user-images.githubusercontent.com/113699569/191085534-65a1ed2d-fbe8-42c4-924e-5fb4ea5c4c45.PNG)

- **Obtaining APT "Wizard Spider" layer**

![Captura4](https://user-images.githubusercontent.com/113699569/190997545-b080864a-f9d2-4ccf-9d21-ff1f5976ad68.PNG)

![Captura5](https://user-images.githubusercontent.com/113699569/190997548-6edc96d6-0efb-4c82-9660-dca1f73670ed.PNG)

- **Obtaining APT "Wizard Spider" layer with modified colour**

![customcolor1](https://user-images.githubusercontent.com/113699569/191191516-714e664c-b5b4-4f66-8e1c-7eb61c742919.PNG)

![customcolor2](https://user-images.githubusercontent.com/113699569/191085529-84014a29-0b06-4ec0-98ce-a18089a5cd8d.PNG)
