Table of Contents
==================
- [Table of Contents](#table-of-contents)
  - [What is kawaweb?](#what-is-kawaweb)
  - [Requirements](#requirements)
  - [Setup](#setup)
  - [Directory Structure](#directory-structure)
  - [The Kawaweb team](#the-kawaweb-team)
  - [Original Guweb Team](#original-guweb-team)
  - [The End](#the-end)

What is kawaweb?
------

Kawaweb is the frontend or user facing appearance of osu! server protocol, [kawata.py](https://github.com/kawatapw/kawata.py), which is our fork of [gulag](https://github.com/cmyui/gulag) featuring an expanded feature set  along with support for older clients and the ability to host a cheating centered server.

The following is a description of stock guweb:

Using native async/await syntax written on top of [Quart](https://github.com/pgjones/quart) and
[cmyui's multipurpose library](https://github.com/cmyui/cmyui_pkg), guweb achieves flexability, cleanliness,
and efficiency not seen in other frontend implementations - all while maintaining the simplicity of Python.

Requirements
------

- Some know-how with Linux (tested on Ubuntu 18.04), Python, and general-programming knowledge.
- MySQL
- NGINX

Setup
------

Setup is relatively simple - these commands should set you right up.

Notes:

- The following commands are for an uncontainerised environment, but personally I believe using the docker method is the better approach to ensure a consistent environment. The below method has not been updated in quite some time so steps may have changed such as the fact that config.py now pulls your config from the .env file instead.
- Ubuntu 20.04 is known to have issues with NGINX and osu! for unknown reasons?
- If you have any difficulties setting up guweb, feel free to join the Discord server at the top of the README, we now have a bit of a community!

```sh
# Install Python >=3.9 and latest version of PIP.
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.11 python3.11-dev python3.11-distutils
wget https://bootstrap.pypa.io/get-pip.py
python3.11 get-pip.py && rm get-pip.py

# Install MySQL and NGINX.
sudo apt install mysql-server nginx

# Clone guweb from GitHub.
git clone https://github.com/kawatapw/kawaweb.git
cd kawaweb

# Initialize and update the submodules.
git submodule init && git submodule update

# Install requirements from pip.
python3.11 -m pip install -r ext/requirements.txt

# Add and configure guweb's NGINX config to your nginx/sites-enabled.
sudo ln -r -s ext/nginx.conf /etc/nginx/sites-enabled/guweb.conf
sudo nano ext/nginx.conf
sudo nginx -s reload

# Configure guweb.
cp ext/config.sample.py config.py
nano config.py

# Run guweb (on port 8000).
python3.11 main.py # Run directly to access debug features for development!
hypercorn main.py # Please run guweb with hypercorn when in production! It will improve performance drastically by disabling all of the debug features a developer would need!
```

Directory Structure
------

    .
    ├── blueprints   # Modular routes such as the API, Frontend, or Admin Panel.
    ├── docs         # Markdown files used in for holding readme and other markdown files such as future plans and designs. Website docs have been moved to a Vue2 Component Template in /templates/components/vue-templates.html to allow for more control over exactly how you want your docs to be displayed and formatted along with allowing a pageless docs setup allowing docs to be viewed from any page on the website.
    ├── ext          # External files from guweb's primary operation.
    ├── objects      # Code for representing privileges, global objects, and more.
    ├── static       # Code or content that is not modified or processed by guweb itself.
    ├── templates    # HTML that contains content that is rendered after the page has loaded.
        ├── admin    # Templated content for the admin panel (/admin).
        ├── settings # Templated content for settings (/settings).
        ├── components # Templated content for various components of the website such as the navbar, footer, docs, various panels and so on.
        └ ...         # Templated content for all of guweb (/).

The Kawaweb team
------

- [The Fantastic Loki](https://github.com/TheFantasticLoki) | Lead Project Dev, Designer, Backend
- [Hinamizawa](https://github.com/alejandroatacho) | Designer, Backend?
- [lkse](https://github.com/lkse) | Backend [Deprecated]

Original Guweb Team
------

- [Yoru](https://github.com/Yo-ru) | Backend, Grammar Checking [Deprecated]
- [Varkaria](https://github.com/Varkaria) | Frontend, Backend?

The End
------

We thank you for taking the time to look into our fork of guweb, we know it's not the most well documented project, but we continue to strive to add more features and consistently improve the way we do things. Please check the original repo of [guweb](https://github.com/Varkaria/guweb) if you wish to learn more about the original project and what it was based on.
