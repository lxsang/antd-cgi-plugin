# antd-cgi-plugin
CGI interface support for [Antd server](https://github.com/lxsang/ant-http)

## Build from source
As **cgi** is an **Antd's** plugin, it need to be built along with the server. This require the following application/libraries to be pre installed:

### build dep
* git
* make
* build-essential

### server dependencies
* libssl-dev
* libsqlite3-dev

### build
When all dependencies are installed, the build can be done with a few single command lines:

```bash
mkdir antd
cd antd
wget -O- https://get.makeand.run/antd | bash -s "cgi"
```
The script will ask you where you want to put the binaries (should be an absolute path, otherwise the build will fail) and the default HTTP port for the server config.

## Example of using PHP-CGI with Antd
Make sure **php-cgi** is installed on your system.
Enable **CGI** for PHP file using antd's config file in ```/path/to/your/build/config.ini```
```ini
; Example of antd's config file
[SERVER]
port=9192 ; port
plugins=/path/to/your/build/plugins/ ; plugins dir
plugins_ext=.dylib ; plugins extensions
database=/path/to/your/build/database/
htdocs=/path/to/your/build/htdocs
tmpdir=/path/to/your/build/tmp/
workers=4
backlog=5000
ssl.enable=1
ssl.cert=/path/to/your/build/server.crt
ssl.key=/path/to/your/build/server.key

[FILEHANDLER]
; using cgi interface for PHP file
php=cgi
```
Next you need to tell the **cgi** plugin where to find the **php-cgi** command by create a ```cgi.ini``` in ```/path/to/your/build/plugins/cgi/cgi.ini```
```ini
;example of cgi.ini
[CGI]
;specify the path to php-cgi for php file
php=/usr/bin/php-cgi
; enable other scripting language using <file extension>=<script-bin CGI>
```

To run the Antd server with the **cgi** plugin:
```sh
/path/to/your/build/antd
```

**php** Web applications can be put on **/path/to/your/build/htdocs**
