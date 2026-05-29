# PIT Chile Looking Glass

![Screenshot](https://github.com/scottiep1pen/lookinglass/blob/main/Doc1.pdf)

Looking Glass y herramientas de red LATAM.
BGP, Whois, RPKI, DNS y Prefix Info desde route servers publicos
con peering en Chile, Mexico, Argentina y Peru.

    Sitio    : https://www.pitchile.cl
    PeeringDB: https://www.peeringdb.com/ix/1514
    NOC      : noc@pitchile.cl
    GitHub   : https://github.com/scottiep1pen/lookinglass
RRozasC
---

## Requisitos

    Python 3.11+
    pip
    Apache 2.4+ (para produccion con SSL)

---

## Instalacion rapida

    git clone https://github.com/scottiep1pen/looking-glass.git
    cd looking-glass
    pip install -r requirements.txt
    cd backend
    python app.py
    # Abrir http://localhost:8080

---

## Estructura

    looking-glass/
    config/
        config.yaml        <- TODA la configuracion aqui
    backend/
        app.py             <- FastAPI + motores de herramientas
        gen_examples.py    <- genera ejemplos con nombres RDAP
    frontend/
        index.html
        static/
            css/main.css
            js/app.js
    requirements.txt
    README.md

---

## Configuracion (config/config.yaml)

Nada esta embebido en el codigo. Todo se controla desde config.yaml.

### Servidor

    server:
      host: "127.0.0.1"   # usar 127.0.0.1 si Apache hace proxy
      port: 8080
      debug: false
      title: "PIT Chile Looking Glass"
      contact_email: "noc@pitchile.cl"

### Seguridad

    security:
      telnet_timeout: 20          # segundos por conexion
      rate_limit_per_minute: 20   # requests por IP
      max_output_lines: 500
      allowed_query_regex: '^[\d\.:/a-zA-Z_\-]+$'

### Agregar route server

    route_servers:
      - id: nuevo_rs
        name: "Nombre legible"
        group: "Peru"
        host: "rs.ejemplo.org"
        port: 23
        type: frr           # frr | cisco | juniper
        prompt: ">"
        enabled: true
        note: "Descripcion"

### Route servers incluidos (probados Abril 2026)

    pit_scl    pit.scl.routeviews.org              Chile    OK
    pit_mex    pitmx.qro.routeviews.org             Mexico   OK
    rv2        route-views2.routeviews.org          Global   OK
    rv4        route-views4.routeviews.org          Global   OK
    rv5        route-views5.routeviews.org          Global   OK
    rv6        route-views6.routeviews.org          Global   OK
    rv_eqix    route-views.eqix.routeviews.org      Global   OK
    rv_linx    route-views.linx.routeviews.org      Global   OK

---

## Produccion con Apache (reverse proxy)

FastAPI corre en 127.0.0.1:8080, Apache expone en 443.

### 1. config.yaml

    server:
      host: "127.0.0.1"   # solo local, Apache hace el proxy
      port: 8080

### 2. Modulos Apache requeridos

    # Ubuntu/Debian
    a2enmod proxy proxy_http proxy_wstunnel rewrite headers ssl
    systemctl reload apache2

    # CentOS/RHEL (ya incluidos en httpd)
    systemctl reload httpd

### 3. VirtualHost Apache

Crear /etc/apache2/sites-available/pit-lg.conf (o /etc/httpd/conf.d/pit-lg.conf):

    # HTTP -> redirige a HTTPS
    <VirtualHost *:80>
        ServerName lg.pitchile.cl
        Redirect permanent / https://lg.pitchile.cl/
    </VirtualHost>

    # HTTPS
    <VirtualHost *:443>
        ServerName lg.pitchile.cl

        SSLEngine on
        SSLCertificateFile    /etc/letsencrypt/live/lg.pitchile.cl/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/lg.pitchile.cl/privkey.pem

        ProxyPreserveHost On
        ProxyPass        / http://127.0.0.1:8080/
        ProxyPassReverse / http://127.0.0.1:8080/

        # WebSocket (futuro)
        RewriteEngine on
        RewriteCond %{HTTP:Upgrade} websocket [NC]
        RewriteCond %{HTTP:Connection} upgrade [NC]
        RewriteRule ^/?(.*) ws://127.0.0.1:8080/$1 [P,L]

        # Headers de seguridad
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"

        ErrorLog  /var/log/apache2/pit-lg-error.log
        CustomLog /var/log/apache2/pit-lg-access.log combined
    </VirtualHost>

### 4. Habilitar y recargar (Ubuntu/Debian)

    a2ensite pit-lg.conf
    systemctl reload apache2

### 5. SSL con Let's Encrypt (si no existe aun)

    apt install certbot python3-certbot-apache
    certbot --apache -d lg.pitchile.cl

### 6. Alternativa: subpath en vez de subdominio

Si prefieren https://pitchile.cl/lg/ en vez de subdominio:

    <VirtualHost *:443>
        ServerName pitchile.cl
        ...
        ProxyPass        /lg/ http://127.0.0.1:8080/
        ProxyPassReverse /lg/ http://127.0.0.1:8080/
    </VirtualHost>

    Y en config.yaml agregar:
    server:
      root_path: "/lg"

---

## Produccion con systemd

Crear /etc/systemd/system/pit-lg.service:

    [Unit]
    Description=PIT Chile Looking Glass
    After=network.target

    [Service]
    User=admin
    WorkingDirectory=/ruta/al/proyecto/backend
    ExecStart=/usr/bin/python3 app.py
    Restart=always
    RestartSec=5
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target

Activar:

    systemctl daemon-reload
    systemctl enable pit-lg
    systemctl start pit-lg
    systemctl status pit-lg

Ver logs:

    journalctl -u pit-lg -f

---

## API REST

    GET  /api/config         config publica para el frontend
    POST /api/query          BGP/ping/traceroute en route server
    POST /api/tool           whois | rpki | dns | prefix_info
    GET  /api/asn/{asn}      nombre de red via RDAP
    GET  /api/latam-ixps     ranking IXPs LATAM (PeeringDB)
    GET  /api/servers        lista de route servers
    GET  /api/health         health check
    GET  /api/docs           Swagger UI

Ejemplo curl:

    curl -s -X POST http://localhost:8080/api/tool \
      -H "Content-Type: application/json" \
      -d '{"tool":"whois","query":"AS61522"}' | python3 -m json.tool

    curl -s -X POST http://localhost:8080/api/query \
      -H "Content-Type: application/json" \
      -d '{"route_server_id":"pit_scl","command":"bgp_route","query":"1.1.1.0/24"}'

---

## GitHub

    git init && git branch -M main

    cat > .gitignore << GITEOF
    __pycache__/
    *.pyc
    *.log
    .env
    GITEOF

    git add .
    git commit -m "feat: PIT Chile Looking Glass v2.1

    - BGP, Whois, RPKI, DNS, Prefix Info
    - Ranking LATAM IXPs (PeeringDB)
    - Route servers PIT Chile/MX + RouteViews
    - Apache reverse proxy ready
    - Config externalizada en config.yaml"

    git remote add origin https://github.com/pitchile/looking-glass.git
    git push -u origin main

---

## Herramientas disponibles

    BGP Route     rutas IPv4/IPv6 desde route servers RouteViews
    BGP AS Path   rutas que contienen un ASN especifico
    BGP Summary   resumen de sesiones BGP del colector
    Whois         consulta LACNIC, ARIN o RIPE segun el recurso
    RPKI          validacion via RIPEstat (resource + prefix)
    DNS           resolucion A/AAAA y PTR desde el servidor
    Prefix Info   calculo de subnets IPv4/IPv6
    LATAM IXPs    ranking IXPs America Latina (PeeringDB, Abril 2026)

---

## Licencia

MIT - PIT Chile SPA - https://www.pitchile.cl
