Frontend Blocklist

Lista de bloqueo para AdGuard generada automáticamente a partir de distintas fuentes de instancias alternativas de Reddit, X/Twitter y Tumblr.

¿Qué hace?

Este repositorio recopila dominios publicados por diferentes registros de instancias y genera automáticamente un archivo:

blocklist.txt

El archivo utiliza reglas compatibles con AdGuard, por ejemplo:

||reddit.com^
||x.com^
||tumblr.com^
||ejemplo.com^

De esta forma, AdGuard puede utilizar una única lista remota en lugar de tener que añadir cada dominio manualmente.

Fuentes

Actualmente el workflow consulta:

LibRedirect Instances
Redlib Instances
Priviblur

También se incluyen algunos dominios principales de las plataformas:

x.com
twitter.com
t.co
reddit.com
redd.it
tumblr.com
Actualización automática

La lista se genera mediante GitHub Actions.

El workflow está configurado para:

ejecutarse manualmente mediante workflow_dispatch;
ejecutarse automáticamente cada 6 horas mediante schedule;
consultar las fuentes configuradas;
extraer los dominios encontrados;
generar blocklist.txt;
guardar los cambios automáticamente en el repositorio.

El archivo del workflow se encuentra en:

.github/workflows/update.yml
Uso con AdGuard

Una vez generado blocklist.txt, abre su versión Raw en GitHub y utiliza esa dirección como filtro DNS remoto en AdGuard.

La idea es que AdGuard mantenga siempre la misma URL mientras GitHub actualiza el contenido de la lista.

Flujo:

Fuentes
   ↓
GitHub Actions
   ↓
blocklist.txt
   ↓
AdGuard
   ↓
Bloqueo de los dominios
Limitaciones

La lista solamente puede bloquear las instancias que aparezcan en las fuentes consultadas.

Una instancia nueva, privada o que todavía no haya sido registrada en dichas fuentes no aparecerá automáticamente en blocklist.txt.

Estructura del repositorio
frontend-blocklist/
├── .github/
│   └── workflows/
│       └── update.yml
├── blocklist.txt
└── README.md
Aviso

Esta lista se genera automáticamente y depende de la disponibilidad y del formato de las fuentes externas. Si una fuente cambia su estructura, el workflow puede necesitar modificaciones.


## Descubrimiento adicional mediante Google

Además de las fuentes de instancias conocidas, existe un segundo descubridor independiente:

`scripts/discover_search_frontends.py`

El descubridor realiza búsquedas en Google en 10 idiomas (inglés, español, francés, alemán, ruso, chino, japonés, coreano, hindi y árabe), recoge dominios candidatos y visita las páginas encontradas para validar que realmente parezcan frontends/viewers de Twitter/X, Reddit o Tumblr.

La validación no se basa en una coincidencia única. Combina términos de plataforma, términos funcionales (viewer, frontend, mirror, proxy, instancia, etc.), términos de contenido (perfil, usuario, tweet, subreddit, post, blog, etc.), presencia de señales de interfaz y repetición del dominio en búsquedas independientes. También descarta motores de búsqueda, dominios oficiales y páginas de artículos/noticias, y no publica un dominio si la comprobación de Google produce un resultado insuficiente.

La salida se publica por separado:

`search-discovered-blocklist.txt`

Es un archivo AdGuard DNS independiente y no se mezcla automáticamente con `blocklist.txt`.

El informe de cada ejecución queda en:

`search-discovered-report.json`

El descubrimiento se ejecuta por separado mediante:

`.github/workflows/discover-search-frontends.yml`

Ese workflow se ejecuta manualmente y una vez al día. Se mantiene separado del workflow principal de actualización cada 6 horas para no bombardear Google con peticiones innecesarias.

## Listas publicadas

- `blocklist.txt`: fuentes de instancias conocidas; formato AdGuard DNS.
- `portmaster.txt`: mismos dominios, uno por línea, para Portmaster.
- `search-rules.txt`: reglas de URL para el filtrado de Safari/AdGuard.
- `search-discovered-blocklist.txt`: dominios nuevos descubiertos mediante Google y validados por el crawler.
