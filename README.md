# Frontend Blocklist

Este repositorio recopila dominios de frontends/viewers alternativos de Reddit, X/Twitter y Tumblr. La lista principal y el descubridor adicional están separados para poder revisar los descubrimientos antes de incorporarlos a otras listas.

## Descubrimiento adicional

El descubridor está en `scripts/discover_search_frontends.py`. Cada día ejecuta un conjunto acotado de consultas de Bing, además de consultar registros mantenidos y GitHub. En modo `deep`/`all` también puede consultar GitLab, Codeberg, Common Crawl y URLScan cuando están disponibles sus credenciales/configuración.

La validación combina señales de plataforma, servicio, identidad de contenido, rutas, interfaz y metadata. También rechaza páginas editoriales, herramientas ajenas, catálogos/repositorios y redirecciones fuera del dominio candidato.

Los candidatos fuertes que no pueden verificarse temporalmente se conservan con estado y backoff. Las correcciones auditadas se mantienen explícitas en el validador y están cubiertas por una guarda de CI para impedir eliminaciones accidentales.

La salida del descubridor es `search-discovered-blocklist.txt` y su informe es `search-discovered-report.json`.

## Automatización

El workflow `.github/workflows/discover-search-frontends.yml` permite ejecución manual, se ejecuta una vez al día a las **03:41 UTC** y se dispara cuando cambian el propio descubridor o su workflow.

El CI preventivo está en `.github/workflows/discover-search-frontends-ci.yml`, se ejecuta en cambios relevantes mediante pull request o manualmente y usa permisos de solo lectura.

El workflow diario verifica que la salida siga siendo válida, que no se eliminen dominios publicados salvo correcciones auditadas y que no cambien estos archivos protegidos: `scripts/generate_blocklist.py`, `blocklist.txt`, `portmaster.txt` y `hagezi-overlap.txt`.

## Fuentes y estabilidad

Las fuentes mantenidas se consultan de forma fail-soft; un fallo externo no convierte automáticamente un candidato en una entrada publicada. GitHub Actions usa permisos mínimos y las acciones oficiales están fijadas a SHA.
