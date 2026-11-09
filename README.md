# SecuraPy Platform — Vanguard

SIEM da **CyberShield Ltda.** evoluído do MVP de linha de comando (1º semestre) para uma plataforma em camadas: os eventos e alertas vão para o **MongoDB**, operadores para o **MySQL**, um modelo de **machine learning** prioriza o risco por IP, uma **API REST** e um **dashboard web** expõem os dados, um **assistente LLM** explica eventos em linguagem natural e tudo sobe com **Docker Compose**. Alertas críticos continuam chegando em tempo real nos consoles TCP do 1º semestre.

> Trabalho Final (GS) · Coding for Security · FIAP · 2º semestre

## Integrantes

| Nome | RM | Módulos |
|------|----|---------|
| Matheus Silva Souza | 572335 | A + C — Núcleo e  Machine Learning |
| Victor Cassamassimo da Silva | 572852 | B + E — Persistência e Dashboard/Segurança Web |
| Nicolas Schulthais Gouvea | 573863 | G + Bônus (JWT e Correlação Temporal) |
| Pedro Bezerra Cardoso | 567119 | D + F — API REST e Docker |

---

## Arquitetura

```mermaid
flowchart LR
    LOGS[(logs/*.log)] --> CORE[core<br/>coletor · regras · detector]
    CORE --> ORQ{{orquestrador}}
    ORQ --> ML[ml<br/>score de risco · Isolation Forest]
    ORQ --> MONGO[(MongoDB<br/>eventos · alertas · ameaças<br/>geolocalização)]
    ORQ --> TCP[alertas<br/>servidor TCP :9999]
    TCP --> C1[console 1] & C2[console 2]
    API[api<br/>Flask :5000] --> ORQ
    API --> MONGO
    API --> IA[ia<br/>assistente LLM]
    WEB[web<br/>dashboard] --> MONGO
    WEB --> MYSQL[(MySQL<br/>operadores)]
    API --> MYSQL
```

Cada camada só conversa com a de baixo e troca dados nos formatos de [`core/contratos.py`](core/contratos.py) (`Evento`, `Alerta`, `Ameaca`, `Classificacao`, `Triagem`). O `core/` não conhece banco, ML nem web — é o mesmo núcleo do 1º semestre.

```
securaPy_platform/
├── core/                   NÚCLEO (1º sem) ............................ Módulo A
│   ├── coletor.py            leitura e parsing dos 3 logs
│   ├── regras.py             motor de regras (config/regras.json)
│   ├── detector.py           brute force, port scan, blacklist (dict + set) + rajada em janela de tempo
│   ├── enriquecimento.py     ipinfo.io + backoff em 429 (o cache agora é o MongoDB)
│   ├── relatorios.py         filtros, top IPs, exportação JSON, menu CLI
│   ├── pipeline.py           núcleo em uma chamada: eventos → alertas + ameaças
│   └── contratos.py          formatos de dados compartilhados por todas as camadas
├── alertas/                TEMPO REAL (1º sem) ........................ Módulo A
│   ├── servidor_alertas.py   broadcast TCP (sobe junto com a API no Docker)
│   └── cliente_alertas.py    console do analista
├── db/                     PERSISTÊNCIA ............................... Módulo B
│   ├── mongo_repo.py         eventos/alertas/ameaças/geolocalização, filtros, agregações
│   ├── mysql_repo.py         operadores — queries parametrizadas, senha em hash
│   ├── migracao.py           ingestão inicial dos logs e da geolocalização no MongoDB
│   └── schema.sql            tabela usuarios (aplicada pelo compose)
├── ml/                     MACHINE LEARNING ........................... Módulo C
│   ├── features.py           features por IP (treino e classificação usam a mesma)
│   ├── treinar.py            Pipeline + validação cruzada + joblib
│   ├── classificar.py        score de risco por IP (carrega só se o hash conferir)
│   ├── integridade.py        SHA-256 do modelo (OWASP A08)
│   └── anomalias.py          Isolation Forest (bônus)
├── api/                    API REST ................................... Módulo D
│   ├── app.py                rotas, validação, erros e montagem da aplicação
│   └── auth.py               JWT dos operadores + token de serviço
├── web/                    DASHBOARD .................................. Módulo E
│   ├── painel.py             login de operador, painel e investigação de IP
│   ├── seguranca.py          headers de segurança + log de acesso (A09)
│   ├── templates/            Jinja2 (escape automático)
│   └── static/painel.css     CSS externo (a CSP bloqueia inline)
├── ia/assistente.py        LLM com fallback por regras ................ Módulo G
├── scripts/verificar_containers.py   status via Docker SDK ............ Módulo F
├── orquestrador.py         fluxo ponta a ponta (GS §4)
├── main.py                 linha de comando
├── config/                 settings.py (variáveis de ambiente) · regras.json · geolocalização inicial (semente do MongoDB)
├── logs/                   auth.log · firewall.log · web_access.log (dados de teste)
├── testes/                 nucleo/ (1º sem) + um arquivo de testes por módulo B–G
├── Dockerfile · docker-compose.yml · .env.example
└── requirements.txt · requirements-dev.txt · pytest.ini
```

---

## Como executar (Docker)

```bash
cp .env.example .env              # troque os valores — o .env nunca vai para o Git
docker compose up --build         # sobe api + mongodb + mysql na rede "securapy"
python scripts/verificar_containers.py   # F2: lista os 3 contêineres como "running"
```

| Serviço | Endereço |
|---------|----------|
| API + dashboard | http://localhost:5000 (saúde: `/api/saude`) |
| Alertas em tempo real | `localhost:9999` |
| MongoDB / MySQL | só em `127.0.0.1` (27017 / 3306) — nunca expostos na rede |

Fluxo da demonstração (GS §4):

```bash
docker compose exec api python main.py operador          # cria o operador do dashboard

python -m alertas.cliente_alertas                        # console 1 (outro terminal, só stdlib)
python -m alertas.cliente_alertas                        # console 2

curl -X POST http://localhost:5000/api/token -H "Content-Type: application/json" \
     -d '{"email": "<email do operador>", "senha": "<senha>"}'   # login → JWT válido por 30 min

curl -X POST http://localhost:5000/api/analisar \
     -H "Authorization: Bearer <JWT recebido>" \
     -H "Content-Type: application/json" -d "{}"         # analisa os 3 logs → alertas chegam nos consoles

curl http://localhost:5000/api/ip/185.220.101.1          # eventos + alertas + geo + score + anomalia + triagem
curl "http://localhost:5000/api/alertas?ordenar=risco"   # alertas priorizados pelo score do ML
curl http://localhost:5000/api/ameacas                   # ameaças da mais arriscada para a menos
```

O modelo já vem treinado no repositório (`ml/modelo.pkl` + hash). Para treinar de novo: `python main.py treinar`.

No PowerShell, use `curl.exe` no lugar de `curl`. Depois: `http://localhost:5000/login` → painel → busca por IP.

### Autenticação da API

As rotas de escrita (`POST /api/alertas` e `POST /api/analisar`) exigem `Authorization: Bearer <token>`. São aceitos dois tipos:

| Token | Para quem | Como obter |
|-------|-----------|------------|
| **JWT** (HS256) | operadores | `POST /api/token` com email e senha do MySQL — expira em `JWT_EXPIRA_MINUTOS` (padrão 30) |
| **Token de serviço** | automações e scripts | `API_TOKEN` do `.env` — deixe vazio para aceitar só JWT |

O JWT é recusado se estiver expirado, adulterado, assinado com outra chave ou sem assinatura (`alg: none`). Alertas criados pela API guardam quem os criou em `criado_por`.

O nível de acesso do operador (1–5, no MySQL) vai dentro do JWT e decide o que ele pode fazer:

| Nível | Pode |
|:-----:|------|
| 1 | consultar (rotas `GET` e dashboard) |
| 2 ou mais | registrar alerta manual (`POST /api/alertas`) |
| 3 ou mais | disparar a análise completa (`POST /api/analisar`) |

Abaixo do nível exigido, a resposta é `403`. O token de serviço vale como nível 5.

### Sem Docker (desenvolvimento)

```bash
python -m venv .venv && .venv\Scripts\activate           # Linux/Mac: source .venv/bin/activate
pip install -r requirements-dev.txt
python main.py analisar --sem-banco --sem-tempo-real    # núcleo + ML + relatório JSON, sem bancos
python main.py api                                       # API + dashboard em http://localhost:5000
python main.py menu                                      # menu interativo do 1º semestre
```

Com os bancos do compose no ar, o `.env` local faz `python main.py ingerir` gravar direto neles.

---

## Dependências

Python 3.12 (imagem `python:3.12-slim`), MongoDB 7 e MySQL 8 — os três sobem pelo `docker compose`. Bibliotecas em `requirements.txt`:

| Biblioteca | Para quê |
|------------|----------|
| `flask` · `gunicorn` | API REST e dashboard (o gunicorn serve a aplicação dentro do contêiner) |
| `pymongo` | MongoDB: eventos, alertas, ameaças e geolocalização |
| `mysql-connector-python` | MySQL: operadores da plataforma |
| `scikit-learn` · `numpy` · `joblib` | modelo de risco, Isolation Forest e persistência do modelo |
| `PyJWT` | bônus JWT |
| `openai` | assistente LLM (sem chave, entra o fallback por regras) |
| `requests` | enriquecimento pelo ipinfo.io |
| `docker` | verificação dos contêineres pelo SDK |
| `python-dotenv` | leitura do `.env` |

Para os testes, `requirements-dev.txt` acrescenta `pytest` e `mongomock`.

---

## Testes

```bash
python -m pytest                       # tudo
python -m pytest -m nucleo             # um módulo: nucleo | persistencia | ml | api | web | docker | llm
python -m pytest -m "jwt or temporal"  # bônus
python -m pytest --tb=no -q            # placar rápido
```

Cada cenário da GS virou teste, no mesmo esquema do 1º semestre. Banco, rede, Docker e OpenAI são simulados (mongomock, MagicMock, LLM falso), então tudo roda offline e sem gastar créditos.

Placar final:

```
351 passed · 2 skipped        # sem Docker
353 passed                    # com o compose no ar e SECURAPY_E2E=1
```

| Marcador | Testes | O que cobre |
|----------|-------:|-------------|
| `nucleo` | 197 | 1º semestre: coletor, regras, detector, enriquecimento, relatórios e servidor |
| `persistencia` | 32 | B1–B4 + geolocalização no MongoDB |
| `ml` | 17 | C1–C4 + prioridade dos alertas pelo score + Isolation Forest |
| `api` | 61 | D1–D5, validação de lote e período, níveis de acesso e JWT |
| `web` | 14 | E1–E4 + painel priorizado pelo ML |
| `docker` | 5 | F1–F3 (2 deles só com o compose no ar) |
| `llm` | 14 | G1–G4 |
| `temporal` · `jwt` · `tempo_real` | 10 · 9 · 3 | bônus e servidor de alertas dentro da plataforma |

Os 2 pulados rodam contra a plataforma real: `SECURAPY_E2E=1 python -m pytest -m docker`.

---

## Mapa dos módulos

| Módulo | Arquivos | Cenários | Testes |
|--------|----------|----------|--------|
| **A** Núcleo + tempo real | `core/`, `alertas/` | A1–A4 | `testes/nucleo/`, `test_a_tempo_real.py`, `test_bonus_temporal.py` |
| **B** Persistência | `db/mongo_repo.py`, `db/mysql_repo.py`, `db/migracao.py`, `db/schema.sql` | B1–B4 | `test_b_persistencia.py` |
| **C** Machine Learning | `ml/` | C1–C4 | `test_c_ml.py` |
| **D** API REST | `api/app.py`, `api/auth.py` | D1–D5 | `test_d_api.py`, `test_bonus_jwt.py` |
| **E** Web | `web/painel.py`, `web/seguranca.py`, `web/templates/` | E1–E4 | `test_e_web.py` |
| **F** Docker | `Dockerfile`, `docker-compose.yml`, `scripts/verificar_containers.py` | F1–F3 | `test_f_docker.py` |
| **G** LLM | `ia/assistente.py` | G1–G4 | `test_g_assistente.py` |

O `orquestrador.py` liga tudo: núcleo → ML → anomalias → enriquecimento → persistência → tempo real. Cada etapa é isolada: um serviço fora do ar vira `falhou` no resumo da análise e nunca derruba o resto.

### Convenções da equipe

- Importe módulos, não funções: `from db import mongo_repo` → `mongo_repo.buscar_alertas(...)`. Os testes substituem funções no módulo.
- Configuração sempre por `settings.X` (`from config import settings`) — nunca valor fixo no código, nunca segredo no Git.
- Queries MySQL só com `%s`; templates sem `|safe`; `debug=True` nunca.
- Mudou um formato em `core/contratos.py`? Avise o grupo antes do commit.

---

## O que veio do 1º semestre

| 1º semestre | Agora | O que mudou |
|-------------|-------|-------------|
| `coletor.py` | `core/coletor.py` | mesmo parsing; dispatch por dicionário de parsers |
| `regras.py` | `core/regras.py` | mesma lógica; código duplicado removido |
| `detector.py` | `core/detector.py` | mesma lógica (dict + set) |
| `enriquecimento.py` | `core/enriquecimento.py` | **corrigido** (`eh_ip_privado` aceitava só objeto, `consultar_ip` retornava `None`); backoff em 429 (Aula 10). O cache em arquivo deu lugar à coleção `geolocalizacao` no MongoDB (índice único em `ip` + TTL de 30 dias), e o JSON antigo virou a carga inicial |
| `relatorios.py` | `core/relatorios.py` | exporta ameaças (sets → listas) para o relatório JSON |
| `servidor_alertas.py` / `cliente_alertas.py` | `alertas/` | porta por variável de ambiente; servidor sobe em thread junto da API |
| `main.py` (menu) | `python main.py menu` | o menu continua disponível como subcomando |
| `testes/` (197) | `testes/nucleo/` | **197/197 passando** (antes da reorganização: 176) |

Observação sobre o cenário A2: o `auth.log` tem **11** FAILs de `185.220.101.1` (a GS cita 10); a severidade esperada, ALTA, confere.

---

## Divisão de tarefas

### Matheus Silva · Módulos A e C
- **O que fez:** Integração do Núcleo da GS1 e implementação de Machine Learning.
- **Dificuldades:**Minha maior dificuldade foi a integração do núcleo da GS1 com o resto do projeto. Sem o uso de IA, seria ainda mais complicado, mesmo com o prazo de entrega alongado.

### Cassa · Módulos B e E
- **O que fez:** Integração dos bancos de dados e "assinatura" das tabelas de persistência. Criação do Dashboard e aplicação de medidas de segurança para a plataforma WEB dos operadores.
- **Dificuldades:** Não tenho costume de fazer vibe coding, portanto, ainda tenho dificuldades de realizar atividades com prompts adequados. A longo prazo, a revisão dos condigos tornou-se mais facil, porém, ter o controle do que faço dessa forma é  mais complicados, diferente da primeira GS, que, ao menos, toda a lógica e parte fundamental do funcionamento do enriquecimento com consultas a API foram feitas por mim, e apenas aprimoradas com o uso de IA.

### Nicolas Schulthais · Módulo G e Bônus (JWT e Correlação Temporal)
- **O que fez:** Implementação de LLM e autenticação da API via JWT e Correlação Temporal
- **Dificuldades:**

### Pedro Bezerra · Módulos D e F
- **O que fez:** Criação do API Rest e o código de verificação dos containers do Docker.
- **Dificuldades:** A principal dificuldade que tive foi de organização na criação dos códigos. Apesar de saber onde procurar por referências para a montagem dos códigos, eu não sabia em como eu poderia estruturar cada informação dentro dos arquivos.

---

## Entregáveis

- [x] Código-fonte com Dockerfile e docker-compose
- [ ] README preenchido (integrantes e divisão de tarefas)
- [ ] Vídeo (12–18 min): compose → análise via API → dashboard → busca de IP → score → LLM → 2 consoles
- [x] `saida/relatorio_exemplo.json` — `python main.py analisar --saida saida/relatorio_exemplo.json`
- [x] `ml/modelo.pkl` + `ml/modelo.sha256` + `ml/metricas.json` — `python main.py treinar`

## Bônus

| Bônus | Onde | Situação |
|-------|------|:--------:|
| Detecção de anomalias (+0,30) | `ml/anomalias.py` — etapa `anomalias` da análise, coluna no painel e campo `anomalia` em `/api/ip`; isolado: `python -m ml.anomalias` | ✅ |
| Correlação temporal (+0,20) | `core/detector.py` — brute force em rajada (padrão: 5 falhas em 60 s, alerta `T001`) — `python -m pytest -m temporal` | ✅ |
| Testes automatizados (+0,30) | `testes/` — `python -m pytest` | ✅ |
| JWT completo (+0,20) | `api/auth.py` — `python -m pytest -m jwt` | ✅ |
