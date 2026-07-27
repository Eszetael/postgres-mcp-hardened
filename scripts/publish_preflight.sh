#!/usr/bin/env bash
# The gate between a private repository and a public one.
#
# Why it exists as a script rather than a paragraph. Everything below was already written down
# somewhere — in docs/SELF_HOSTED_RUNNER.md, in a commit message, in someone's head. That is exactly
# the pattern this project spends its time hunting in its own code: a claim with no executor. A rule
# nobody can fail is not a rule, it is an intention, and intentions are what you find out about
# afterwards.
#
#   ./scripts/publish_preflight.sh            # judge; exit 1 on any refusal
#   ./scripts/publish_preflight.sh --explain  # the same, plus why each check exists
#
# It refuses rather than warns, and it refuses when it CANNOT CHECK. A gate that passes because it
# could not reach the API is worse than no gate, because it produces the paperwork of safety.
set -uo pipefail

EXPLAIN=0
[ "${1:-}" = "--explain" ] && EXPLAIN=1

PASS=0; REFUSE=0
ok()   { printf '  \033[32mOK    \033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no()   { printf '  \033[31mODMOWA\033[0m %s\n     %s\n' "$1" "${2:-}"; REFUSE=$((REFUSE+1)); }
why()  { [ "$EXPLAIN" = 1 ] && printf '         \033[2m%s\033[0m\n' "$1"; return 0; }

cd "$(dirname "$0")/.." || exit 2
printf '\n== Brama publikacji: %s ==\n\n' "$(pwd)"

# --- 1. Runner -----------------------------------------------------------------------------------
# On a public repository anyone can open a pull request, and a pull request runs workflow code. On a
# self-hosted runner that code runs on our machine, with our network. GitHub documents this as the
# reason not to do it; it is not a theoretical risk.
why "Publiczne PR wykonują kod na runnerze. Nasz runner stoi na maszynie produkcyjnej."
OWNER_REPO=$(git remote get-url origin 2>/dev/null | sed -E 's#.*github.com[:/]([^/]+/[^/.]+)(\.git)?$#\1#')
if [ -z "${GITHUB_TOKEN:-}" ]; then
  no "nie mogę sprawdzić runnera" "brak GITHUB_TOKEN — brama odmawia, gdy nie umie sprawdzić"
elif [ -z "$OWNER_REPO" ]; then
  no "nie umiem odczytać owner/repo z origin" "$(git remote get-url origin 2>&1)"
else
  api() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GITHUB_TOKEN" \
            "https://api.github.com/repos/$OWNER_REPO/$1"; }
  code=$(api "actions/variables/RUNNER_LABEL")
  case "$code" in
    404) ok "zmienna RUNNER_LABEL nie jest ustawiona (CI wraca na maszyny GitHuba)";;
    200) no "RUNNER_LABEL WCIĄŻ USTAWIONA" "przepływy nadal celują we własny runner";;
    *)   no "nie umiem sprawdzić RUNNER_LABEL" "API zwróciło $code";;
  esac
  runners=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
             "https://api.github.com/repos/$OWNER_REPO/actions/runners" \
             | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("total_count","?"))
except Exception: print("?")')
  # Wzorce w cytatach: goły `?` w `case` znaczy „dowolny JEDEN znak", więc łapał „1" i zgłaszał
  # błąd odczytu tam, gdzie API odpowiedziało poprawnie. Brama, która myli sprawny odczyt z awarią,
  # uczy człowieka ignorować własne odmowy.
  case "$runners" in
    "0") ok "żaden self-hosted runner nie jest zarejestrowany";;
    "?") no "nie umiem policzyć runnerów" "odpowiedź API nie do odczytania";;
    *)   no "ZAREJESTROWANE RUNNERY: $runners" "odepnij je, zanim repo stanie się publiczne";;
  esac
fi

# --- 2. Dokumenty wewnętrzne ---------------------------------------------------------------------
# Strategia, wycena i plan wejścia na rynek żyją poza tym repozytorium celowo. Wystarczy jeden
# `git add -A` w pośpiechu, żeby to przestało być prawdą — i nikt się nie dowie, dopóki repo jest
# prywatne.
why "Jeden odruchowy 'git add -A' publikuje plan launchu razem z kodem."
INTERNAL='PLAN.local|BATTLE_PLAN|LAUNCH_PLAN|MONETIZATION|SUBMISSIONS|\.env$|\.env\.'
leaked=$(git ls-files | grep -Ei "$INTERNAL" || true)
if [ -z "$leaked" ]; then
  ok "żaden dokument wewnętrzny nie jest śledzony przez git"
else
  no "ŚLEDZONE DOKUMENTY WEWNĘTRZNE" "$(echo "$leaked" | tr '\n' ' ')"
fi

# --- 3. Infrastruktura w treści ------------------------------------------------------------------
# Publikujemy serwer, nie mapę naszej sieci. Adresy Tailscale, ścieżki hosta i nazwy węzłów nie mają
# tu czego szukać — a wpadają do plików przez przykłady i wklejone logi.
why "Adresy 100.x, ścieżki <workspace> i nazwy węzłów to mapa naszej infrastruktury."
INFRA='100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.[0-9]+\.[0-9]+|<workspace>|<ssh-key>|eszetael@|<user>@'
hits=$(git grep -InE "$INFRA" -- . ':!scripts/publish_preflight.sh' 2>/dev/null | head -5 || true)
if [ -z "$hits" ]; then
  ok "brak adresów Tailscale, ścieżek hosta i nazw węzłów w śledzonych plikach"
else
  no "INFRASTRUKTURA W ŚLEDZONYCH PLIKACH" "$(echo "$hits" | head -3 | tr '\n' ' ')"
fi
# Osobno HISTORIA. Usunięcie pliku z gałęzi nie usuwa go z commitów, a publikacja odsłania każdy
# commit, jaki kiedykolwiek powstał. To rozróżnienie kosztowało nas prawdziwe znalezisko: adres
# węzła i nazwa użytkownika SSH siedziały w śledzonym pliku dokumentacji i przeszłyby na świat.
hist=$(git log --all -p --no-color -U0 2>/dev/null | grep -aoE "$INFRA" | sort -u | head -5 || true)
if [ -z "$hist" ]; then
  ok "historia commitów też jest czysta z infrastruktury"
else
  no "INFRASTRUKTURA W HISTORII COMMITÓW" \
     "$(echo "$hist" | tr '\n' ' ')— usunięcie pliku NIE kasuje go z historii (wymaga git filter-repo)"
fi

# --- 4. Sekrety ----------------------------------------------------------------------------------
# Historia, nie tylko czubek gałęzi: publikacja odsłania każdy commit, jaki kiedykolwiek powstał.
why "Publikacja odsłania CAŁĄ historię, nie tylko ostatni commit."
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --no-banner --redact -v >/tmp/preflight_gitleaks.$$ 2>&1; then
    ok "gitleaks: czysto w całej historii"
  else
    no "GITLEAKS ZNALAZŁ SEKRETY" "szczegóły: /tmp/preflight_gitleaks.$$"
  fi
else
  no "brak gitleaks" "brama odmawia, gdy nie umie sprawdzić historii pod kątem sekretów"
fi

# --- 5. Twierdzenia dokumentacji -----------------------------------------------------------------
why "README obiecuje rzeczy, których kod może już nie robić — to psuje zaufanie, nie funkcję."
if sh tests/docs_claims.sh >/tmp/preflight_docs.$$ 2>&1; then
  ok "twierdzenia dokumentacji zgadzają się z kodem"
else
  no "DOKUMENTACJA ROZJECHAŁA SIĘ Z KODEM" "szczegóły: /tmp/preflight_docs.$$"
fi

# --- 6. Brama jakości G4 -------------------------------------------------------------------------
why "G4 to sześciowymiarowa brama fabryki; bez zielonej karty nie ma podpisu."
if [ ! -f GATE_CARD.json ]; then
  no "BRAK GATE_CARD.json" "runda G4 nie została jeszcze przeprowadzona na tym kodzie"
elif python3 -c 'import json,sys; sys.exit(0 if json.load(open("GATE_CARD.json")).get("g4_pass") else 1)' 2>/dev/null; then
  ok "karta G4 zielona"
else
  no "KARTA G4 NIE JEST ZIELONA" "$(python3 -c 'import json;print(json.load(open("GATE_CARD.json")).get("summary","brak podsumowania"))' 2>&1 | head -1)"
fi

# --- 7. To, co lokalne, jest tym, co publikujemy --------------------------------------------------
why "Publikujesz to, co jest na GitHubie, a nie to, co widzisz u siebie."
if [ -z "$(git status --porcelain)" ]; then
  ok "katalog roboczy czysty"
else
  no "NIEZACOMMITOWANE ZMIANY" "$(git status --porcelain | head -3 | tr '\n' ' ')"
fi
git fetch -q origin main 2>/dev/null || true
if [ "$(git rev-parse HEAD 2>/dev/null)" = "$(git rev-parse origin/main 2>/dev/null)" ]; then
  ok "HEAD jest tym samym commitem co origin/main"
else
  no "LOKALNE I ZDALNE SIĘ ROZJECHAŁY" "publikacja pokaże wersję ze zdalnego, nie tę u Ciebie"
fi

printf '\n== %d przeszło, %d ODMÓW ==\n' "$PASS" "$REFUSE"
if [ "$REFUSE" -gt 0 ]; then
  printf '\n\033[31mNIE PUBLIKOWAĆ.\033[0m Powyższe odmowy są warunkami, nie sugestiami.\n\n'
  exit 1
fi
printf '\n\033[32mBrama przepuszcza.\033[0m Sam podpis pod publikacją należy do CEO.\n\n'
